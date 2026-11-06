import type { Finding, CertFacts, ModuleResult } from "./types";
import { registrableDomain } from "./url";

interface CrtShEntry {
  issuer_ca_id?: number;
  issuer_name?: string;
  common_name?: string;
  name_value?: string;
  id?: number;
  entry_timestamp?: string;
  not_before?: string;
  not_after?: string;
  serial_number?: string;
}

const extractSANs = (nameValue: unknown): string[] => {
  if (typeof nameValue !== "string") return [];
  return nameValue
    .split("\n")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
};

const wildcardMatches = (san: string, host: string): boolean => {
  const s = san.toLowerCase();
  const h = host.toLowerCase();
  if (s.startsWith("*.")) {
    const suffix = s.slice(1); // keeps ".example.com"
    return h.endsWith(suffix) && h.split(".").length >= s.split(".").length;
  }
  return s === h;
};

export async function runCertModule(hostname: string, isHttps: boolean): Promise<ModuleResult<CertFacts>> {
  const hostnameLc = hostname.toLowerCase();
  const baseDomain = registrableDomain(hostnameLc);
  const now = new Date();
  const observedAt = now.toISOString();
  let fetchError: string | undefined;

  let allEntries: CrtShEntry[] = [];
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  const fetchCT = async (query: string): Promise<CrtShEntry[]> => {
    try {
      const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(query)}&output=json`, {
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status} ${res.statusText}`);
      }
      const text = await res.text();
      if (!text || text.trim().startsWith("<")) {
        // Returned HTML (e.g. rate limit or server error)
        return [];
      }
      return JSON.parse(text) as CrtShEntry[];
    } catch (err: unknown) {
      if (err instanceof Error) {
        if (err.name === "AbortError") {
          throw new Error("Request timed out (8s limit)");
        }
        throw err;
      }
      throw new Error("Unknown error fetching certificate transparency logs");
    }
  };

  try {
    // 1. Query for the exact hostname
    let entries = await fetchCT(hostnameLc);
    allEntries = entries;

    // 2. If no entries or matching certificate, fallback to querying base domain
    if (entries.length === 0 && baseDomain && baseDomain !== hostnameLc) {
      entries = await fetchCT(baseDomain);
      allEntries = entries;
    }
  } catch (err: unknown) {
    fetchError = err instanceof Error ? err.message : String(err);
  } finally {
    clearTimeout(timeoutId);
  }

  // Filter entries to those that cover the target hostname
  const matchingCandidates = (allEntries || [])
    .filter((e) => {
      const sans = extractSANs(e.name_value);
      if (sans.length === 0 && e.common_name) {
        return wildcardMatches(e.common_name, hostnameLc);
      }
      return sans.some((san) => wildcardMatches(san, hostnameLc));
    })
    .map((e) => {
      const notBeforeDate = e.not_before ? new Date(e.not_before) : null;
      const notAfterDate = e.not_after ? new Date(e.not_after) : null;
      return {
        entry: e,
        notBefore: notBeforeDate && !isNaN(notBeforeDate.getTime()) ? notBeforeDate : null,
        notAfter: notAfterDate && !isNaN(notAfterDate.getTime()) ? notAfterDate : null,
        issuer: e.issuer_name || "Unknown CA",
      };
    })
    .filter((c) => c.notAfter !== null)
    .sort((a, b) => b.notAfter!.getTime() - a.notAfter!.getTime());

  const latest = matchingCandidates[0] ?? null;

  // Compute facts
  let firstSeen: string | null = null;
  const subdomainsSet = new Set<string>();

  for (const e of allEntries) {
    if (e.entry_timestamp) {
      const ts = new Date(e.entry_timestamp).toISOString();
      if (!firstSeen || ts < firstSeen) {
        firstSeen = ts;
      }
    }
    const sans = extractSANs(e.name_value);
    for (const san of sans) {
      if (!san.includes("*") && (san === hostnameLc || san.endsWith(`.${baseDomain}`))) {
        subdomainsSet.add(san);
      }
    }
  }

  const daysUntilExpiry = latest?.notAfter
    ? Math.ceil((latest.notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
    : null;

  const facts: CertFacts = {
    latestIssuer: latest?.issuer ?? null,
    latestNotBefore: latest?.notBefore ? latest.notBefore.toISOString() : null,
    latestNotAfter: latest?.notAfter ? latest.notAfter.toISOString() : null,
    firstSeen,
    certificateCount: allEntries.length > 0 ? allEntries.length : null,
    subdomains: Array.from(subdomainsSet).slice(0, 50),
  };

  const findings: Finding[] = [];

  // Finding 1: cert-https
  findings.push({
    id: "cert-https",
    module: "certificates",
    title: "HTTPS protocol",
    status: isHttps ? "pass" : "fail",
    kind: "observation",
    weight: 25,
    evidence: isHttps
      ? "Target is accessed over secure HTTPS protocol."
      : "Target is accessed over unencrypted HTTP protocol; traffic is vulnerable to interception and tampering.",
    source: "URL scheme inspection",
    observedAt,
    remediation: isHttps ? undefined : "Configure SSL/TLS encryption and enforce automatic redirection from HTTP to HTTPS.",
  });

  // Finding 2: cert-found
  findings.push({
    id: "cert-found",
    module: "certificates",
    title: "Certificate observed in CT logs",
    status: latest ? "pass" : "unknown",
    kind: "observation",
    weight: 20,
    evidence: latest
      ? `Certificate observed in Certificate Transparency logs matching host ${hostnameLc} (Issuer: ${latest.issuer}).`
      : fetchError
        ? `Certificate Transparency log lookup failed or timed out: ${fetchError}.`
        : `No public Certificate Transparency log records found specifically matching ${hostnameLc}.`,
    source: "crt.sh Certificate Transparency",
    observedAt,
    remediation: latest
      ? undefined
      : "Ensure a valid public certificate is provisioned by a trusted CA and logged to Certificate Transparency.",
  });

  // Finding 3: cert-expiry
  if (latest && daysUntilExpiry !== null) {
    const expiryStr = latest.notAfter!.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
    if (daysUntilExpiry <= 0) {
      findings.push({
        id: "cert-expiry",
        module: "certificates",
        title: "Certificate validity period",
        status: "fail",
        kind: "observation",
        weight: 20,
        evidence: `Certificate expired on ${expiryStr} (${Math.abs(daysUntilExpiry)} days ago). Browsers will block connections.`,
        source: "crt.sh Certificate Transparency",
        observedAt,
        remediation: "Immediately renew and deploy a current SSL/TLS certificate.",
      });
    } else if (daysUntilExpiry <= 30) {
      findings.push({
        id: "cert-expiry",
        module: "certificates",
        title: "Certificate validity period",
        status: "warn",
        kind: "observation",
        weight: 10,
        evidence: `Certificate is valid but expires in ${daysUntilExpiry} days (${expiryStr}).`,
        source: "crt.sh Certificate Transparency",
        observedAt,
        remediation: "Schedule certificate renewal before expiration to avoid service interruption.",
      });
    } else {
      findings.push({
        id: "cert-expiry",
        module: "certificates",
        title: "Certificate validity period",
        status: "pass",
        kind: "observation",
        weight: 10,
        evidence: `Certificate is active and valid for ${daysUntilExpiry} more days (expires ${expiryStr}).`,
        source: "crt.sh Certificate Transparency",
        observedAt,
      });
    }
  } else {
    findings.push({
      id: "cert-expiry",
      module: "certificates",
      title: "Certificate validity period",
      status: "unknown",
      kind: "observation",
      weight: 15,
      evidence: "Certificate expiration date could not be verified from public Certificate Transparency logs.",
      source: "crt.sh Certificate Transparency",
      observedAt,
      remediation: "Verify TLS certificate expiration directly using server monitoring tools.",
    });
  }

  // Finding 4: cert-issuer
  findings.push({
    id: "cert-issuer",
    module: "certificates",
    title: "Certificate issuer",
    status: "pass",
    kind: "observation",
    weight: 5,
    evidence: latest?.issuer
      ? `Certificate issued by: ${latest.issuer}.`
      : isHttps
        ? "Target runs on HTTPS; detailed CA identity could not be retrieved from CT logs."
        : "No certificate issuer available for plain HTTP target.",
    source: "crt.sh Certificate Transparency",
    observedAt,
  });

  return {
    module: "certificates",
    findings,
    facts,
    ...(fetchError ? { error: fetchError } : {}),
  };
}
