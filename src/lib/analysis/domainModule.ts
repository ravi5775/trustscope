import type { Finding, DomainFacts, ModuleResult } from "./types";
import { registrableDomain } from "./url";

interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DnsResponse {
  Status: number;
  Answer?: DnsAnswer[];
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapEntity {
  roles?: string[];
  handle?: string;
  vcardArray?: unknown[];
}

interface RdapResponse {
  events?: RdapEvent[];
  entities?: RdapEntity[];
  status?: string[];
  nameservers?: Array<{ ldhName?: string } | string>;
}

async function queryDoh(name: string, type: string, signal: AbortSignal): Promise<string[]> {
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { Accept: "application/dns-json" },
      signal,
    });
    if (!res.ok) return [];
    const data = (await res.json()) as DnsResponse;
    if (!data.Answer || !Array.isArray(data.Answer)) return [];
    return data.Answer.map((a) => a.data.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

export async function runDomainModule(hostname: string): Promise<ModuleResult<DomainFacts>> {
  const hostnameLc = hostname.toLowerCase().replace(/\.$/, "");
  const reg = registrableDomain(hostnameLc);
  const now = new Date();
  const observedAt = now.toISOString();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  let rdapData: RdapResponse | null = null;
  let rdapError: string | undefined;

  let aRecords: string[] = [];
  let aaaaRecords: string[] = [];
  let cnameRecords: string[] = [];
  let mxRecords: string[] = [];
  let txtRecords: string[] = [];
  let nsRecords: string[] = [];

  try {
    const dohPromise = Promise.all([
      queryDoh(hostnameLc, "A", controller.signal),
      queryDoh(hostnameLc, "AAAA", controller.signal),
      queryDoh(hostnameLc, "CNAME", controller.signal),
      queryDoh(reg, "MX", controller.signal),
      queryDoh(reg, "TXT", controller.signal),
      queryDoh(reg, "NS", controller.signal),
    ]);

    const rdapPromise = (async () => {
      try {
        const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(reg)}`, {
          signal: controller.signal,
          headers: { Accept: "application/rdap+json, application/json" },
        });
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        return (await res.json()) as RdapResponse;
      } catch (err: unknown) {
        if (err instanceof Error && err.name === "AbortError") {
          throw new Error("RDAP query timed out");
        }
        throw err;
      }
    })();

    const [dohResults, rdapResult] = await Promise.allSettled([dohPromise, rdapPromise]);

    if (dohResults.status === "fulfilled") {
      [aRecords, aaaaRecords, cnameRecords, mxRecords, txtRecords, nsRecords] = dohResults.value;
    }

    if (rdapResult.status === "fulfilled") {
      rdapData = rdapResult.value;
    } else {
      rdapError = rdapResult.reason instanceof Error ? rdapResult.reason.message : String(rdapResult.reason);
    }
  } catch (err: unknown) {
    rdapError = err instanceof Error ? err.message : String(err);
  } finally {
    clearTimeout(timeoutId);
  }

  // Parse RDAP
  let created: string | null = null;
  let expires: string | null = null;
  let registrar: string | null = null;
  const status: string[] = [];
  const nameservers: string[] = [...nsRecords];

  if (rdapData) {
    if (Array.isArray(rdapData.events)) {
      for (const ev of rdapData.events) {
        const action = ev.eventAction?.toLowerCase();
        if ((action === "registration" || action === "created") && ev.eventDate) {
          created = ev.eventDate;
        } else if (action === "expiration" && ev.eventDate) {
          expires = ev.eventDate;
        }
      }
    }

    if (Array.isArray(rdapData.entities)) {
      for (const ent of rdapData.entities) {
        if (Array.isArray(ent.roles) && ent.roles.includes("registrar")) {
          if (Array.isArray(ent.vcardArray) && Array.isArray(ent.vcardArray[1])) {
            for (const item of ent.vcardArray[1] as unknown[]) {
              if (Array.isArray(item) && item[0] === "fn" && typeof item[3] === "string") {
                registrar = item[3];
                break;
              }
            }
          }
          if (!registrar && typeof ent.handle === "string") {
            registrar = ent.handle;
          }
        }
      }
    }

    if (Array.isArray(rdapData.status)) {
      for (const s of rdapData.status) {
        if (typeof s === "string" && !status.includes(s)) {
          status.push(s);
        }
      }
    }

    if (Array.isArray(rdapData.nameservers)) {
      for (const ns of rdapData.nameservers) {
        const name = typeof ns === "string" ? ns : ns.ldhName;
        if (name && typeof name === "string") {
          const clean = name.toLowerCase().replace(/\.$/, "");
          if (!nameservers.includes(clean)) {
            nameservers.push(clean);
          }
        }
      }
    }
  }

  let ageDays: number | null = null;
  if (created) {
    const cDate = new Date(created);
    if (!isNaN(cDate.getTime())) {
      ageDays = Math.max(0, Math.floor((now.getTime() - cDate.getTime()) / (1000 * 60 * 60 * 24)));
    }
  }

  const facts: DomainFacts = {
    registrableDomain: reg,
    registrar,
    created,
    expires,
    ageDays,
    status,
    nameservers,
    a: aRecords,
    aaaa: aaaaRecords,
    mx: mxRecords,
    txt: txtRecords,
    cname: cnameRecords,
  };

  const findings: Finding[] = [];

  // Finding 1: domain-age
  // pass if >2 years (weight 15)
  // warn if 6months-2years (weight 15)
  // fail if <6 months (weight 20)
  // unknown if no data
  if (ageDays !== null && created) {
    const years = (ageDays / 365.25).toFixed(1);
    const dateFormatted = new Date(created).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
    if (ageDays >= 730) {
      findings.push({
        id: "domain-age",
        module: "domain",
        title: "Domain registration age",
        status: "pass",
        kind: "observation",
        weight: 15,
        evidence: `Domain was registered on ${dateFormatted} (${years} years / ${ageDays} days old). Established domains have lower incidence of malicious campaigns.`,
        source: "RDAP registry data",
        observedAt,
      });
    } else if (ageDays >= 180) {
      findings.push({
        id: "domain-age",
        module: "domain",
        title: "Domain registration age",
        status: "warn",
        kind: "observation",
        weight: 15,
        evidence: `Domain was registered relatively recently on ${dateFormatted} (${years} years / ${ageDays} days old).`,
        source: "RDAP registry data",
        observedAt,
        remediation: "Verify the domain reputation through secondary channels if conducting financial transactions.",
      });
    } else {
      findings.push({
        id: "domain-age",
        module: "domain",
        title: "Domain registration age",
        status: "fail",
        kind: "observation",
        weight: 20,
        evidence: `Domain is brand new, registered on ${dateFormatted} (only ${ageDays} days old). Newly registered domains (NRDs) carry significantly elevated phishing and malware risk.`,
        source: "RDAP registry data",
        observedAt,
        remediation: "Treat newly registered domains with extreme caution, especially when requesting credentials or payment.",
      });
    }
  } else {
    findings.push({
      id: "domain-age",
      module: "domain",
      title: "Domain registration age",
      status: "unknown",
      kind: "observation",
      weight: 15,
      evidence: rdapError
        ? `Domain registration date could not be determined: ${rdapError}.`
        : "RDAP record did not disclose domain registration timestamp (common for certain ccTLD registries).",
      source: "RDAP registry data",
      observedAt,
    });
  }

  // Finding 2: domain-rdap
  findings.push({
    id: "domain-rdap",
    module: "domain",
    title: "RDAP registration data",
    status: rdapData ? "pass" : "unknown",
    kind: "observation",
    weight: 5,
    evidence: rdapData
      ? `RDAP registration records located for "${reg}". Registrar: ${registrar || "Registry-managed / masked"}.`
      : `RDAP registration records not available for "${reg}" (${rdapError || "Query timed out or unsupported TLD"}).`,
    source: "RDAP.org",
    observedAt,
  });

  // Finding 3: domain-dns-a
  findings.push({
    id: "domain-dns-a",
    module: "domain",
    title: "DNS A record",
    status: aRecords.length > 0 ? "pass" : "unknown",
    kind: "observation",
    weight: 5,
    evidence: aRecords.length > 0
      ? `Hostname resolves to IPv4 address(es): ${aRecords.join(", ")}.`
      : "No IPv4 (A) records resolved for this hostname over DNS-over-HTTPS.",
    source: "Cloudflare DNS-over-HTTPS",
    observedAt,
  });

  // Finding 4: domain-nameservers
  findings.push({
    id: "domain-nameservers",
    module: "domain",
    title: "Nameservers configured",
    status: nameservers.length > 0 ? "pass" : "unknown",
    kind: "observation",
    weight: 5,
    evidence: nameservers.length > 0
      ? `Authoritative nameservers identified: ${nameservers.slice(0, 4).join(", ")}${nameservers.length > 4 ? ` (+${nameservers.length - 4} more)` : ""}.`
      : "No nameserver records could be discovered via DNS or RDAP.",
    source: "Cloudflare DNS / RDAP",
    observedAt,
  });

  // Finding 5: domain-status
  // warn if clientHold/serverHold in status (weight 15), pass otherwise
  const holdStatuses = status.filter((s) => s.toLowerCase().includes("hold"));
  if (holdStatuses.length > 0) {
    findings.push({
      id: "domain-status",
      module: "domain",
      title: "Domain status flags",
      status: "warn",
      kind: "observation",
      weight: 15,
      evidence: `Domain has suspension hold flags active: ${holdStatuses.join(", ")}. The registry or registrar has suspended resolution.`,
      source: "RDAP registry data",
      observedAt,
      remediation: "Investigate domain suspension reasons with the registry or registrar.",
    });
  } else {
    findings.push({
      id: "domain-status",
      module: "domain",
      title: "Domain status flags",
      status: "pass",
      kind: "observation",
      weight: 5,
      evidence: status.length > 0
        ? `Registry status flags: ${status.join(", ")} (no suspension holds).`
        : "Domain exhibits standard active status with no administrative holds.",
      source: "RDAP registry data",
      observedAt,
    });
  }

  return {
    module: "domain",
    findings,
    facts,
    ...(rdapError ? { error: rdapError } : {}),
  };
}
