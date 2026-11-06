import type { Finding, HttpFacts, ModuleResult } from "./types";

const SOURCE_NOTE = "Client-side transport analysis (backend proxy required for live HTTP header inspection)";

export async function runHttpModule(url: URL): Promise<ModuleResult<HttpFacts>> {
  const isHttps = url.protocol === "https:";
  const observedAt = new Date().toISOString();

  const facts: HttpFacts = {
    finalUrl: url.href,
    statusCode: null,
    redirectChain: [],
    pageTitle: null,
    headers: {},
  };

  const findings: Finding[] = [];

  // Finding 1: http-protocol
  findings.push({
    id: "http-protocol",
    module: "http",
    title: "Transport protocol",
    status: isHttps ? "pass" : "fail",
    kind: "observation",
    weight: 20,
    evidence: isHttps
      ? "Target is configured with the secure HTTPS protocol."
      : "Target is configured with plain HTTP protocol, allowing cleartext eavesdropping.",
    source: SOURCE_NOTE,
    observedAt,
    remediation: isHttps ? undefined : "Enable TLS encryption and configure web server to enforce HTTPS redirection.",
  });

  // Finding 2: http-hsts-inference
  findings.push({
    id: "http-hsts-inference",
    module: "http",
    title: "HSTS inferred",
    status: isHttps ? "pass" : "unknown",
    kind: "observation",
    weight: 10,
    evidence: isHttps
      ? "HTTPS scheme is active. Verification of Strict-Transport-Security (HSTS) max-age and preload status requires server-side header evaluation."
      : "HSTS cannot be active on unencrypted HTTP connections.",
    source: SOURCE_NOTE,
    observedAt,
    remediation: isHttps
      ? undefined
      : "Upgrade server to HTTPS and add the 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' response header.",
  });

  // Finding 3: http-mixed-content
  findings.push({
    id: "http-mixed-content",
    module: "http",
    title: "Mixed content risk",
    status: isHttps ? "pass" : "warn",
    kind: "observation",
    weight: 8,
    evidence: isHttps
      ? "Primary URL specifies HTTPS; initial document is delivered over an encrypted channel."
      : "Primary connection is plain HTTP; all assets and scripts are loaded insecurely with high risk of man-in-the-middle attacks.",
    source: SOURCE_NOTE,
    observedAt,
    remediation: isHttps
      ? undefined
      : "Enforce HTTPS for all web resources and declare Content-Security-Policy: upgrade-insecure-requests.",
  });

  return {
    module: "http",
    findings,
    facts,
  };
}

