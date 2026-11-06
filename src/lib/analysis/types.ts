export type FindingStatus = "pass" | "warn" | "fail" | "unknown";

/** confirmed = matched an authoritative source; observation = measured fact; heuristic = rule-based indicator */
export type FindingKind = "confirmed" | "observation" | "heuristic";

export type ModuleId = "lexical" | "domain" | "certificates" | "http" | "threat";

export interface Finding {
  id: string;
  module: ModuleId;
  title: string;
  status: FindingStatus;
  kind: FindingKind;
  /** Risk points contributed when status is "fail" (half for "warn"). */
  weight: number;
  evidence: string;
  source: string;
  observedAt: string;
  remediation?: string | undefined;
}

export interface DomainFacts {
  registrableDomain: string;
  registrar: string | null;
  created: string | null;
  expires: string | null;
  ageDays: number | null;
  status: string[];
  nameservers: string[];
  a: string[];
  aaaa: string[];
  mx: string[];
  txt: string[];
  cname: string[];
}

export interface CertFacts {
  latestIssuer: string | null;
  latestNotBefore: string | null;
  latestNotAfter: string | null;
  firstSeen: string | null;
  certificateCount: number | null;
  subdomains: string[];
}

export interface HttpFacts {
  finalUrl: string | null;
  statusCode: number | null;
  redirectChain: string[];
  pageTitle: string | null;
  headers: Record<string, string>;
}

export interface ModuleResult<F = unknown> {
  module: ModuleId;
  findings: Finding[];
  facts: F | null;
  error?: string;
}
