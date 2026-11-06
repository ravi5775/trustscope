import type { Finding } from "./types";

export const RULESET_VERSION = "trustscope-rules-2026.11.1";

export type Verdict = "Low risk" | "Moderate risk" | "High risk" | "Critical risk" | "Insufficient evidence";

export interface RiskAssessment {
  risk: number; // 0-100, indicator-based, not a probability
  coverage: number; // 0-100, share of checks that produced evidence
  confidence: "High" | "Medium" | "Low";
  verdict: Verdict;
  contributors: { title: string; points: number; status: Finding["status"]; kind: Finding["kind"] }[];
  counts: Record<Finding["status"], number>;
  rulesetVersion: string;
}

/**
 * fail = full weight, warn = half weight, pass/unknown = 0.
 * Unknown findings never add risk but lower coverage.
 * Risk is the weighted share of evaluated points; a confirmed threat match forces at least 90.
 */
export function assessRisk(findings: Finding[]): RiskAssessment {
  const counts = { pass: 0, warn: 0, fail: 0, unknown: 0 };
  let earned = 0;
  let possible = 0;
  let totalWeight = 0;
  const contributors: RiskAssessment["contributors"] = [];
  for (const f of findings) {
    counts[f.status]++;
    totalWeight += f.weight;
    if (f.status === "unknown") continue;
    possible += f.weight;
    const pts = f.status === "fail" ? f.weight : f.status === "warn" ? f.weight / 2 : 0;
    if (pts > 0) {
      earned += pts;
      contributors.push({ title: f.title, points: pts, status: f.status, kind: f.kind });
    }
  }
  // Scale: sum of points, softened so many small warnings cannot exceed real failures.
  let risk = possible === 0 ? 0 : Math.round(Math.min(100, (earned / Math.max(possible * 0.45, 1)) * 100));
  if (findings.some((f) => f.kind === "confirmed" && f.status === "fail")) risk = Math.max(risk, 90);
  const coverage = totalWeight === 0 ? 0 : Math.round((possible / totalWeight) * 100);
  const confidence = coverage >= 80 ? "High" : coverage >= 55 ? "Medium" : "Low";
  let verdict: Verdict =
    risk >= 75 ? "Critical risk" : risk >= 50 ? "High risk" : risk >= 25 ? "Moderate risk" : "Low risk";
  if (coverage < 40 && risk < 50) verdict = "Insufficient evidence";
  contributors.sort((a, b) => b.points - a.points);
  return { risk, coverage, confidence, verdict, contributors, counts, rulesetVersion: RULESET_VERSION };
}
