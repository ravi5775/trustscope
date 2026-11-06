import { useState } from "react";
import {
  Shield,
  AlertTriangle,
  XCircle,
  CheckCircle2,
  HelpCircle,
  Activity,
  Clock,
  ShieldCheck,
  Flame,
  Copy,
  Check,
  ExternalLink,
  Radar,
  Radio,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/use-toast";
import type { RiskAssessment } from "@/lib/analysis/scoring";

export interface RiskScoreProps {
  assessment: RiskAssessment;
  url: string;
  hostname: string;
  scannedAt: string;
}

export const RiskScore = ({ assessment, url, hostname, scannedAt }: RiskScoreProps) => {
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();
  const { risk, coverage, confidence, verdict, contributors, counts, rulesetVersion } = assessment;

  // Visual status bucket configuration
  const getVisualConfig = () => {
    if (verdict === "Insufficient evidence") {
      return {
        icon: HelpCircle,
        title: "Insufficient Evidence",
        colorClass: "text-muted-foreground",
        strokeColor: "#94a3b8",
        gradientClass: "bg-muted text-foreground",
        borderClass: "border-muted-foreground/30",
        badgeVariant: "secondary" as const,
        description: "Coverage is too low to reliably clear or flag this target. Sourced public records yielded minimal telemetry.",
      };
    }
    if (risk < 25) {
      return {
        icon: ShieldCheck,
        title: "Low Risk Domain",
        colorClass: "text-safe",
        strokeColor: "#22c55e",
        gradientClass: "status-safe",
        borderClass: "border-safe/30",
        badgeVariant: "default" as const,
        description: "All evaluated indicators align with standard authentic domain behaviors and TLS hygiene.",
      };
    }
    if (risk < 60) {
      return {
        icon: AlertTriangle,
        title: "Moderate Risk Detected",
        colorClass: "text-warning",
        strokeColor: "#f59e0b",
        gradientClass: "status-warning",
        borderClass: "border-warning/30",
        badgeVariant: "default" as const,
        description: "Structural anomalies or missing cryptographic controls detected. Exercise caution before transacting.",
      };
    }
    return {
      icon: XCircle,
      title: "Elevated Security Threat",
      colorClass: "text-danger",
      strokeColor: "#ef4444",
      gradientClass: "status-danger",
      borderClass: "border-danger/30",
      badgeVariant: "destructive" as const,
      description: "Severe threat indicators, brand imitation, or malicious structural patterns identified.",
    };
  };

  const visual = getVisualConfig();
  const Icon = visual.icon;
  const topContributors = contributors.slice(0, 4);
  const formattedDate = new Date(scannedAt).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  });

  const totalRules = counts.pass + counts.warn + counts.fail + counts.unknown;

  const copySummary = async () => {
    const text = `TrustScope Audit for ${hostname}:
Verdict: ${verdict} | Risk Score: ${risk}/100 | Coverage: ${coverage}% (${confidence} confidence)
Checks: ${counts.pass} Passed, ${counts.warn} Warnings, ${counts.fail} Failed, ${counts.unknown} Unknown
Evaluated at: ${formattedDate} via ${rulesetVersion}`;

    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast({
        title: "Audit Summary Copied",
        description: "Copied findings summary to clipboard.",
      });
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({
        title: "Copy Failed",
        description: "Could not access clipboard.",
        variant: "destructive",
      });
    }
  };

  // SVG Circular Gauge calculations
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffsetRisk = circumference - (risk / 100) * circumference;
  const strokeDashoffsetCov = circumference - (coverage / 100) * circumference;

  return (
    <Card className="glass-card max-w-5xl mx-auto animate-bounce-in border-border/80 overflow-hidden relative shadow-cyber">
      {/* Background radial glow */}
      <div
        className={`absolute -top-32 -right-32 w-96 h-96 rounded-full blur-[120px] opacity-20 pointer-events-none ${
          risk < 25 ? "bg-safe" : risk < 60 ? "bg-warning" : "bg-danger"
        }`}
      />
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-60" />

      <CardHeader className="text-center pb-4 pt-8 relative z-10">
        <div className="flex items-center justify-center mb-4">
          <div className={`p-4 rounded-2xl ${visual.gradientClass} animate-risk-pulse shadow-xl border border-white/10`}>
            <Icon className="w-12 h-12" />
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-center gap-2 mb-2">
          <Badge className={`${visual.gradientClass} text-xs font-semibold px-3 py-1 tracking-wider uppercase shadow-md`}>
            {verdict}
          </Badge>
          <Badge variant="outline" className="text-xs bg-muted/60 border-border text-foreground font-mono">
            {confidence} Confidence
          </Badge>
          <Button
            variant="ghost"
            size="sm"
            onClick={copySummary}
            className="h-6 px-2 text-[11px] gap-1 text-muted-foreground hover:text-foreground"
          >
            {copied ? <Check className="w-3 h-3 text-safe" /> : <Copy className="w-3 h-3" />}
            {copied ? "Copied" : "Copy Summary"}
          </Button>
        </div>

        <CardTitle className="text-3xl sm:text-4xl font-extrabold tracking-tight mb-1 text-foreground">
          {visual.title}
        </CardTitle>
        <p className="text-sm text-muted-foreground max-w-xl mx-auto leading-relaxed">{visual.description}</p>
      </CardHeader>

      <CardContent className="space-y-6 px-4 sm:px-8 pb-8 relative z-10">
        {/* Analyzed Target Details Bar */}
        <div className="bg-muted/30 border border-border/60 rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 font-mono">
            <span className="px-2 py-0.5 rounded bg-primary/10 border border-primary/20 text-primary uppercase text-[10px] font-bold">
              Target
            </span>
            <span className="font-semibold text-foreground text-sm truncate max-w-xs sm:max-w-md select-all">
              {url}
            </span>
          </div>

          <div className="flex items-center gap-3 text-muted-foreground font-mono text-[11px]">
            <span className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />
              {formattedDate}
            </span>
            <span className="text-border">|</span>
            <span className="text-cyan">{rulesetVersion}</span>
          </div>
        </div>

        {/* Dual Cyberpunk Gauge Cluster */}
        <div className="grid md:grid-cols-2 gap-6 bg-gradient-to-b from-card/80 to-muted/20 border border-border/60 rounded-2xl p-6 relative overflow-hidden">
          {/* Main Risk Score Gauge */}
          <div className="flex flex-col sm:flex-row items-center gap-6">
            <div className="relative w-36 h-36 shrink-0 flex items-center justify-center">
              <svg className="w-36 h-36 -rotate-90 transform" viewBox="0 0 128 128">
                {/* Background circle */}
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  stroke="currentColor"
                  strokeWidth="9"
                  className="text-muted/40"
                  fill="transparent"
                />
                {/* Dynamic colored progress circle */}
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  stroke={visual.strokeColor}
                  strokeWidth="9"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffsetRisk}
                  strokeLinecap="round"
                  className="transition-all duration-1000 ease-out"
                  fill="transparent"
                  style={{ filter: `drop-shadow(0 0 8px ${visual.strokeColor})` }}
                />
              </svg>

              {/* Number centered inside */}
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className={`text-3xl font-black ${visual.colorClass} tracking-tight`}>
                  {risk}
                </span>
                <span className="text-[10px] font-mono text-muted-foreground uppercase">Score / 100</span>
              </div>
            </div>

            <div className="space-y-2 text-center sm:text-left flex-1">
              <div className="flex items-center justify-center sm:justify-start gap-1.5">
                <Radio className="w-4 h-4 text-primary" />
                <h4 className="text-sm font-bold uppercase tracking-wider text-foreground">
                  Computed Risk Index
                </h4>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Aggregated indicator penalty score. Evaluates structural anomalies, expired certs, and brand lures.
              </p>
              <div className="flex items-center justify-center sm:justify-start gap-2 pt-1 text-[11px] font-mono">
                <span className="text-safe">0-24 Low</span>
                <span className="text-muted-foreground">•</span>
                <span className="text-warning">25-49 Mod</span>
                <span className="text-muted-foreground">•</span>
                <span className="text-danger">50-74 High</span>
                <span className="text-muted-foreground">•</span>
                <span className="text-danger font-bold">75+ Crit</span>
              </div>
            </div>
          </div>

          {/* Evidence Coverage Gauge */}
          <div className="flex flex-col sm:flex-row items-center gap-6 md:border-l md:border-border/50 md:pl-6 pt-4 md:pt-0 border-t md:border-t-0">
            <div className="relative w-36 h-36 shrink-0 flex items-center justify-center">
              <svg className="w-36 h-36 -rotate-90 transform" viewBox="0 0 128 128">
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  stroke="currentColor"
                  strokeWidth="9"
                  className="text-muted/40"
                  fill="transparent"
                />
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  stroke="#38bdf8"
                  strokeWidth="9"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffsetCov}
                  strokeLinecap="round"
                  className="transition-all duration-1000 ease-out"
                  fill="transparent"
                  style={{ filter: "drop-shadow(0 0 8px #38bdf8)" }}
                />
              </svg>

              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-3xl font-black text-cyan tracking-tight">
                  {coverage}%
                </span>
                <span className="text-[10px] font-mono text-muted-foreground uppercase">Coverage</span>
              </div>
            </div>

            <div className="space-y-2 text-center sm:text-left flex-1">
              <div className="flex items-center justify-center sm:justify-start gap-1.5">
                <Activity className="w-4 h-4 text-cyan" />
                <h4 className="text-sm font-bold uppercase tracking-wider text-foreground">
                  Evidence Completeness
                </h4>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Percentage of verifiable security rule weight successfully retrieved via public telemetry channels.
              </p>
              <div className="flex items-center justify-center sm:justify-start gap-2 pt-1 text-xs">
                <span className="text-muted-foreground">Confidence Rating:</span>
                <Badge
                  variant="outline"
                  className={`text-[10px] font-mono ${
                    confidence === "High"
                      ? "border-safe text-safe bg-safe/10"
                      : confidence === "Medium"
                      ? "border-warning text-warning bg-warning/10"
                      : "border-muted-foreground text-muted-foreground"
                  }`}
                >
                  {confidence} Level
                </Badge>
              </div>
            </div>
          </div>
        </div>

        {/* Verification Rules Summary Row */}
        <div>
          <div className="flex items-center justify-between mb-2.5">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground font-mono flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-primary" />
              Rule Verification Breakdown ({totalRules} Rules)
            </p>
            <span className="text-[11px] text-muted-foreground font-mono">
              Passed: {Math.round((counts.pass / Math.max(totalRules, 1)) * 100)}%
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl bg-safe/10 border border-safe/30 transition-all hover:bg-safe/15">
              <div className="flex items-center justify-between mb-1">
                <CheckCircle2 className="w-5 h-5 text-safe" />
                <span className="text-[10px] font-mono font-semibold text-safe uppercase">Pass</span>
              </div>
              <div className="text-2xl font-black text-safe">{counts.pass}</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Verified Safe</div>
            </div>

            <div className="p-3.5 rounded-xl bg-warning/10 border border-warning/30 transition-all hover:bg-warning/15">
              <div className="flex items-center justify-between mb-1">
                <AlertTriangle className="w-5 h-5 text-warning" />
                <span className="text-[10px] font-mono font-semibold text-warning uppercase">Warn</span>
              </div>
              <div className="text-2xl font-black text-warning">{counts.warn}</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Potential Risk</div>
            </div>

            <div className="p-3.5 rounded-xl bg-danger/10 border border-danger/30 transition-all hover:bg-danger/15">
              <div className="flex items-center justify-between mb-1">
                <XCircle className="w-5 h-5 text-danger" />
                <span className="text-[10px] font-mono font-semibold text-danger uppercase">Fail</span>
              </div>
              <div className="text-2xl font-black text-danger">{counts.fail}</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Failed Checks</div>
            </div>

            <div className="p-3.5 rounded-xl bg-muted/40 border border-border/70 transition-all hover:bg-muted/60">
              <div className="flex items-center justify-between mb-1">
                <HelpCircle className="w-5 h-5 text-muted-foreground" />
                <span className="text-[10px] font-mono font-semibold text-muted-foreground uppercase">N/A</span>
              </div>
              <div className="text-2xl font-black text-foreground">{counts.unknown}</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Unresolved</div>
            </div>
          </div>
        </div>

        {/* Top Risk Contributors */}
        <div>
          <div className="flex items-center justify-between mb-2.5">
            <div className="flex items-center gap-1.5">
              <Flame className="w-4 h-4 text-warning" />
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground font-mono">
                Primary Risk Indicators
              </p>
            </div>
            {topContributors.length > 0 && (
              <span className="text-[11px] text-muted-foreground font-mono">
                {topContributors.length} active penalty flags
              </span>
            )}
          </div>

          {topContributors.length > 0 ? (
            <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
              {topContributors.map((c, idx) => (
                <div
                  key={idx}
                  className={`p-3.5 rounded-xl border flex flex-col justify-between transition-all hover:scale-[1.02] ${
                    c.status === "fail"
                      ? "bg-danger/10 border-danger/30 text-danger-foreground"
                      : "bg-warning/10 border-warning/30 text-warning-foreground"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-xs font-bold line-clamp-2 text-foreground">
                      {c.title}
                    </span>
                    <Badge
                      variant="outline"
                      className={`text-[10px] font-mono shrink-0 ${
                        c.status === "fail"
                          ? "border-danger text-danger bg-danger/20 font-bold"
                          : "border-warning text-warning bg-warning/20 font-bold"
                      }`}
                    >
                      +{c.points} pts
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/30">
                    <span className="capitalize font-mono text-[10px]">{c.status}</span>
                    <span className="uppercase text-[9px] font-mono tracking-wider opacity-75">{c.kind}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-safe/10 border border-safe/30 text-xs text-safe flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 shrink-0 text-safe" />
              <div>
                <span className="font-bold block">Clean Baseline Posture</span>
                <span>No risk penalty points accrued. All evaluated indicators passed without warnings or failures.</span>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
