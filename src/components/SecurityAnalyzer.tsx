import { useState } from "react";
import {
  Shield,
  Globe,
  Lock,
  AlertTriangle,
  CheckCircle2,
  Activity,
  RotateCcw,
  Search,
  Server,
  Layers,
  ArrowRight,
  Terminal,
  Cpu,
  Radio,
  Download,
  Share2,
  X,
  Sparkles,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/components/ui/use-toast";
import { normalizeTarget } from "@/lib/analysis/url";
import { analyzeLexical } from "@/lib/analysis/lexical";
import { assessRisk, type RiskAssessment } from "@/lib/analysis/scoring";
import { runCertModule } from "@/lib/analysis/certModule";
import { runHttpModule } from "@/lib/analysis/httpModule";
import { runDomainModule } from "@/lib/analysis/domainModule";
import { runThreatModule } from "@/lib/analysis/threatModule";
import type { Finding } from "@/lib/analysis/types";
import { RiskScore } from "./RiskScore";
import { SecurityReport, type AnalysisResult } from "./SecurityReport";

const SAMPLE_TARGETS = [
  { label: "google.com", desc: "Benign target", tag: "Clean" },
  { label: "paypal-security-update.com", desc: "Monitored brand lure", tag: "Suspicious" },
  { label: "xn--pple-43d.com", desc: "IDN Homoglyph", tag: "Spoof" },
  { label: "192.168.1.1", desc: "Private network", tag: "SSRF Blocked" },
];

export const SecurityAnalyzer = () => {
  const [targetInput, setTargetInput] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState("");
  const [scanSteps, setScanSteps] = useState<{ label: string; done: boolean }[]>([]);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const { toast } = useToast();

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !isAnalyzing) {
      void analyzeWebsite();
    }
  };

  const handleReset = () => {
    setAnalysisResult(null);
    setAnalysisProgress(0);
    setScanPhase("");
    setScanSteps([]);
    setTargetInput("");
  };

  const setSample = (sample: string) => {
    setTargetInput(sample);
  };

  const exportReportJson = () => {
    if (!analysisResult) return;
    const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `trustscope-${analysisResult.hostname}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast({
      title: "Audit Report Exported",
      description: "Downloaded complete telemetry JSON snapshot.",
    });
  };

  const analyzeWebsite = async (overrideTarget?: string) => {
    const rawTarget = overrideTarget ?? targetInput;
    if (!rawTarget.trim()) {
      toast({
        title: "Address Required",
        description: "Please enter a web address or domain name to analyze.",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    setAnalysisProgress(10);
    setScanPhase("Sanitizing input & verifying SSRF boundary...");
    setScanSteps([
      { label: "Input Sanitization & SSRF Guard", done: false },
      { label: "Certificate Transparency (crt.sh)", done: false },
      { label: "ICANN RDAP & Cloudflare DoH", done: false },
      { label: "Phishing & Homoglyph Heuristics", done: false },
      { label: "Calibrated Risk Synthesis", done: false },
    ]);

    // 1. Validation with SSRF guard and scheme normalisation
    const norm = normalizeTarget(rawTarget);
    if (!norm.ok) {
      setIsAnalyzing(false);
      setAnalysisProgress(0);
      setScanPhase("");
      setScanSteps([]);
      toast({
        title: "Target Validation Blocked",
        description: norm.error,
        variant: "destructive",
      });
      return;
    }

    try {
      setScanSteps((prev) => prev.map((s, i) => (i === 0 ? { ...s, done: true } : s)));
      setScanPhase("Interrogating Certificate Transparency logs...");
      setAnalysisProgress(30);

      const certPromise = runCertModule(norm.hostname, norm.url.protocol === "https:").then((res) => {
        setScanSteps((prev) => prev.map((s, i) => (i === 1 ? { ...s, done: true } : s)));
        return res;
      });

      const domainPromise = runDomainModule(norm.hostname).then((res) => {
        setScanSteps((prev) => prev.map((s, i) => (i === 2 ? { ...s, done: true } : s)));
        return res;
      });

      const httpPromise = runHttpModule(norm.url);
      const threatPromise = runThreatModule(norm.hostname, norm.url);

      setScanPhase("Querying DNS-over-HTTPS & ICANN registry...");
      setAnalysisProgress(55);

      const [certResult, domainResult, httpResult, threatResult] = await Promise.all([
        certPromise,
        domainPromise,
        httpPromise,
        threatPromise,
      ]);

      setScanPhase("Evaluating lexical patterns & brand lookalikes...");
      setAnalysisProgress(80);
      const lexicalFindings = analyzeLexical(norm.url);
      setScanSteps((prev) => prev.map((s, i) => (i === 3 ? { ...s, done: true } : s)));

      await new Promise((r) => setTimeout(r, 180));

      setScanPhase("Synthesizing risk assessment & confidence score...");
      setAnalysisProgress(100);
      setScanSteps((prev) => prev.map((s, i) => (i === 4 ? { ...s, done: true } : s)));

      const allFindings: Finding[] = [
        ...lexicalFindings,
        ...domainResult.findings,
        ...certResult.findings,
        ...httpResult.findings,
        ...threatResult.findings,
      ];

      const assessment: RiskAssessment = assessRisk(allFindings);

      const result: AnalysisResult = {
        url: norm.url.href,
        hostname: norm.hostname,
        assessment,
        moduleResults: {
          lexical: lexicalFindings,
          cert: certResult,
          http: httpResult,
          domain: domainResult,
          threat: threatResult,
        },
        scannedAt: new Date().toISOString(),
      };

      await new Promise((r) => setTimeout(r, 200));

      setAnalysisResult(result);
      toast({
        title: "Security Audit Complete",
        description: `Verified ${norm.hostname}. Risk verdict: ${assessment.verdict} (${assessment.risk}/100)`,
      });
    } catch (err: unknown) {
      console.error("Analysis failure:", err);
      toast({
        title: "Audit Interrupted",
        description: "An unexpected error occurred during security module execution.",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-background relative overflow-hidden text-foreground selection:bg-primary/20">
      {/* Cyber Grid Background */}
      <div className="absolute inset-0 cyber-grid pointer-events-none" />

      {/* Ambient Lighting Orbs */}
      <div className="absolute -top-32 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-primary/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/3 -right-48 w-[450px] h-[450px] bg-cyan/8 rounded-full blur-[130px] pointer-events-none" />
      <div className="absolute top-2/3 -left-48 w-[450px] h-[450px] bg-purple/6 rounded-full blur-[130px] pointer-events-none" />

      {/* Main Content */}
      <div className="relative z-10 container mx-auto px-4 py-8 sm:py-12 max-w-6xl">
        {/* Top SOC Status Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pb-6 mb-8 border-b border-border/50 text-xs text-muted-foreground font-mono">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-safe font-semibold">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-safe opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-safe" />
              </span>
              NODE: ONLINE
            </span>
            <span className="text-border">|</span>
            <span className="flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-primary" />
              ZERO-KNOWLEDGE BROWSER RUNTIME
            </span>
          </div>

          <div className="flex items-center gap-3">
            <span className="hud-tag text-[10px] text-primary-glow border-primary/30">
              TRUSTSCOPE v2026.11
            </span>
            <span className="hidden sm:inline-flex items-center gap-1 text-[11px]">
              <Cpu className="w-3.5 h-3.5 text-cyan" />
              CORS-SECURED
            </span>
          </div>
        </div>

        {/* Header */}
        <div className="text-center mb-10 animate-fade-in-up">
          <div className="flex items-center justify-center mb-5">
            <div className="relative p-4 rounded-2xl bg-gradient-to-b from-primary/20 to-primary/5 border border-primary/40 shadow-primary group cursor-default transition-all duration-300 hover:scale-105">
              <div className="absolute inset-0 rounded-2xl bg-primary/20 blur-xl opacity-50 group-hover:opacity-100 transition-opacity" />
              <Shield className="w-12 h-12 text-primary relative z-10 animate-cyber-glow" />
            </div>
          </div>

          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/30 text-xs font-mono text-primary mb-3">
            <Sparkles className="w-3 h-3 text-cyan" />
            Autonomous Client-Side Cybersecurity Engine
          </div>

          <h1 className="text-4xl sm:text-6xl font-black tracking-tight mb-4">
            <span className="text-gradient-primary">TrustScope</span>{" "}
            <span className="text-foreground">Analyzer</span>
          </h1>

          <p className="text-base sm:text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed">
            Real-time, zero-knowledge domain trust & security intelligence. Inspects Certificate
            Transparency, RDAP registration, DNS-over-HTTPS, and phishing heuristics directly in your browser.
          </p>
        </div>

        {/* Input Bar */}
        <Card className="glass-card max-w-3xl mx-auto mb-10 shadow-cyber border-border/80 hover-lift-sm relative overflow-hidden">
          {/* Subtle top glowing line */}
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-primary to-transparent opacity-80" />

          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
                <Globe className="w-5 h-5 text-primary" />
                Target Website Analysis
              </CardTitle>
              {analysisResult && (
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={exportReportJson}
                    className="gap-1.5 text-xs h-8 border-border hover:bg-muted/60"
                  >
                    <Download className="w-3.5 h-3.5 text-primary" />
                    Export JSON
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleReset}
                    className="gap-1.5 text-xs h-8 border-border hover:bg-muted/60"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    New Scan
                  </Button>
                </div>
              )}
            </div>
            <CardDescription className="text-xs sm:text-sm">
              Enter any fully qualified domain name or URL (e.g. <code>example.com</code> or <code>https://accounts.google.com</code>)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="example.com or https://secure-login.net"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  className="glass-input pl-10 pr-9 h-12 text-base font-mono"
                  disabled={isAnalyzing}
                  autoFocus
                />
                {targetInput && !isAnalyzing && (
                  <button
                    onClick={() => setTargetInput("")}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-1 transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
              <Button
                onClick={() => analyzeWebsite()}
                disabled={isAnalyzing}
                className="h-12 px-7 font-semibold bg-gradient-to-r from-primary via-primary-glow to-cyan hover:brightness-110 text-primary-foreground shadow-primary transition-cyber shrink-0"
              >
                {isAnalyzing ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-2 border-primary-foreground border-t-transparent mr-2" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <span>Inspect Target</span>
                    <ArrowRight className="w-4 h-4 ml-1.5" />
                  </>
                )}
              </Button>
            </div>

            {/* Quick Demo Target Chips */}
            {!isAnalyzing && (
              <div className="mt-3.5 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                <span className="font-mono text-[11px] text-muted-foreground/80 flex items-center gap-1 mr-1">
                  <Zap className="w-3 h-3 text-warning" />
                  Try sample:
                </span>
                {SAMPLE_TARGETS.map((s, idx) => (
                  <button
                    key={idx}
                    onClick={() => setSample(s.label)}
                    className="font-mono text-[11px] px-2 py-0.5 rounded bg-muted/40 hover:bg-primary/20 border border-border hover:border-primary/50 text-foreground/80 hover:text-foreground transition-colors flex items-center gap-1.5"
                  >
                    <span>{s.label}</span>
                    <span className="text-[9px] uppercase px-1 rounded bg-secondary text-muted-foreground">
                      {s.tag}
                    </span>
                  </button>
                ))}
              </div>
            )}

            {/* High-Tech Scanning Progress HUD */}
            {isAnalyzing && (
              <div className="mt-5 space-y-3 p-4 rounded-xl bg-card/60 border border-primary/30 animate-fade-in-up">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="flex items-center gap-2 text-primary font-semibold">
                    <Activity className="w-4 h-4 animate-spin text-cyan" />
                    {scanPhase}
                  </span>
                  <span className="text-cyan font-bold">{analysisProgress}%</span>
                </div>

                <div className="relative">
                  <Progress value={analysisProgress} className="h-2 bg-muted/80" />
                  <div
                    className="absolute top-0 bottom-0 scan-beam pointer-events-none"
                    style={{ left: `${analysisProgress}%` }}
                  />
                </div>

                {/* Sub-steps checklist */}
                <div className="grid sm:grid-cols-2 gap-2 pt-2 border-t border-border/40">
                  {scanSteps.map((step, idx) => (
                    <div
                      key={idx}
                      className={`flex items-center gap-2 text-xs font-mono transition-opacity ${
                        step.done ? "text-safe" : "text-muted-foreground opacity-60"
                      }`}
                    >
                      {step.done ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-safe shrink-0" />
                      ) : (
                        <div className="w-3.5 h-3.5 rounded-full border border-muted-foreground/40 shrink-0" />
                      )}
                      <span className="truncate">{step.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Results View */}
        {analysisResult && !isAnalyzing && (
          <div className="space-y-8 animate-fade-in-up">
            <RiskScore
              assessment={analysisResult.assessment}
              url={analysisResult.url}
              hostname={analysisResult.hostname}
              scannedAt={analysisResult.scannedAt}
            />

            <SecurityReport result={analysisResult} />
          </div>
        )}

        {/* Feature Cards Grid (Shown when idle/no results) */}
        {!analysisResult && !isAnalyzing && (
          <div className="mt-8 space-y-8 animate-fade-in-up">
            <div className="text-center">
              <h3 className="text-xs uppercase tracking-widest font-mono text-muted-foreground flex items-center justify-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-primary" />
                Autonomous Client-Side Verification Suite
              </h3>
            </div>

            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              <Card className="glass-card-hover border-border/70 relative overflow-hidden group">
                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-primary to-cyan opacity-0 group-hover:opacity-100 transition-opacity" />
                <CardHeader className="pb-2">
                  <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/30 w-fit mb-2 group-hover:scale-110 transition-transform">
                    <Globe className="w-5 h-5 text-primary" />
                  </div>
                  <CardTitle className="text-base font-bold">Domain Intelligence</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground leading-relaxed">
                  Queries public ICANN RDAP registries and Cloudflare DNS-over-HTTPS for domain age,
                  registrar identity, nameservers, and cryptographic DNS records (A, AAAA, MX, TXT).
                </CardContent>
              </Card>

              <Card className="glass-card-hover border-border/70 relative overflow-hidden group">
                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-safe to-safe-glow opacity-0 group-hover:opacity-100 transition-opacity" />
                <CardHeader className="pb-2">
                  <div className="p-2.5 rounded-xl bg-safe/10 border border-safe/30 w-fit mb-2 group-hover:scale-110 transition-transform">
                    <Lock className="w-5 h-5 text-safe" />
                  </div>
                  <CardTitle className="text-base font-bold">TLS & CT Logs</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground leading-relaxed">
                  Interrogates crt.sh Certificate Transparency monitors to verify certificate authority
                  issuers, expiration thresholds, historical issuance counts, and SAN subdomains.
                </CardContent>
              </Card>

              <Card className="glass-card-hover border-border/70 relative overflow-hidden group">
                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-warning to-danger opacity-0 group-hover:opacity-100 transition-opacity" />
                <CardHeader className="pb-2">
                  <div className="p-2.5 rounded-xl bg-warning/10 border border-warning/30 w-fit mb-2 group-hover:scale-110 transition-transform">
                    <AlertTriangle className="w-5 h-5 text-warning" />
                  </div>
                  <CardTitle className="text-base font-bold">Phishing & Brand Spoofing</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground leading-relaxed">
                  Detects homoglyphs, mixed-script Unicode spoofing, Levenshtein typosquatting, credential-lure
                  keywords, and high-abuse top-level domains across 30+ monitored brands.
                </CardContent>
              </Card>

              <Card className="glass-card-hover border-border/70 relative overflow-hidden group">
                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan to-primary opacity-0 group-hover:opacity-100 transition-opacity" />
                <CardHeader className="pb-2">
                  <div className="p-2.5 rounded-xl bg-cyan/10 border border-cyan/30 w-fit mb-2 group-hover:scale-110 transition-transform">
                    <Server className="w-5 h-5 text-cyan" />
                  </div>
                  <CardTitle className="text-base font-bold">HTTP Security Heuristics</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground leading-relaxed">
                  Evaluates transport layer guarantees, plain-text downgrade exposure, mixed content
                  vulnerabilities, and HSTS policy enforcement expectations.
                </CardContent>
              </Card>

              <Card className="glass-card-hover border-border/70 sm:col-span-2 lg:col-span-2 relative overflow-hidden group">
                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-primary via-cyan to-safe opacity-0 group-hover:opacity-100 transition-opacity" />
                <CardHeader className="pb-2">
                  <div className="p-2.5 rounded-xl bg-safe/10 border border-safe/30 w-fit mb-2 group-hover:scale-110 transition-transform">
                    <CheckCircle2 className="w-5 h-5 text-safe" />
                  </div>
                  <CardTitle className="text-base font-bold">Calibrated Risk Engine & Audit Trail</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground leading-relaxed">
                  Transparent mathematical risk scoring that separates observed facts from heuristic flags,
                  explicitly tracks evidence coverage confidence, and provides actionable remediation guidance
                  for every detected vulnerability.
                </CardContent>
              </Card>
            </div>

            {/* Micro Telemetry Metrics Footer */}
            <div className="p-5 rounded-2xl bg-card/40 border border-border/50 grid grid-cols-2 md:grid-cols-4 gap-4 text-center font-mono">
              <div>
                <div className="text-2xl font-bold text-gradient-primary">30+</div>
                <div className="text-[11px] text-muted-foreground uppercase mt-0.5">Monitored Brands</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-safe">14 CIDRs</div>
                <div className="text-[11px] text-muted-foreground uppercase mt-0.5">SSRF Guard Blocked</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-cyan">0 Server Hops</div>
                <div className="text-[11px] text-muted-foreground uppercase mt-0.5">Direct Client Telemetry</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-warning">0-100</div>
                <div className="text-[11px] text-muted-foreground uppercase mt-0.5">Calibrated Risk Scale</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
