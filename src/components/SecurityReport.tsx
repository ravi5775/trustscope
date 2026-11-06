import { useState } from "react";
import {
  Shield,
  ShieldAlert,
  Globe,
  Lock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Calendar,
  Layers,
  FileText,
  Server,
  Info,
  ExternalLink,
  Lightbulb,
  Check,
  AlertCircle,
  Network,
  Eye,
  Key,
  Database,
  ArrowRight,
  Copy,
  Search,
  Filter,
  Flame,
  CheckCheck,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/components/ui/use-toast";
import type { Finding, FindingStatus, FindingKind, CertFacts, HttpFacts, DomainFacts, ModuleResult } from "@/lib/analysis/types";
import type { RiskAssessment } from "@/lib/analysis/scoring";
import { registrableDomain, publicSuffix } from "@/lib/analysis/url";

export interface AnalysisResult {
  url: string;
  hostname: string;
  assessment: RiskAssessment;
  moduleResults: {
    lexical: Finding[];
    cert: ModuleResult<CertFacts>;
    http: ModuleResult<HttpFacts>;
    domain: ModuleResult<DomainFacts>;
    threat: ModuleResult<null>;
  };
  scannedAt: string;
}

export interface SecurityReportProps {
  result: AnalysisResult;
}

export const SecurityReport = ({ result }: SecurityReportProps) => {
  const [statusFilter, setStatusFilter] = useState<"all" | FindingStatus>("all");
  const [moduleFilter, setModuleFilter] = useState<"all" | string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const { toast } = useToast();

  const { url, hostname, moduleResults } = result;

  // Flatten all findings
  const allFindings: Finding[] = [
    ...moduleResults.lexical,
    ...moduleResults.domain.findings,
    ...moduleResults.cert.findings,
    ...moduleResults.http.findings,
    ...moduleResults.threat.findings,
  ];

  const filteredFindings = allFindings.filter((f) => {
    if (statusFilter !== "all" && f.status !== statusFilter) return false;
    if (moduleFilter !== "all" && f.module !== moduleFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.evidence.toLowerCase().includes(q) ||
        f.module.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const copyFindingEvidence = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      toast({
        title: "Evidence Copied",
        description: "Copied finding evidence to clipboard.",
      });
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      toast({
        title: "Copy Failed",
        description: "Clipboard access was denied.",
        variant: "destructive",
      });
    }
  };

  const getStatusIcon = (status: FindingStatus) => {
    switch (status) {
      case "pass":
        return <CheckCircle2 className="w-5 h-5 text-safe shrink-0" />;
      case "warn":
        return <AlertTriangle className="w-5 h-5 text-warning shrink-0" />;
      case "fail":
        return <XCircle className="w-5 h-5 text-danger shrink-0" />;
      case "unknown":
      default:
        return <HelpCircle className="w-5 h-5 text-muted-foreground shrink-0" />;
    }
  };

  const getStatusBadge = (status: FindingStatus) => {
    switch (status) {
      case "pass":
        return <Badge className="status-safe text-xs uppercase px-2 py-0.5 font-bold font-mono">Pass</Badge>;
      case "warn":
        return <Badge className="status-warning text-xs uppercase px-2 py-0.5 font-bold font-mono">Warning</Badge>;
      case "fail":
        return <Badge className="status-danger text-xs uppercase px-2 py-0.5 font-bold font-mono">Fail</Badge>;
      case "unknown":
      default:
        return (
          <Badge variant="outline" className="border-border text-muted-foreground text-xs uppercase px-2 py-0.5 font-mono">
            Unknown
          </Badge>
        );
    }
  };

  const getKindBadge = (kind: FindingKind) => {
    switch (kind) {
      case "confirmed":
        return (
          <Badge variant="outline" className="text-[10px] uppercase font-mono border-primary/40 text-primary bg-primary/10">
            Confirmed
          </Badge>
        );
      case "observation":
        return (
          <Badge variant="outline" className="text-[10px] uppercase font-mono border-border text-muted-foreground bg-muted/40">
            Observation
          </Badge>
        );
      case "heuristic":
        return (
          <Badge variant="outline" className="text-[10px] uppercase font-mono border-warning/40 text-warning bg-warning/10">
            Heuristic
          </Badge>
        );
    }
  };

  // URL parsing details for Phishing tab
  let parsedUrl: URL | null = null;
  try {
    parsedUrl = new URL(url);
  } catch {
    // Ignore fallback
  }

  const regDomain = registrableDomain(hostname);
  const tldSuffix = publicSuffix(hostname);
  const brandFinding = moduleResults.lexical.find((f) => f.id === "lex-brand");
  const isBrandImpersonation = brandFinding && brandFinding.status === "fail";

  // Certificate helpers
  const certFacts = moduleResults.cert.facts;
  const daysUntilExpiry = certFacts?.latestNotAfter
    ? Math.ceil((new Date(certFacts.latestNotAfter).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
    : null;

  // Domain facts
  const domainFacts = moduleResults.domain.facts;

  return (
    <div className="space-y-6 animate-fade-in-up">
      <Tabs defaultValue="findings" className="space-y-6">
        {/* Futuristic Glass Tabs Bar */}
        <div className="overflow-x-auto pb-1 scrollbar-none">
          <TabsList className="bg-card/70 p-1.5 border border-border/70 rounded-xl h-auto gap-1 backdrop-blur-md shadow-cyber">
            <TabsTrigger
              value="findings"
              className="flex items-center gap-2 py-2.5 px-3.5 text-xs sm:text-sm rounded-lg data-[state=active]:bg-primary/20 data-[state=active]:text-primary data-[state=active]:border data-[state=active]:border-primary/40 transition-all"
            >
              <ShieldAlert className="w-4 h-4 text-primary" />
              <span>Findings</span>
              <span className="ml-1 text-[11px] font-mono px-1.5 py-0.2 rounded-full bg-primary/20 text-primary">
                {allFindings.length}
              </span>
            </TabsTrigger>

            <TabsTrigger
              value="domain"
              className="flex items-center gap-2 py-2.5 px-3.5 text-xs sm:text-sm rounded-lg data-[state=active]:bg-cyan/20 data-[state=active]:text-cyan data-[state=active]:border data-[state=active]:border-cyan/40 transition-all"
            >
              <Globe className="w-4 h-4 text-cyan" />
              <span>Domain & DNS</span>
            </TabsTrigger>

            <TabsTrigger
              value="certificates"
              className="flex items-center gap-2 py-2.5 px-3.5 text-xs sm:text-sm rounded-lg data-[state=active]:bg-safe/20 data-[state=active]:text-safe data-[state=active]:border data-[state=active]:border-safe/40 transition-all"
            >
              <Lock className="w-4 h-4 text-safe" />
              <span>Certificates</span>
            </TabsTrigger>

            <TabsTrigger
              value="phishing"
              className="flex items-center gap-2 py-2.5 px-3.5 text-xs sm:text-sm rounded-lg data-[state=active]:bg-warning/20 data-[state=active]:text-warning data-[state=active]:border data-[state=active]:border-warning/40 transition-all"
            >
              <Eye className="w-4 h-4 text-warning" />
              <span>Phishing & URL</span>
            </TabsTrigger>

            <TabsTrigger
              value="http"
              className="flex items-center gap-2 py-2.5 px-3.5 text-xs sm:text-sm rounded-lg data-[state=active]:bg-primary/20 data-[state=active]:text-primary data-[state=active]:border data-[state=active]:border-primary/40 transition-all"
            >
              <Server className="w-4 h-4 text-primary" />
              <span>Transport & HTTP</span>
            </TabsTrigger>

            <TabsTrigger
              value="limitations"
              className="flex items-center gap-2 py-2.5 px-3.5 text-xs sm:text-sm rounded-lg data-[state=active]:bg-muted/80 data-[state=active]:text-foreground data-[state=active]:border data-[state=active]:border-border transition-all"
            >
              <Info className="w-4 h-4" />
              <span>Disclosures</span>
            </TabsTrigger>
          </TabsList>
        </div>

        {/* TAB 1: ALL FINDINGS */}
        <TabsContent value="findings" className="space-y-4">
          <Card className="glass-card shadow-cyber">
            <CardHeader className="pb-4">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <CardTitle className="flex items-center gap-2 text-xl font-bold">
                    <Shield className="w-5 h-5 text-primary" />
                    Security Verification Findings
                  </CardTitle>
                  <CardDescription className="text-xs sm:text-sm">
                    Detailed ruleset output across DNS, TLS, transport, brand intelligence, and lexical signals
                  </CardDescription>
                </div>

                {/* Filter and Search controls */}
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                  {/* Search input */}
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      placeholder="Filter findings..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="glass-input pl-8 h-8 text-xs font-mono w-full sm:w-44"
                    />
                  </div>

                  {/* Status filter pills */}
                  <div className="flex items-center gap-1 bg-muted/40 p-1 rounded-lg border border-border text-xs">
                    {(["all", "fail", "warn", "pass", "unknown"] as const).map((s) => (
                      <button
                        key={s}
                        onClick={() => setStatusFilter(s)}
                        className={`px-2.5 py-1 rounded capitalize font-medium text-[11px] transition-colors ${
                          statusFilter === s
                            ? "bg-primary text-primary-foreground font-bold shadow-sm"
                            : "text-muted-foreground hover:text-foreground"
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>

                  {/* Module filter pills */}
                  <div className="flex items-center gap-1 bg-muted/40 p-1 rounded-lg border border-border text-xs overflow-x-auto">
                    {(["all", "lexical", "domain", "certificates", "http", "threat"] as const).map((m) => (
                      <button
                        key={m}
                        onClick={() => setModuleFilter(m)}
                        className={`px-2 py-1 rounded capitalize font-medium text-[11px] transition-colors ${
                          moduleFilter === m
                            ? "bg-secondary text-foreground font-bold shadow-sm"
                            : "text-muted-foreground hover:text-foreground"
                        }`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </CardHeader>

            <CardContent className="space-y-3">
              {filteredFindings.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground bg-muted/10 rounded-xl border border-dashed border-border/60">
                  <HelpCircle className="w-10 h-10 mx-auto mb-2 opacity-40 text-primary" />
                  <p className="text-sm">No findings match the current filter selection.</p>
                  {(statusFilter !== "all" || moduleFilter !== "all" || searchQuery) && (
                    <Button
                      variant="link"
                      size="sm"
                      onClick={() => {
                        setStatusFilter("all");
                        setModuleFilter("all");
                        setSearchQuery("");
                      }}
                      className="mt-2 text-xs text-primary"
                    >
                      Clear all filters
                    </Button>
                  )}
                </div>
              ) : (
                filteredFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className={`p-4 rounded-xl bg-card/60 border transition-all hover-lift-sm space-y-2.5 ${
                      finding.status === "fail"
                        ? "border-l-4 border-l-danger border-border/80"
                        : finding.status === "warn"
                        ? "border-l-4 border-l-warning border-border/80"
                        : finding.status === "pass"
                        ? "border-l-4 border-l-safe border-border/80"
                        : "border-l-4 border-l-muted-foreground border-border/80"
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                      <div className="flex items-start gap-3">
                        {getStatusIcon(finding.status)}
                        <div>
                          <div className="flex items-center flex-wrap gap-2">
                            <span className="font-bold text-foreground text-sm tracking-tight">{finding.title}</span>
                            {getKindBadge(finding.kind)}
                            <Badge variant="outline" className="text-[10px] uppercase font-mono text-muted-foreground bg-muted/20">
                              {finding.module}
                            </Badge>
                          </div>
                          <p className="text-[11px] font-mono text-muted-foreground mt-0.5">
                            Source: {finding.source}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2.5 self-start sm:self-auto shrink-0">
                        <span className="text-[11px] font-mono text-muted-foreground px-2 py-0.5 rounded bg-muted/40 border border-border/40">
                          Weight: {finding.weight}
                        </span>
                        {getStatusBadge(finding.status)}
                      </div>
                    </div>

                    {/* Evidence Box with Micro-Copy */}
                    <div className="relative group/box">
                      <div className="text-xs text-foreground/90 bg-muted/40 p-3 rounded-lg border border-border/60 font-mono break-words leading-relaxed pr-9">
                        {finding.evidence}
                      </div>
                      <button
                        onClick={() => copyFindingEvidence(finding.id, finding.evidence)}
                        className="absolute right-2.5 top-2.5 opacity-60 hover:opacity-100 p-1 rounded bg-card border border-border text-muted-foreground hover:text-foreground transition-all"
                        title="Copy evidence text"
                      >
                        {copiedId === finding.id ? (
                          <CheckCheck className="w-3.5 h-3.5 text-safe" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>

                    {/* Actionable Remediation Guidance */}
                    {finding.remediation && (
                      <div className="flex items-start gap-2.5 p-3 rounded-lg bg-warning/10 border border-warning/30 text-xs text-warning-foreground">
                        <Lightbulb className="w-4 h-4 text-warning shrink-0 mt-0.5" />
                        <div>
                          <span className="font-bold text-warning uppercase font-mono tracking-wide text-[10px] block mb-0.5">
                            Actionable Remediation
                          </span>
                          <span className="leading-relaxed">{finding.remediation}</span>
                        </div>
                      </div>
                    )}
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 2: DOMAIN & DNS */}
        <TabsContent value="domain" className="space-y-6">
          <div className="grid md:grid-cols-2 gap-6">
            {/* Domain Registration Intel */}
            <Card className="glass-card shadow-cyber">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Database className="w-5 h-5 text-cyan" />
                  Domain Registration (ICANN RDAP)
                </CardTitle>
                <CardDescription>
                  Registration and authority data queried via public ICANN RDAP registries
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex justify-between items-center py-2 border-b border-border/40 text-sm">
                    <span className="text-muted-foreground">Registrable Domain</span>
                    <span className="font-mono font-bold text-foreground">{domainFacts?.registrableDomain || regDomain}</span>
                  </div>

                  <div className="flex justify-between items-center py-2 border-b border-border/40 text-sm">
                    <span className="text-muted-foreground">Registrar</span>
                    <span className="font-medium text-right max-w-[240px] truncate text-foreground">
                      {domainFacts?.registrar || "Not disclosed or unavailable"}
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-2 border-b border-border/40 text-sm">
                    <span className="text-muted-foreground">Creation Date</span>
                    <span className="font-mono">
                      {domainFacts?.created
                        ? new Date(domainFacts.created).toLocaleDateString("en-US", {
                            year: "numeric",
                            month: "short",
                            day: "numeric",
                          })
                        : "Unknown"}
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-2 border-b border-border/40 text-sm">
                    <span className="text-muted-foreground">Expiration Date</span>
                    <span className="font-mono">
                      {domainFacts?.expires
                        ? new Date(domainFacts.expires).toLocaleDateString("en-US", {
                            year: "numeric",
                            month: "short",
                            day: "numeric",
                          })
                        : "Unknown"}
                    </span>
                  </div>

                  {/* Domain Age with visual status bar */}
                  <div className="py-2 border-b border-border/40 text-sm space-y-1.5">
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">Domain Age</span>
                      <span className="font-bold font-mono">
                        {domainFacts?.ageDays !== null && domainFacts?.ageDays !== undefined
                          ? `${domainFacts.ageDays} days (~${(domainFacts.ageDays / 365.25).toFixed(1)} yrs)`
                          : "Unknown"}
                      </span>
                    </div>

                    {domainFacts?.ageDays !== null && domainFacts?.ageDays !== undefined && (
                      <div className="space-y-1">
                        <div className="h-1.5 w-full bg-muted rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${
                              domainFacts.ageDays >= 730
                                ? "bg-safe"
                                : domainFacts.ageDays >= 180
                                ? "bg-warning"
                                : "bg-danger"
                            }`}
                            style={{ width: `${Math.min(100, (domainFacts.ageDays / 1095) * 100)}%` }}
                          />
                        </div>
                        <div className="flex justify-between text-[10px] font-mono text-muted-foreground">
                          <span>NRD (&lt;6mo)</span>
                          <span>Established (&gt;2yr)</span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Status Flags */}
                <div>
                  <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-2 font-mono">
                    Registry Status Flags
                  </span>
                  {domainFacts?.status && domainFacts.status.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {domainFacts.status.map((st, i) => (
                        <Badge
                          key={i}
                          variant="outline"
                          className={`text-[11px] font-mono ${
                            st.toLowerCase().includes("hold")
                              ? "border-danger text-danger bg-danger/10"
                              : "border-border text-muted-foreground bg-muted/40"
                          }`}
                        >
                          {st}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground italic">No status flags reported by registry</p>
                  )}
                </div>

                {moduleResults.domain.error && (
                  <div className="p-3 rounded-lg bg-warning/10 border border-warning/20 text-xs text-warning leading-relaxed font-mono">
                    Notice: RDAP query limitation ({moduleResults.domain.error})
                  </div>
                )}
              </CardContent>
            </Card>

            {/* DNS Records */}
            <Card className="glass-card shadow-cyber">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Network className="w-5 h-5 text-primary" />
                  DNS Infrastructure (Cloudflare DoH)
                </CardTitle>
                <CardDescription>
                  Cryptographically resolved records queried over encrypted DNS-over-HTTPS
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Authoritative Nameservers */}
                <div>
                  <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-2 font-mono">
                    Authoritative Nameservers
                  </span>
                  {domainFacts?.nameservers && domainFacts.nameservers.length > 0 ? (
                    <div className="space-y-1">
                      {domainFacts.nameservers.map((ns, idx) => (
                        <div key={idx} className="font-mono text-xs bg-muted/40 p-2 rounded-lg border border-border/50 text-foreground flex items-center justify-between">
                          <span>{ns}</span>
                          <span className="text-[10px] text-muted-foreground uppercase">NS</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground italic">No nameservers resolved</p>
                  )}
                </div>

                {/* IPv4 (A Records) */}
                <div>
                  <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-2 font-mono">
                    IPv4 Addresses (A Records)
                  </span>
                  {domainFacts?.a && domainFacts.a.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {domainFacts.a.map((ip, i) => (
                        <Badge key={i} variant="outline" className="font-mono text-xs border-primary/40 text-primary bg-primary/10 px-2.5 py-1">
                          {ip}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground italic">No IPv4 address records found</p>
                  )}
                </div>

                {/* IPv6 (AAAA Records) */}
                {domainFacts?.aaaa && domainFacts.aaaa.length > 0 && (
                  <div>
                    <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-2 font-mono">
                      IPv6 Addresses (AAAA Records)
                    </span>
                    <div className="space-y-1">
                      {domainFacts.aaaa.map((ip6, i) => (
                        <div key={i} className="font-mono text-xs bg-muted/40 p-1.5 rounded border border-border/40 break-all text-foreground">
                          {ip6}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* MX Records */}
                {domainFacts?.mx && domainFacts.mx.length > 0 && (
                  <div>
                    <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-2 font-mono">
                      Mail Servers (MX Records)
                    </span>
                    <div className="space-y-1">
                      {domainFacts.mx.map((mx, i) => (
                        <div key={i} className="font-mono text-xs bg-muted/40 p-1.5 rounded border border-border/40 text-foreground">
                          {mx}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* TXT Records */}
                {domainFacts?.txt && domainFacts.txt.length > 0 && (
                  <div>
                    <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-2 font-mono">
                      TXT / SPF Records ({domainFacts.txt.length})
                    </span>
                    <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                      {domainFacts.txt.map((txt, i) => (
                        <div key={i} className="font-mono text-[11px] bg-muted/30 p-2 rounded border border-border/40 break-all text-muted-foreground leading-normal">
                          {txt}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* TAB 3: CERTIFICATES */}
        <TabsContent value="certificates" className="space-y-6">
          <Card className="glass-card shadow-cyber">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Lock className="w-5 h-5 text-safe" />
                Certificate Transparency Telemetry (crt.sh)
              </CardTitle>
              <CardDescription>
                Public certificate authority audit records extracted from Certificate Transparency (CT) monitors
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-card/60 border border-border/70">
                  <span className="text-xs text-muted-foreground font-mono uppercase block mb-1">Observed Issuer</span>
                  <p className="font-bold text-sm text-foreground break-words">
                    {certFacts?.latestIssuer || "No record in CT logs"}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-card/60 border border-border/70">
                  <span className="text-xs text-muted-foreground font-mono uppercase block mb-1">Valid Until (Not After)</span>
                  <p className="font-mono text-sm font-bold text-foreground">
                    {certFacts?.latestNotAfter
                      ? new Date(certFacts.latestNotAfter).toLocaleDateString("en-US", {
                          year: "numeric",
                          month: "short",
                          day: "numeric",
                        })
                      : "—"}
                  </p>
                  {daysUntilExpiry !== null && (
                    <span
                      className={`text-[11px] font-mono font-bold block mt-1 ${
                        daysUntilExpiry > 30 ? "text-safe" : daysUntilExpiry > 0 ? "text-warning" : "text-danger"
                      }`}
                    >
                      {daysUntilExpiry > 0 ? `${daysUntilExpiry} days remaining` : `Expired ${Math.abs(daysUntilExpiry)} days ago`}
                    </span>
                  )}
                </div>

                <div className="p-4 rounded-xl bg-card/60 border border-border/70">
                  <span className="text-xs text-muted-foreground font-mono uppercase block mb-1">Issue Date (Not Before)</span>
                  <p className="font-mono text-sm text-foreground">
                    {certFacts?.latestNotBefore
                      ? new Date(certFacts.latestNotBefore).toLocaleDateString("en-US", {
                          year: "numeric",
                          month: "short",
                          day: "numeric",
                        })
                      : "—"}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-card/60 border border-border/70">
                  <span className="text-xs text-muted-foreground font-mono uppercase block mb-1">Total CT Records Found</span>
                  <p className="font-mono text-3xl font-black text-primary">
                    {certFacts?.certificateCount ?? 0}
                  </p>
                  <span className="text-[11px] text-muted-foreground">Historical certificates</span>
                </div>
              </div>

              {/* Subdomains observed */}
              <div>
                <div className="flex items-center justify-between mb-2.5">
                  <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider font-mono">
                    Observed Subdomains in Certificate SANs ({certFacts?.subdomains.length || 0})
                  </span>
                  <span className="text-xs text-muted-foreground font-mono">Max 50 listed</span>
                </div>

                {certFacts?.subdomains && certFacts.subdomains.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5 max-h-52 overflow-y-auto p-3 bg-muted/20 rounded-xl border border-border/60">
                    {certFacts.subdomains.map((sub, i) => (
                      <Badge
                        key={i}
                        variant="secondary"
                        className="font-mono text-xs bg-muted/70 text-foreground border border-border/60 hover:border-primary/50 transition-colors"
                      >
                        {sub}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-xl bg-muted/20 border border-border text-center text-xs text-muted-foreground">
                    No SAN subdomains extracted from Certificate Transparency query.
                  </div>
                )}
              </div>

              {moduleResults.cert.error && (
                <div className="p-3.5 rounded-xl bg-warning/10 border border-warning/25 text-xs text-warning-foreground font-mono">
                  crt.sh warning: {moduleResults.cert.error}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 4: PHISHING ANALYSIS */}
        <TabsContent value="phishing" className="space-y-6">
          {/* Brand Impersonation Alert Banner */}
          {isBrandImpersonation ? (
            <div className="p-5 rounded-2xl bg-danger/15 border-2 border-danger/50 flex items-start gap-4 animate-risk-pulse shadow-danger">
              <AlertTriangle className="w-8 h-8 text-danger shrink-0 mt-0.5" />
              <div>
                <h4 className="text-base font-black text-danger tracking-tight">
                  High Confidence Brand Impersonation Warning
                </h4>
                <p className="text-sm text-foreground/90 mt-1 leading-relaxed">{brandFinding?.evidence}</p>
                {brandFinding?.remediation && (
                  <p className="text-xs text-muted-foreground mt-2 font-mono bg-card/60 p-2 rounded border border-danger/30">
                    Guidance: {brandFinding.remediation}
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-2xl bg-safe/10 border border-safe/30 flex items-center gap-3">
              <CheckCircle2 className="w-6 h-6 text-safe shrink-0" />
              <div>
                <h4 className="text-sm font-bold text-safe">No Brand Impersonation Detected</h4>
                <p className="text-xs text-muted-foreground">
                  The target domain does not exhibit known typosquatting, confusable homoglyphs, or lookalike patterns against our monitored brand list.
                </p>
              </div>
            </div>
          )}

          {/* Interactive URL Component Breakdown */}
          <Card className="glass-card shadow-cyber">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <FileText className="w-5 h-5 text-primary" />
                URL Anatomy Breakdown
              </CardTitle>
              <CardDescription>
                Structural decomposition used for lexical, homograph, and obfuscation detection
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-xl bg-card/60 border border-border/60">
                  <span className="text-muted-foreground block text-[10px] uppercase font-sans font-bold">Protocol</span>
                  <span className="text-primary font-bold text-sm">{parsedUrl?.protocol || "—"}</span>
                </div>
                <div className="p-3 rounded-xl bg-card/60 border border-border/60">
                  <span className="text-muted-foreground block text-[10px] uppercase font-sans font-bold">Hostname</span>
                  <span className="text-foreground font-bold text-sm">{hostname}</span>
                </div>
                <div className="p-3 rounded-xl bg-card/60 border border-border/60">
                  <span className="text-muted-foreground block text-[10px] uppercase font-sans font-bold">Registrable Domain (eTLD+1)</span>
                  <span className="text-cyan font-bold text-sm">{regDomain}</span>
                </div>
                <div className="p-3 rounded-xl bg-card/60 border border-border/60">
                  <span className="text-muted-foreground block text-[10px] uppercase font-sans font-bold">Public Suffix (TLD)</span>
                  <span className="text-safe font-bold text-sm">.{tldSuffix}</span>
                </div>
              </div>

              {/* Query parameters table */}
              <div>
                <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-2 font-mono">
                  Query Parameters
                </span>
                {parsedUrl && [...parsedUrl.searchParams.entries()].length > 0 ? (
                  <div className="border border-border/60 rounded-xl overflow-hidden">
                    <table className="w-full text-xs font-mono">
                      <thead className="bg-muted/60 border-b border-border/60 text-muted-foreground">
                        <tr>
                          <th className="text-left p-2.5 font-bold">Key</th>
                          <th className="text-left p-2.5 font-bold">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {[...parsedUrl.searchParams.entries()].map(([k, v], idx) => (
                          <tr key={idx} className="border-b border-border/30 last:border-0 hover:bg-muted/20">
                            <td className="p-2.5 font-bold text-primary">{k}</td>
                            <td className="p-2.5 text-foreground/90 break-all">{v}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground italic">No URL query parameters present.</p>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Lexical Findings List */}
          <Card className="glass-card shadow-cyber">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                Lexical & Brand Rule Results ({moduleResults.lexical.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {moduleResults.lexical.map((finding) => (
                <div
                  key={finding.id}
                  className="p-3.5 rounded-xl bg-card/60 border border-border/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover-lift-sm transition-cyber"
                >
                  <div className="flex items-start gap-3">
                    {getStatusIcon(finding.status)}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold">{finding.title}</span>
                        {getKindBadge(finding.kind)}
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5 font-mono">{finding.evidence}</p>
                    </div>
                  </div>
                  <div className="shrink-0">{getStatusBadge(finding.status)}</div>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 5: HTTP SECURITY */}
        <TabsContent value="http" className="space-y-6">
          <Card className="glass-card shadow-cyber">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Server className="w-5 h-5 text-primary" />
                Transport & HTTP Security Analysis
              </CardTitle>
              <CardDescription>
                Client-side transport evaluation and web security posture
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Findings */}
              <div className="space-y-3">
                {moduleResults.http.findings.map((finding) => (
                  <div
                    key={finding.id}
                    className="p-4 rounded-xl bg-card/60 border border-border/60 flex flex-col sm:flex-row sm:items-start justify-between gap-3 hover-lift-sm transition-cyber"
                  >
                    <div className="flex items-start gap-3">
                      {getStatusIcon(finding.status)}
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-bold">{finding.title}</span>
                          {getKindBadge(finding.kind)}
                        </div>
                        <p className="text-xs text-foreground/90 font-mono bg-muted/40 p-2.5 rounded-lg border border-border/50">
                          {finding.evidence}
                        </p>
                        {finding.remediation && (
                          <p className="text-xs text-warning mt-1 font-mono">
                            Recommendation: {finding.remediation}
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="shrink-0">{getStatusBadge(finding.status)}</div>
                  </div>
                ))}
              </div>

              <Separator />

              {/* Browser limitations & Backend enhancements notice */}
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-primary/10 border border-primary/30">
                  <h4 className="text-sm font-bold text-primary flex items-center gap-2 mb-1">
                    <Info className="w-4 h-4" />
                    Browser Execution Sandbox Architecture
                  </h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    TrustScope executes in zero-knowledge browser runtime for privacy. Web browser security boundaries
                    (Same-Origin Policy / CORS) prohibit direct inspection of arbitrary third-party HTTP response headers
                    such as <code>Strict-Transport-Security</code>, <code>Content-Security-Policy</code>, and redirect chains.
                  </p>
                </div>

                <div>
                  <h4 className="text-sm font-bold mb-3 font-mono uppercase tracking-wider text-muted-foreground">
                    Enterprise Backend Proxy Enhancements
                  </h4>
                  <div className="grid sm:grid-cols-2 gap-3 text-xs">
                    <div className="p-3.5 rounded-xl bg-card/60 border border-border/60 flex gap-2.5">
                      <ArrowRight className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-foreground block font-bold mb-0.5">Full Header Inspection</strong>
                        <span className="text-muted-foreground">
                          Evaluates HSTS preloading, CSP directives, CORS origins, and Permissions-Policy.
                        </span>
                      </div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-card/60 border border-border/60 flex gap-2.5">
                      <ArrowRight className="w-4 h-4 text-cyan shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-foreground block font-bold mb-0.5">Redirect Traversal</strong>
                        <span className="text-muted-foreground">
                          Follows server-side HTTP 301/302 redirects and meta-refreshes to detect destination swapping.
                        </span>
                      </div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-card/60 border border-border/60 flex gap-2.5">
                      <ArrowRight className="w-4 h-4 text-safe shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-foreground block font-bold mb-0.5">TLS Handshake Audit</strong>
                        <span className="text-muted-foreground">
                          Inspects cipher suites, TLS 1.3 negotiation, ALPN protocols, and OCSP stapling status.
                        </span>
                      </div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-card/60 border border-border/60 flex gap-2.5">
                      <ArrowRight className="w-4 h-4 text-warning shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-foreground block font-bold mb-0.5">DOM & Form Scanner</strong>
                        <span className="text-muted-foreground">
                          Detects credential harvesting inputs, injected cryptominers, and hidden malicious iframes.
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 6: LIMITATIONS & METHODOLOGY */}
        <TabsContent value="limitations" className="space-y-6">
          <Card className="glass-card shadow-cyber">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Info className="w-5 h-5 text-primary" />
                Limitations & Operational Disclaimers
              </CardTitle>
              <CardDescription>
                Methodological disclosures and boundaries of client-side security assessment
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-card/60 border border-border/60 space-y-1.5">
                  <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                    <Server className="w-4 h-4 text-warning" />
                    External Provider Reliability
                  </h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Telemetry is sourced in real-time from public third-party services including crt.sh (Certificate
                    Transparency) and Cloudflare DNS-over-HTTPS. External APIs may experience temporary latency, rate-limiting,
                    or incomplete data propagation.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-card/60 border border-border/60 space-y-1.5">
                  <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                    <Globe className="w-4 h-4 text-primary" />
                    TLD & RDAP Registry Availability
                  </h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Domain registration records depend on ICANN RDAP endpoints. Certain country-code top-level domains
                    (ccTLDs) or specialized registries do not operate public RDAP servers or redact registration
                    timestamps for privacy reasons.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-card/60 border border-border/60 space-y-1.5">
                  <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                    <Eye className="w-4 h-4 text-warning" />
                    Heuristic Brand Matching
                  </h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Phishing heuristics evaluate string distance, confusable Unicode characters, and monitored brand tokens.
                    Heuristic analysis can produce false positives on legitimate subdomains or false negatives on previously
                    unseen spoofing techniques.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-card/60 border border-border/60 space-y-1.5">
                  <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-danger" />
                    No Absolute Safety Certification
                  </h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    A low risk score or clean report is <strong>not a guarantee or certification of safety</strong>. Sophisticated
                    attackers can compromise established domains, obtain valid TLS certificates, and deploy short-lived
                    phishing campaigns that bypass initial detection.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-card/60 border border-border/60 space-y-1.5">
                  <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                    <Layers className="w-4 h-4 text-primary" />
                    Evaluated Rule Scope
                  </h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Assessments represent only the specific rules executed during the scan. Unknown findings explicitly
                    indicate missing or unavailable telemetry, which proportionally reduces evidence coverage rather than
                    assuming safety.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-card/60 border border-border/60 space-y-1.5">
                  <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                    <Key className="w-4 h-4 text-warning" />
                    Threat Intelligence Feeds
                  </h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Commercial threat reputation services (such as Google Safe Browsing, VirusTotal, and URLhaus feeds)
                    require API keys and backend proxies to operate securely. In this browser-only deployment, threat checks
                    are marked as unconfigured.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};
