/** Deterministic URL lexical, homograph, typosquatting and brand-impersonation rules. */
import { BRANDS } from "./brands";
import { toUnicodeHost } from "./punycode";
import { isIpLiteral, registrableDomain } from "./url";
import type { Finding, FindingStatus } from "./types";

const SOURCE = "TrustScope lexical rules";
const SUSPICIOUS_TLDS = new Set(["tk", "ml", "ga", "cf", "gq", "zip", "mov", "top", "xyz", "icu", "click", "buzz", "rest", "cam", "monster"]);
const CREDENTIAL_WORDS = ["login", "signin", "sign-in", "verify", "verification", "account", "secure", "update", "wallet", "banking", "password", "unlock", "suspended", "confirm", "billing", "webscr"];
const REDIRECT_PARAMS = ["url", "redirect", "redirect_uri", "redirect_url", "next", "return", "returnurl", "return_to", "goto", "dest", "destination", "continue", "target"];
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc"]);

const CONFUSABLES: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d", "ѕ": "s",
  "һ": "h", "ӏ": "l", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
  "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s",
};

export function skeleton(s: string): string {
  let out = "";
  for (const ch of s.toLowerCase().normalize("NFKC")) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d").replace(/-/g, "");
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0]!;
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j]!;
      prev[j] = Math.min(prev[j]! + 1, prev[j - 1]! + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length]!;
}

export function detectScripts(s: string): string[] {
  const scripts: [string, RegExp][] = [
    ["Latin", /\p{Script=Latin}/u], ["Cyrillic", /\p{Script=Cyrillic}/u], ["Greek", /\p{Script=Greek}/u],
    ["Armenian", /\p{Script=Armenian}/u], ["Han", /\p{Script=Han}/u], ["Arabic", /\p{Script=Arabic}/u],
    ["Devanagari", /\p{Script=Devanagari}/u], ["Hebrew", /\p{Script=Hebrew}/u],
  ];
  return scripts.filter(([, re]) => re.test(s)).map(([n]) => n);
}

export interface BrandMatch {
  brand: string;
  reason: "contains-brand" | "typosquat" | "homograph";
  detail: string;
}

/** Returns a brand-impersonation match for a hostname whose registrable domain is not official. */
export function findBrandImpersonation(hostname: string): BrandMatch | null {
  const reg = registrableDomain(hostname);
  const unicodeHost = toUnicodeHost(hostname);
  const unicodeReg = toUnicodeHost(reg);
  const regLabel = unicodeReg.split(".")[0] ?? "";
  const regSkeleton = skeleton(regLabel);
  for (const b of BRANDS) {
    if (b.official.some((d) => reg === d || hostname.endsWith(`.${d}`) || hostname === d)) continue;
    if (regLabel === b.token) {
      // Same brand label on a different TLD (e.g. paypal.xyz)
      return { brand: b.name, reason: "contains-brand", detail: `"${reg}" uses the ${b.name} name on a non-official domain` };
    }
    if (regSkeleton === b.token && regLabel !== b.token) {
      const nonAscii = /[^\x00-\x7f]/.test(regLabel);
      return {
        brand: b.name,
        reason: nonAscii ? "homograph" : "typosquat",
        detail: `"${unicodeReg}" visually imitates "${b.token}"`,
      };
    }
    const dist = levenshtein(regLabel, b.token);
    if (b.token.length >= 5 && dist > 0 && dist <= (b.token.length >= 8 ? 2 : 1)) {
      return { brand: b.name, reason: "typosquat", detail: `"${regLabel}" is ${dist} edit(s) away from "${b.token}"` };
    }
    const hostSkeleton = skeleton(unicodeHost.replace(/\./g, "-"));
    if (unicodeHost.toLowerCase().includes(b.token) || hostSkeleton.includes(b.token)) {
      return { brand: b.name, reason: "contains-brand", detail: `hostname contains "${b.token}" but is not on an official ${b.name} domain` };
    }
  }
  return null;
}

function f(id: string, title: string, status: FindingStatus, weight: number, evidence: string, remediation?: string): Finding {
  return { id, module: "lexical", title, status, weight, evidence, source: SOURCE, kind: "heuristic", observedAt: new Date().toISOString(), remediation };
}

export function analyzeLexical(url: URL): Finding[] {
  const host = url.hostname.toLowerCase();
  const unicodeHost = toUnicodeHost(host);
  const reg = registrableDomain(host);
  const tld = host.split(".").pop() ?? "";
  const out: Finding[] = [];

  out.push(isIpLiteral(host)
    ? f("lex-ip", "Hostname type", "fail", 25, `The URL uses a raw IP address (${host}) instead of a domain name.`, "Legitimate services almost always use a domain name.")
    : f("lex-ip", "Hostname type", "pass", 25, "The URL uses a domain name, not a raw IP address."));

  const isIdn = host.split(".").some((l) => l.startsWith("xn--"));
  if (isIdn) {
    const scripts = detectScripts(unicodeHost.replace(/[.\-0-9]/g, ""));
    const mixed = scripts.length > 1;
    out.push(f("lex-idn", "Internationalised domain (IDN)", mixed ? "fail" : "warn", 25,
      `Displays as "${unicodeHost}" (encoded ${host}). Scripts: ${scripts.join(", ") || "unknown"}.${mixed ? " Mixed scripts are a common homograph technique." : ""}`,
      "Verify the address character by character; mixed-script names often imitate trusted sites."));
  } else {
    out.push(f("lex-idn", "Internationalised domain (IDN)", "pass", 25, "Hostname uses plain ASCII characters only."));
  }

  const brand = findBrandImpersonation(host);
  out.push(brand
    ? f("lex-brand", "Brand impersonation / lookalike", "fail", 35, `${brand.detail}.`, `Only trust ${brand.brand} on its official domains.`)
    : f("lex-brand", "Brand impersonation / lookalike", "pass", 35, "No resemblance to monitored brand domains detected."));

  out.push(SUSPICIOUS_TLDS.has(tld)
    ? f("lex-tld", "Top-level domain", "warn", 10, `".${tld}" is a TLD frequently abused for phishing and malware.`)
    : f("lex-tld", "Top-level domain", "pass", 10, `".${tld}" is not on the high-abuse TLD list.`));

  const labels = host.split(".");
  const subDepth = Math.max(0, labels.length - reg.split(".").length);
  const hyphens = (reg.match(/-/g) ?? []).length;
  const digits = (reg.replace(/\.[^.]+$/, "").match(/\d/g) ?? []).length;
  const structural: string[] = [];
  if (host.length > 50) structural.push(`long hostname (${host.length} chars)`);
  if (subDepth >= 4) structural.push(`${subDepth} subdomain levels`);
  if (hyphens >= 3) structural.push(`${hyphens} hyphens in the domain`);
  if (digits >= 4) structural.push(`${digits} digits in the domain`);
  out.push(structural.length
    ? f("lex-structure", "Hostname structure", structural.length >= 2 ? "fail" : "warn", 15, `Unusual structure: ${structural.join(", ")}.`)
    : f("lex-structure", "Hostname structure", "pass", 15, "Hostname length, depth and character mix look ordinary."));

  const fullPath = decodeURIComponent((url.pathname + url.search).toLowerCase());
  const subdomainPart = labels.slice(0, subDepth).join(".");
  const words = CREDENTIAL_WORDS.filter((w) => subdomainPart.includes(w) || reg.includes(w) || fullPath.includes(w));
  out.push(words.length >= 2
    ? f("lex-keywords", "Credential-lure keywords", "warn", 10, `URL contains credential-related words: ${words.join(", ")}.`)
    : f("lex-keywords", "Credential-lure keywords", "pass", 10, words.length ? `Only one credential word found (${words[0]}).` : "No credential-lure keywords found."));

  const raw = url.href;
  const tricks: string[] = [];
  if (raw.slice(url.protocol.length + 2).includes("@")) tricks.push("an '@' character that can disguise the real host");
  if (/\/\/.*\/\//.test(raw.replace(/^https?:\/\//, "x//"))) tricks.push("an embedded '//' in the path");
  if (/%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}/i.test(url.hostname + url.pathname)) tricks.push("heavy percent-encoding");
  const redirectParams = [...url.searchParams.entries()].filter(([k, v]) => REDIRECT_PARAMS.includes(k.toLowerCase()) && /^(https?:)?\/\//i.test(v));
  if (redirectParams.length) tricks.push(`open-redirect style parameter (${redirectParams.map(([k]) => k).join(", ")})`);
  if (url.searchParams.has("email") || url.searchParams.has("user")) tricks.push("pre-filled email/user parameter");
  out.push(tricks.length
    ? f("lex-tricks", "URL obfuscation & parameters", "warn", 15, `Found ${tricks.join("; ")}.`)
    : f("lex-tricks", "URL obfuscation & parameters", "pass", 15, "No obfuscation tricks or suspicious redirect parameters."));

  if (SHORTENERS.has(reg)) out.push(f("lex-shortener", "URL shortener", "warn", 10, `${reg} is a link shortener; the final destination is hidden until followed.`));

  return out;
}
