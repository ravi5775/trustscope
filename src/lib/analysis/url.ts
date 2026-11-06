/** Input validation, normalisation and private-network blocking (SSRF guard). */

export type NormalizeResult =
  | { ok: true; url: URL; hostname: string }
  | { ok: false; error: string };

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".intranet", ".lan", ".home.arpa", ".corp"];

export function normalizeTarget(raw: string): NormalizeResult {
  const input = raw.trim();
  if (!input) return { ok: false, error: "Enter a website address." };
  if (input.length > 2048) return { ok: false, error: "Address is too long (max 2048 characters)." };
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return { ok: false, error: "That doesn't look like a valid web address." };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:")
    return { ok: false, error: "Only http and https addresses can be analysed." };
  if (url.username || url.password)
    return { ok: false, error: "Addresses with embedded credentials are not accepted." };
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname) return { ok: false, error: "The address has no hostname." };
  if (url.port && !["80", "443", "8080", "8443"].includes(url.port))
    return { ok: false, error: "Only standard web ports (80, 443, 8080, 8443) are allowed." };
  if (isBlockedHostname(hostname))
    return { ok: false, error: "Private, local and reserved network addresses cannot be analysed." };
  if (!isIpLiteral(hostname) && !hostname.includes("."))
    return { ok: false, error: "Enter a full domain name such as example.com." };
  url.hash = "";
  return { ok: true, url, hostname };
}

export function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[") || host.includes(":");
}

export function isBlockedHostname(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || BLOCKED_SUFFIXES.some((s) => h.endsWith(s))) return true;
  if (isIpLiteral(h)) return isPrivateIp(h.replace(/^\[|\]$/g, ""));
  return false;
}

function ipv4ToInt(ip: string): number | null {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0]! << 24) >>> 0) + (p[1]! << 16) + (p[2]! << 8) + p[3]!;
}

const V4_BLOCKS: [string, number][] = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

/** True for loopback, private, link-local, CGNAT, documentation, multicast and reserved ranges. */
export function isPrivateIp(ip: string): boolean {
  const v4 = ipv4ToInt(ip);
  if (v4 !== null) {
    return V4_BLOCKS.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return ((v4 & mask) >>> 0) === ((ipv4ToInt(base)! & mask) >>> 0);
    });
  }
  const v6 = ip.toLowerCase();
  if (!v6.includes(":")) return true; // unparseable → treat as unsafe
  if (v6 === "::" || v6 === "::1") return true;
  const mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIp(mapped[1]!);
  if (/^::ffff:/.test(v6)) return true;
  if (/^f[cd]/.test(v6)) return true; // fc00::/7 unique local
  if (/^fe[89ab]/.test(v6)) return true; // fe80::/10 link-local
  if (/^ff/.test(v6)) return true; // multicast
  if (/^2001:db8/.test(v6) || /^64:ff9b/.test(v6) || /^100:/.test(v6)) return true;
  return false;
}

const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in", "org.in",
  "gov.in", "ac.in", "co.jp", "ne.jp", "com.br", "com.cn", "com.mx", "co.nz", "co.za", "com.sg",
  "com.tr", "com.hk", "co.kr", "com.ar", "com.pk", "com.ng", "co.id", "com.my", "github.io",
  "vercel.app", "netlify.app", "pages.dev", "workers.dev", "herokuapp.com", "web.app", "firebaseapp.com",
  "blogspot.com", "fly.dev", "azurewebsites.net", "appspot.com",
]);

/** Approximate registrable domain (eTLD+1) using a curated suffix list. */
export function registrableDomain(host: string): string {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (isIpLiteral(h)) return h;
  const parts = h.split(".");
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

export function publicSuffix(host: string): string {
  const reg = registrableDomain(host);
  return reg.split(".").slice(1).join(".");
}
