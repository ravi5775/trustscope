# TrustScope Analyzer

> **Advanced, Autonomous Website Trust & Cybersecurity Intelligence Platform**

TrustScope Analyzer is a client-side security assessment application built with **React 19**, **TanStack Start**, **TypeScript**, and **Tailwind CSS v4**. It conducts real-time, privacy-preserving website trust analyses directly in your browser without routing targeted URLs through third-party tracking servers.

---

## Key Features

- **Autonomous Client-Side Telemetry**: Zero-knowledge queries executed via public CORS-enabled APIs.
- **Certificate Transparency (CT) Auditing**: Real-time query of `crt.sh` logs for issuer CA identification, expiration timeline, and Subject Alternative Name (SAN) subdomain mapping.
- **Domain & DNS-over-HTTPS Inspection**: Automated lookup of ICANN RDAP registry data (creation, expiration, registrar, status flags) and cryptographic Cloudflare DoH resolution (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`).
- **Phishing & Brand Impersonation Heuristics**: Detects Unicode homoglyphs, mixed-script spoofing, Levenshtein distance typosquatting, credential-lure keywords, and high-abuse top-level domains.
- **HTTP Transport Posture**: Analyzes encryption protocols, HSTS preloading expectations, and mixed-content risks.
- **Calibrated Risk Engine**: Transparent indicator-based scoring model (0–100) paired with an explicit **Evidence Coverage** percentage and confidence rating.
- **Interactive Cyberpunk Dark UI**: Fully responsive glassmorphism interface with multi-phase animated scanning progress and comprehensive 6-tab audit reports.
- **SSRF & Private Network Guard**: Automatically blocks scanning of private IPv4/IPv6 ranges, loopback (`localhost`), and reserved local network suffixes.

---

## Architecture & Analysis Modules

TrustScope evaluates URLs through independent analysis modules:

```
                      ┌───────────────────────┐
                      │    Target Web URL     │
                      └───────────┬───────────┘
                                  │
                       [ normalizeTarget() ]
                      (SSRF Guard & Validation)
                                  │
       ┌──────────────────────────┼──────────────────────────┐
       │                          │                          │
┌──────┴──────┐            ┌──────┴──────┐            ┌──────┴──────┐
│  Cert Module│            │Domain Module│            │Lexical Rules│
│  (crt.sh)   │            │ (RDAP + DoH)│            │(Phishing/IDN)│
└──────┬──────┘            └──────┬──────┘            └──────┬──────┘
       │                          │                          │
       │                   ┌──────┴──────┐                   │
       └──────────────────►│ HTTP Module │◄──────────────────┘
                           │ (Transport) │
                           └──────┬──────┘
                                  │
                        ┌─────────┴─────────┐
                        │   Threat Module   │
                        │ (API Disclosures) │
                        └─────────┬─────────┘
                                  │
                         [ assessRisk() ]
                    (Aggregated Findings Score)
                                  │
               ┌──────────────────┴──────────────────┐
               ▼                                     ▼
        ┌──────────────┐                     ┌───────────────┐
        │  Risk Score  │                     │Security Report│
        │  (0-100)     │                     │  (6 Full Tabs)│
        └──────────────┘                     └───────────────┘
```

1. **`certModule.ts`**: Queries public Certificate Transparency logs for SSL/TLS validity, issuer authority, expiration alerts (<30 days), and subdomains.
2. **`domainModule.ts`**: Queries ICANN RDAP for domain registration age and Cloudflare DNS-over-HTTPS for DNS infrastructure records.
3. **`lexical.ts`**: Applies deterministic rules for structural anomalies, suspicious TLDs, confusable Unicode characters, and monitored brand lookalikes.
4. **`httpModule.ts`**: Analyzes connection transport, mixed-content exposure, and HSTS policy requirements.
5. **`threatModule.ts`**: Handles threat intelligence interfaces with clear operational disclosures.
6. **`scoring.ts`**: Weights observations and heuristics to compute a fair score, rule counts, and primary risk contributors.

---

## Tech Stack

- **Framework**: [TanStack Start](https://tanstack.com/start) & [TanStack Router](https://tanstack.com/router)
- **Runtime & UI**: [React 19](https://react.dev/), [TypeScript](https://www.typescriptlang.org/)
- **Styling**: [Tailwind CSS v4](https://tailwindcss.com/) with `@theme inline` design tokens
- **Components**: [shadcn/ui](https://ui.shadcn.com/) (Radix UI primitives)
- **Icons**: [Lucide React](https://lucide.dev/)
- **Bundler & SSR Engine**: [Vite 8](https://vitejs.dev/) & [Nitro](https://nitro.unjs.io/)
- **Testing**: [Vitest](https://vitest.dev/)

---

## Getting Started

### Prerequisites

- **Node.js**: v18.0.0 or later (v20+ recommended)
- **npm**: v9.0.0 or later

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd trustscope-analyzer
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the development server**:
   ```bash
   npm run dev
   ```
   Open **[http://localhost:8080](http://localhost:8080)** in your browser.

---

## Available Scripts

| Command | Description |
| :--- | :--- |
| `npm run dev` | Starts the Vite development server with hot module replacement |
| `npm run build` | Builds the production bundle (client assets + Nitro SSR server) |
| `npm run preview` | Previews the compiled production build locally |
| `npm run test` | Executes unit tests via Vitest |
| `npm run test:watch` | Runs Vitest in interactive watch mode |
| `npm run lint` | Runs ESLint across the codebase |
| `npm run format` | Formats code with Prettier |
| `npx tsc --noEmit` | Runs the TypeScript compiler to check for type errors |

---

## Project Structure

```
├── public/                 # Static assets (favicons, robots.txt)
├── src/
│   ├── components/
│   │   ├── ui/             # Radix UI / shadcn component library
│   │   ├── RiskScore.tsx   # Risk score gauge, coverage bar, and contributor metrics
│   │   ├── SecurityAnalyzer.tsx # Main analyzer workflow, scan progress, & target input
│   │   └── SecurityReport.tsx   # 6-tab detailed technical report
│   ├── lib/
│   │   ├── analysis/
│   │   │   ├── brands.ts   # Monitored brand list for lookalike detection
│   │   │   ├── certModule.ts # crt.sh Certificate Transparency client
│   │   │   ├── domainModule.ts # RDAP and DNS-over-HTTPS queries
│   │   │   ├── httpModule.ts   # Transport protocol & mixed-content heuristics
│   │   │   ├── lexical.ts  # Homoglyph, typosquatting & lexical heuristics
│   │   │   ├── punycode.ts # Unicode & IDN punycode converter
│   │   │   ├── scoring.ts  # Risk assessment calculation engine
│   │   │   ├── threatModule.ts # Threat-intel provider status
│   │   │   ├── types.ts    # TypeScript interfaces and finding types
│   │   │   └── url.ts      # Target normalisation and SSRF guard
│   │   ├── error-capture.ts # Error recovery utility
│   │   ├── error-page.ts   # Fallback error page template
│   │   └── utils.ts        # Class merging utilities (clsx + tailwind-merge)
│   ├── routes/
│   │   ├── __root.tsx      # Root router shell and layout
│   │   └── index.tsx       # Root page mounting SecurityAnalyzer
│   ├── styles.css          # Cyberpunk dark theme and Tailwind CSS v4 definitions
│   └── test/               # Vitest unit test suites
├── package.json            # Project dependencies and script definitions
├── tsconfig.json           # TypeScript configuration
└── vite.config.ts          # Vite build configuration
```

---

## Operational Disclaimers

- **Browser-Only Environment**: Web browser security policies (CORS) prevent direct inspection of raw HTTP response headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`) or programmatic cross-origin redirect following.
- **Public API Reliability**: External services such as `crt.sh` and Cloudflare DNS may experience temporary latency, rate-limiting, or partial availability.
- **No Absolute Safety Guarantee**: A low risk score indicates that assessed indicators passed standard checks; it is not a formal certification of security or innocence.
