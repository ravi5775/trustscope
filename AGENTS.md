# TrustScope Analyzer — Agent Guidelines

This repository contains the **TrustScope Analyzer** codebase, an autonomous client-side website trust, reputation, and cybersecurity analysis platform.

## Architecture Overview

- **Framework**: TanStack Start (fullstack React framework with SSR and Vite)
- **UI Components**: shadcn/ui primitives, Tailwind CSS v4, Lucide React icons
- **Security Theme**: Cyberpunk dark theme configured via `@theme inline` in `src/styles.css`
- **Client Execution**: All telemetry inspection operates in the browser via public CORS-enabled endpoints:
  - Certificate Transparency via `crt.sh`
  - DNS-over-HTTPS via Cloudflare DNS JSON API (`https://cloudflare-dns.com/dns-query`)
  - Domain WHOIS & Registration data via ICANN RDAP (`https://rdap.org/domain/{domain}`)
  - URL pattern, homograph, and brand typosquatting heuristics via deterministic rules

## Key Modules

- `src/lib/analysis/types.ts`: Core data structures (`Finding`, `RiskAssessment`, `CertFacts`, `DomainFacts`, `HttpFacts`, `ModuleResult`).
- `src/lib/analysis/scoring.ts`: Mathematical risk calculation and evidence coverage estimator (`assessRisk`).
- `src/lib/analysis/url.ts`: Target normalisation, validation, SSRF guard, and registrable domain extraction.
- `src/lib/analysis/lexical.ts`: Hostname structure, brand impersonation detection, and credential keyword heuristics.
- `src/lib/analysis/certModule.ts`: Certificate Transparency log interrogation.
- `src/lib/analysis/domainModule.ts`: RDAP and DNS-over-HTTPS lookup module.
- `src/lib/analysis/httpModule.ts`: Transport protocol and mixed-content security evaluation.
- `src/lib/analysis/threatModule.ts`: Threat-intelligence provider interface and disclosure.

## Development & Verification

- `npm run dev`: Launch local development server.
- `npm run build`: Compile client and server SSR bundles.
- `npm run test`: Run unit test suite via Vitest.
- `npx tsc --noEmit`: Typecheck the TypeScript codebase.
