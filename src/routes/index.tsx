import { createFileRoute } from "@tanstack/react-router";
import { SecurityAnalyzer } from "@/components/SecurityAnalyzer";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "TrustScope Analyzer — Website Trust & Security Check" },
      { name: "description", content: "Analyze any website for SSL, domain reputation, and phishing risk signals." },
      { property: "og:title", content: "TrustScope Analyzer — Website Trust & Security Check" },
      { property: "og:description", content: "Analyze any website for SSL, domain reputation, and phishing risk signals." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: SecurityAnalyzer,
});
