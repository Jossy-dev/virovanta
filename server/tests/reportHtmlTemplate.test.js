import { describe, expect, it } from "vitest";
import { buildWebsiteSecurityReportHtml } from "../src/utils/reportHtmlTemplate.js";

function createWebsiteReport() {
  return {
    id: "report_website_123",
    sourceType: "website",
    createdAt: "2026-03-30T10:00:00.000Z",
    completedAt: "2026-03-30T10:02:00.000Z",
    verdict: "suspicious",
    riskScore: 42,
    plainLanguageReasons: [
      "The site is missing a few hardening controls and exposed sensitive endpoints that deserve review."
    ],
    recommendations: [
      "Add a Content-Security-Policy and HSTS header.",
      "Remove or protect exposed administrative and secret-bearing paths."
    ],
    findings: [
      {
        id: "missing_headers",
        severity: "medium",
        category: "Headers",
        title: "Missing security headers",
        description: "The site is missing one or more recommended browser hardening headers.",
        evidence: "content-security-policy, strict-transport-security"
      },
      {
        id: "sensitive_exposure",
        severity: "high",
        category: "Exposure",
        title: "Sensitive exposure reachable",
        description: "A sensitive path responded with content that should not be public.",
        evidence: "/.env responded with 200"
      }
    ],
    file: {
      originalName: "https://example.com",
      hashes: {
        sha256: "abc123def456"
      }
    },
    url: {
      final: "https://example.com",
      normalized: "https://example.com",
      hostname: "example.com"
    },
    websiteSafety: {
      score: 58,
      verdict: "suspicious",
      modules: {
        ssl: {
          status: "completed",
          protocol: "TLSv1.3",
          certIssuer: "Let's Encrypt",
          certValidTo: "2026-06-15T00:00:00.000Z",
          certDaysRemaining: 77,
          certSelfSigned: false
        },
        headers: {
          missing: ["content-security-policy", "strict-transport-security"],
          values: {
            "x-frame-options": "SAMEORIGIN"
          }
        },
        dnsDomain: {
          ageDays: 2048,
          registrar: "Example Registrar",
          registeredAt: "2020-08-20T00:00:00.000Z",
          expiresAt: "2027-08-20T00:00:00.000Z",
          nameservers: ["ns1.example.com", "ns2.example.com"],
          rdap: {
            domain: "example.com",
            registrationEvidence: "created event",
            dnssecSigned: true,
            abuseEmail: "abuse@example.com",
            domainStatus: ["client transfer prohibited"]
          },
          mailAuth: {
            spfPresent: true,
            dmarcPresent: true
          }
        },
        ipHosting: {
          primaryIp: "203.0.113.10",
          asn: "AS64500",
          organization: "Example Hosting"
        },
        content: {
          phishingSignalScore: 16,
          suspiciousKeywords: ["verify", "urgent"],
          externalLinkCount: 12,
          suspiciousExternalLinkCount: 1,
          hiddenIframes: 0,
          obfuscatedScriptIndicators: 1,
          externalScripts: ["https://cdn.example.com/app.js"]
        },
        redirects: {
          count: 1,
          crossDomainCount: 0,
          chain: [
            {
              from: "http://example.com",
              to: "https://example.com",
              statusCode: 301
            }
          ]
        },
        reputation: {
          flaggedProviders: [],
          providers: [
            {
              provider: "virustotal",
              status: "clean"
            }
          ]
        },
        vulnerabilityChecks: {
          exposures: [
            {
              path: "/.env",
              status: 200
            }
          ]
        }
      }
    }
  };
}

describe("buildWebsiteSecurityReportHtml", () => {
  it("renders premium summary sections and eye-catching metrics for website reports", async () => {
    const { html } = await buildWebsiteSecurityReportHtml({
      report: createWebsiteReport(),
      appName: "ViroVanta"
    });

    expect(html).toContain("Executive website safety report");
    expect(html).toContain("Priority Findings");
    expect(html).toContain("Analyst-ready assessment");
    expect(html).toContain("Sensitive exposures");
    expect(html).toContain("First analyst note");
    expect(html).toContain("example.com");
  });
});
