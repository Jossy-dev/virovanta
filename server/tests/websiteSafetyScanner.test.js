import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dnsMock = vi.hoisted(() => ({
  lookup: vi.fn(),
  resolve4: vi.fn(),
  resolve6: vi.fn(),
  resolveMx: vi.fn(),
  resolveNs: vi.fn(),
  resolveTxt: vi.fn(),
  resolveCname: vi.fn(),
  resolveSoa: vi.fn()
}));

const tlsMock = vi.hoisted(() => ({
  connect: vi.fn()
}));

vi.mock("dns/promises", () => ({
  default: dnsMock
}));

vi.mock("tls", () => ({
  default: tlsMock
}));

import {
  buildRdapLookupCandidates,
  extractRdapMetadata,
  normalizeWebsiteSafetyReport,
  scanWebsiteSafetyTarget
} from "../src/scanner/websiteSafetyScanner.js";

function htmlResponse(body, headers = {}) {
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...headers
    }
  });
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}

function emptyResponse(status = 404, headers = {}) {
  return new Response("", {
    status,
    headers
  });
}

const FAST_TEST_CONFIG = Object.freeze({
  urlScanTimeoutMs: 500,
  urlScanMaxRedirects: 2,
  urlScanMaxBodyBytes: 64_000,
  urlScanEnableBrowserRender: false,
  urlIntelTimeoutMs: 500,
  urlScanUserAgent: "virovanta-website-safety-test",
  googleSafeBrowsingApiKey: "",
  virusTotalApiKey: "",
  urlhausEnabled: false
});

describe("website safety scanner", () => {
  beforeEach(() => {
    dnsMock.lookup.mockResolvedValue([{ address: "93.184.216.34" }]);
    dnsMock.resolve4.mockResolvedValue(["93.184.216.34"]);
    dnsMock.resolve6.mockResolvedValue([]);
    dnsMock.resolveMx.mockResolvedValue([]);
    dnsMock.resolveNs.mockResolvedValue(["ns1.example.net", "ns2.example.net"]);
    dnsMock.resolveTxt.mockImplementation(async (hostname) => {
      if (String(hostname).startsWith("_dmarc.")) {
        return [];
      }

      return [];
    });
    dnsMock.resolveCname.mockResolvedValue([]);
    dnsMock.resolveSoa.mockResolvedValue({
      nsname: "ns1.example.net",
      hostmaster: "hostmaster.example.net",
      serial: 2026032701
    });

    tlsMock.connect.mockImplementation((_options, onSecureConnect) => {
      const socket = {
        authorized: true,
        authorizationError: null,
        getProtocol: () => "TLSv1.3",
        getPeerCertificate: () => ({
          valid_from: "Jan 1 2024 00:00:00 GMT",
          valid_to: "Jan 1 2030 00:00:00 GMT",
          subject: { CN: "docs.djangoproject.com" },
          issuer: { CN: "Example Test CA" }
        }),
        setTimeout: vi.fn(),
        on: vi.fn(() => socket),
        end: vi.fn(),
        destroy: vi.fn()
      };

      queueMicrotask(() => {
        onSecureConnect();
      });

      return socket;
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        const normalizedUrl = String(url);

        if (normalizedUrl === "https://docs.djangoproject.com/en/4.1/") {
          return htmlResponse("<html><head><title>Django documentation</title></head><body>Documentation</body></html>", {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin"
          });
        }

        if (normalizedUrl === "https://portal.example.dev/") {
          return htmlResponse("<html><head><title>Example portal</title></head><body>Portal</body></html>", {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin"
          });
        }

        if (normalizedUrl === "https://data.iana.org/rdap/dns.json") {
          return jsonResponse({
            services: [
              [["com"], ["https://rdap.verisign.com/com/v1/"]],
              [["dev"], ["https://rdap.nic.dev/"]]
            ]
          });
        }

        if (normalizedUrl === "https://rdap.org/domain/djangoproject.com" || normalizedUrl === "https://rdap.verisign.com/com/v1/domain/djangoproject.com") {
          return jsonResponse({
            ldhName: "djangoproject.com",
            events: [
              {
                eventAction: "registration",
                eventDate: "2012-02-14T00:00:00Z"
              }
            ],
            nameservers: [{ ldhName: "ns1.example.net" }, { ldhName: "ns2.example.net" }],
            entities: [
              {
                roles: ["registrar"],
                vcardArray: ["vcard", [["fn", {}, "text", "Example Registrar"]]]
              }
            ]
          });
        }

        if (normalizedUrl === "https://rdap.nic.dev/domain/example.dev") {
          return jsonResponse({
            ldhName: "example.dev",
            status: ["client transfer prohibited"],
            events: [
              {
                eventAction: "registration",
                eventDate: "2021-04-12T00:00:00Z"
              }
            ],
            secureDNS: {
              delegationSigned: true
            },
            nameservers: [{ ldhName: "ns1.example.net" }, { ldhName: "ns2.example.net" }],
            entities: [
              {
                roles: ["registrar"],
                vcardArray: ["vcard", [["fn", {}, "text", "Example Dev Registrar"]]]
              },
              {
                roles: ["abuse"],
                vcardArray: ["vcard", [["email", {}, "text", "abuse@example.dev"]]]
              }
            ]
          });
        }

        if (normalizedUrl.startsWith("https://docs.djangoproject.com/.well-known/security.txt")) {
          return emptyResponse(404, { "content-type": "text/plain" });
        }

        if (normalizedUrl.startsWith("https://docs.djangoproject.com/robots.txt")) {
          return emptyResponse(200, { "content-type": "text/plain" });
        }

        if (
          [
            "https://docs.djangoproject.com/.env",
            "https://docs.djangoproject.com/.git/config",
            "https://docs.djangoproject.com/config.php",
            "https://docs.djangoproject.com/backup.zip",
            "https://docs.djangoproject.com/phpinfo.php",
            "https://docs.djangoproject.com/admin",
            "https://docs.djangoproject.com/login",
            "https://docs.djangoproject.com/wp-admin",
            "https://docs.djangoproject.com/administrator"
          ].includes(normalizedUrl)
        ) {
          return htmlResponse("<html><head><title>Django documentation</title></head><body>Documentation</body></html>", {
            "content-type": "text/html; charset=utf-8"
          });
        }

        if (normalizedUrl.startsWith("https://docs.djangoproject.com/")) {
          return emptyResponse(404, { "content-type": "text/plain" });
        }

        if (normalizedUrl.startsWith("https://portal.example.dev/.well-known/security.txt")) {
          return emptyResponse(404, { "content-type": "text/plain" });
        }

        if (normalizedUrl.startsWith("https://portal.example.dev/robots.txt")) {
          return emptyResponse(200, { "content-type": "text/plain" });
        }

        if (
          [
            "https://portal.example.dev/.env",
            "https://portal.example.dev/.git/config",
            "https://portal.example.dev/config.php",
            "https://portal.example.dev/backup.zip",
            "https://portal.example.dev/phpinfo.php",
            "https://portal.example.dev/admin",
            "https://portal.example.dev/login",
            "https://portal.example.dev/wp-admin",
            "https://portal.example.dev/administrator"
          ].includes(normalizedUrl)
        ) {
          return emptyResponse(404, { "content-type": "text/plain" });
        }

        if (normalizedUrl.startsWith("https://portal.example.dev/")) {
          return emptyResponse(404, { "content-type": "text/plain" });
        }

        throw new Error(`Unexpected fetch: ${normalizedUrl}`);
      })
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("prioritizes the registrable parent domain for docs-style subdomains", () => {
    expect(buildRdapLookupCandidates("docs.djangoproject.com")).toEqual([
      "djangoproject.com",
      "docs.djangoproject.com"
    ]);
  });

  it("does not infer a registration date from unrelated RDAP events", () => {
    const metadata = extractRdapMetadata(
      {
        ldhName: "docs.djangoproject.com",
        events: [
          {
            eventAction: "last changed",
            eventDate: "2026-03-20T00:00:00Z"
          }
        ]
      },
      "docs.djangoproject.com"
    );

    expect(metadata.registeredAt).toBeNull();
    expect(metadata.registrationEvidence).toBe("unverified");
  });

  it("does not flag a mature docs subdomain as newly registered", async () => {
    const report = await scanWebsiteSafetyTarget({
      url: "https://docs.djangoproject.com/en/4.1/",
      runtimeConfig: FAST_TEST_CONFIG
    });

    expect(report.sourceType).toBe("website");
    expect(report.findings.some((item) => item.id === "website_domain_new")).toBe(false);
    expect(report.findings.some((item) => item.id === "website_sensitive_path_exposed")).toBe(false);
    expect(report.websiteSafety.modules.vulnerabilityChecks.exposures).toHaveLength(0);
    expect(report.websiteSafety.modules.dnsDomain.ageDays).toBeGreaterThan(365);
    expect(report.websiteSafety.modules.dnsDomain.rdap.domain).toBe("djangoproject.com");
    expect(report.websiteSafety.modules.dnsDomain.rdap.registrationEvidence).toBe("explicit_rdap_event");
    expect(report.websiteSafety.verdict).toBe("safe");
    expect(report.riskScore).toBeLessThanOrEqual(10);
  });

  it("uses IANA RDAP bootstrap data to discover authoritative RDAP for additional TLDs", async () => {
    const report = await scanWebsiteSafetyTarget({
      url: "https://portal.example.dev/",
      runtimeConfig: FAST_TEST_CONFIG
    });

    expect(report.websiteSafety.modules.dnsDomain.ageDays).toBeGreaterThan(365);
    expect(report.websiteSafety.modules.dnsDomain.rdap.source).toBe("https://rdap.nic.dev/domain/example.dev");
    expect(report.websiteSafety.modules.dnsDomain.rdap.domain).toBe("example.dev");
    expect(report.websiteSafety.modules.dnsDomain.rdap.dnssecSigned).toBe(true);
    expect(report.websiteSafety.modules.dnsDomain.rdap.abuseEmail).toBe("abuse@example.dev");
    expect(report.websiteSafety.modules.dnsDomain.rdap.domainStatus).toContain("client transfer prohibited");
    expect(report.findings.some((item) => item.id === "website_domain_new")).toBe(false);
  });

  it("normalizes legacy website reports with unverified age and exposure claims", () => {
    const report = normalizeWebsiteSafetyReport({
      id: "scan_legacy_docs",
      createdAt: "2026-03-28T00:00:00Z",
      completedAt: "2026-03-28T00:00:00Z",
      sourceType: "website",
      verdict: "suspicious",
      riskScore: 42,
      file: {
        originalName: "https://docs.djangoproject.com/en/4.1/",
        extension: "(website)",
        size: 2048,
        sizeDisplay: "2 KB",
        declaredMimeType: "text/url",
        detectedMimeType: "text/html",
        detectedFileType: "website",
        magicType: "Website target",
        entropy: 0,
        printableRatio: 1,
        hashes: {
          md5: "md5",
          sha1: "sha1",
          sha256: "sha256"
        }
      },
      findings: [
        {
          id: "website_domain_new",
          severity: "high",
          category: "Domain",
          weight: 15,
          title: "Newly registered domain",
          description: "The domain appears recently registered, which increases phishing risk.",
          evidence: "unknown"
        },
        {
          id: "website_sensitive_path_exposed",
          severity: "critical",
          category: "Exposure",
          weight: 30,
          title: "Sensitive endpoint appears publicly reachable",
          description: "One or more sensitive paths responded successfully and may expose confidential data.",
          evidence: "/.env (200), /.git/config (200)"
        }
      ],
      recommendations: ["Legacy report."],
      plainLanguageReasons: ["The domain appears recently registered, which increases phishing risk."],
      technicalIndicators: {},
      websiteSafety: {
        score: 58,
        verdict: "suspicious",
        checkedAt: "2026-03-28T00:00:00Z",
        url: {
          input: "https://docs.djangoproject.com/en/4.1/",
          normalized: "https://docs.djangoproject.com/en/4.1/",
          final: "https://docs.djangoproject.com/en/4.1/",
          hostname: "docs.djangoproject.com",
          protocol: "https"
        },
        modules: {
          dnsDomain: {
            status: "completed",
            ageDays: null,
            rdap: {
              domain: "djangoproject.com",
              registrationEvidence: "unverified"
            }
          },
          headers: {
            status: "completed",
            missing: ["content-security-policy"]
          },
          redirects: {
            status: "completed",
            count: 0,
            crossDomainCount: 0
          },
          content: {
            status: "completed",
            phishingSignalScore: 0,
            hiddenIframes: 0,
            obfuscatedScriptIndicators: 0,
            suspiciousExternalLinkCount: 0,
            suspiciousExternalLinks: [],
            suspiciousKeywords: [],
            phishingPhrases: []
          },
          ssl: {
            status: "completed",
            certExpired: false,
            certSelfSigned: false,
            authorized: true
          },
          reputation: {
            flagged: false,
            flaggedProviders: [],
            flaggedThreats: []
          },
          vulnerabilityChecks: {
            status: "completed",
            exposures: [
              { path: "/.env", status: 200, reachable: true },
              { path: "/.git/config", status: 200, reachable: true }
            ],
            adminEndpoints: []
          }
        }
      },
      engines: {
        fetch: { status: "ok", statusCode: 200 }
      },
      url: {
        input: "https://docs.djangoproject.com/en/4.1/",
        normalized: "https://docs.djangoproject.com/en/4.1/",
        final: "https://docs.djangoproject.com/en/4.1/",
        protocol: "https",
        hostname: "docs.djangoproject.com"
      }
    });

    expect(report.findings.some((item) => item.id === "website_domain_new")).toBe(false);
    expect(report.findings.some((item) => item.id === "website_sensitive_path_exposed")).toBe(false);
    expect(report.websiteSafety.modules.vulnerabilityChecks.exposures).toHaveLength(0);
    expect(report.verdict).toBe("clean");
    expect(report.riskScore).toBe(4);
    expect(report.plainLanguageReasons[0]).toBe("The target is missing one or more recommended HTTP security headers.");
  });
});
