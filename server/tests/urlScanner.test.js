import { describe, expect, it } from "vitest";
import { scanTargetUrl } from "../src/scanner/urlScanner.js";

const FAST_TEST_CONFIG = Object.freeze({
  urlScanTimeoutMs: 500,
  urlScanMaxRedirects: 2,
  urlScanMaxBodyBytes: 64_000,
  urlScanMaxDownloadBytes: 128_000,
  urlScanEnableBrowserRender: false,
  urlScanEnableDownloadInspection: false,
  urlIntelTimeoutMs: 500,
  urlScanUserAgent: "virovanta-url-scanner-test"
});

describe("URL scanner", () => {
  it("rejects non-http protocols during normalization", async () => {
    await expect(
      scanTargetUrl({
        url: "ftp://example.com",
        runtimeConfig: FAST_TEST_CONFIG
      })
    ).rejects.toThrow(/Only HTTP and HTTPS links are supported/i);
  });

  it("rejects non-standard ports for strict egress safety", async () => {
    await expect(
      scanTargetUrl({
        url: "https://example.com:8443/login",
        runtimeConfig: FAST_TEST_CONFIG
      })
    ).rejects.toThrow(/Only standard web ports/i);
  });

  it("blocks localhost/private addresses and emits SSRF findings", async () => {
    const report = await scanTargetUrl({
      url: "http://127.0.0.1/private",
      runtimeConfig: FAST_TEST_CONFIG
    });

    expect(report.sourceType).toBe("url");
    expect(report.verdict).toBe("malicious");
    expect(report.findings.some((item) => item.id === "url_ssrf_blocked")).toBe(true);
    expect(report.engines.ssrfGuard.status).toBe("blocked");
  });

  it("canonicalizes IDN domains to punycode in URL metadata", async () => {
    const report = await scanTargetUrl({
      url: "https://bücher.de/login",
      runtimeConfig: {
        ...FAST_TEST_CONFIG,
        urlScanTimeoutMs: 800
      }
    });

    expect(report.sourceType).toBe("url");
    expect(report.url.asciiHostname).toContain("xn--");
    expect(report.url.unicodeHostname).toContain("bücher");
  });

  it("returns disabled reputation providers when API keys are not configured", async () => {
    const report = await scanTargetUrl({
      url: "http://127.0.0.1/private",
      runtimeConfig: FAST_TEST_CONFIG
    });

    expect(Array.isArray(report.engines.reputation.providers)).toBe(true);
    expect(report.engines.reputation.providers.every((provider) => provider.status === "disabled")).toBe(true);
    expect(report.engines.reputation.providers.map((provider) => provider.provider)).toEqual(
      expect.arrayContaining(["virustotal", "google_safe_browsing", "urlhaus"])
    );
  });
});
