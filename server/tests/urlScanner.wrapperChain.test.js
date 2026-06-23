import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dnsMock = vi.hoisted(() => ({
  lookup: vi.fn()
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

import { scanTargetUrl } from "../src/scanner/urlScanner.js";

function htmlResponse(body, headers = {}) {
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...headers
    }
  });
}

const FAST_TEST_CONFIG = Object.freeze({
  urlScanTimeoutMs: 500,
  urlScanMaxRedirects: 3,
  urlScanMaxBodyBytes: 64_000,
  urlScanMaxDownloadBytes: 128_000,
  urlScanEnableBrowserRender: false,
  urlScanEnableDownloadInspection: false,
  urlIntelTimeoutMs: 500,
  urlScanUserAgent: "virovanta-url-wrapper-test",
  googleSafeBrowsingApiKey: "",
  virusTotalApiKey: "",
  urlhausEnabled: false
});

describe("URL scanner wrapper chain analysis", () => {
  beforeEach(() => {
    dnsMock.lookup.mockImplementation(async (hostname) => {
      const normalized = String(hostname || "").toLowerCase();
      if (normalized === "t.co") {
        return [{ address: "104.244.42.129" }];
      }

      if (normalized === "contactparcelfedex.com") {
        return [{ address: "198.51.100.24" }];
      }

      return [{ address: "93.184.216.34" }];
    });

    tlsMock.connect.mockImplementation((_options, onSecureConnect) => {
      const socket = {
        authorized: true,
        authorizationError: null,
        getProtocol: () => "TLSv1.3",
        getPeerCertificate: () => ({
          valid_from: "Jan 1 2025 00:00:00 GMT",
          valid_to: "Jan 1 2030 00:00:00 GMT",
          subject: { CN: "contactparcelfedex.com" },
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
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("unwraps known social redirect wrappers and scores the full navigation chain", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        const normalized = String(url);

        if (normalized === "https://t.co/LXtg5UMy39?ssr=true") {
          return new Response("", {
            status: 302,
            headers: {
              location: "https://contactparcelfedex.com/"
            }
          });
        }

        if (normalized === "https://contactparcelfedex.com/") {
          return htmlResponse(`
            <html>
              <head><title>Parcel review required</title></head>
              <body>
                <h1>Urgent action required</h1>
                <p>Please verify your account to release your package.</p>
                <form method="post" action="/submit">
                  <input type="password" name="password" />
                </form>
              </body>
            </html>
          `);
        }

        throw new Error(`Unexpected fetch URL: ${normalized}`);
      })
    );

    const report = await scanTargetUrl({
      url: "https://l.facebook.com/%6C%2E%70%68%70?%75=%68%74%74%70%73%3A%2F%2F%74%2E%63%6F%2F%4C%58%74%67%35%55%4D%79%33%39%3F%73%73%72%3D%74%72%75%65",
      runtimeConfig: FAST_TEST_CONFIG
    });

    expect(report.verdict).toBe("malicious");
    expect(report.url.input).toContain("l.facebook.com");
    expect(report.url.analysisStart).toBe("https://t.co/LXtg5UMy39?ssr=true");
    expect(report.url.final).toBe("https://contactparcelfedex.com/");
    expect(Array.isArray(report.url.navigationChain)).toBe(true);
    expect(report.url.navigationChain.some((step) => step.kind === "wrapper_param")).toBe(true);
    expect(report.url.navigationChain.some((step) => step.kind === "http_redirect")).toBe(true);
    expect(report.technicalIndicators.wrapperResolution.wrapperHosts).toContain("l.facebook.com");
    expect(report.findings.some((item) => item.id === "url_known_redirect_wrapper")).toBe(true);
    expect(report.findings.some((item) => item.id === "url_nested_target_extracted")).toBe(true);
    expect(report.findings.some((item) => item.id === "url_final_destination_mismatch")).toBe(true);
    expect(report.recommendations.some((item) => /wrapper extraction chain/i.test(item))).toBe(true);
  });

  it("unwraps nested facebook login forwarding before following the warning chain", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        const normalized = String(url);

        if (normalized === "https://t.co/LXtg5UMy39?ssr=true") {
          return new Response("", {
            status: 302,
            headers: {
              location: "https://contactparcelfedex.com/"
            }
          });
        }

        if (normalized === "https://contactparcelfedex.com/") {
          return htmlResponse(`
            <html>
              <head><title>Parcel review required</title></head>
              <body>
                <h1>Urgent action required</h1>
                <p>Please verify your account to release your package.</p>
                <form method="post" action="/submit">
                  <input type="password" name="password" />
                </form>
              </body>
            </html>
          `);
        }

        throw new Error(`Unexpected fetch URL: ${normalized}`);
      })
    );

    const report = await scanTargetUrl({
      url: "https://www.facebook.com/login/?next=https%3A%2F%2Fwww.facebook.com%2Fflx%2Fwarn%2F%3Fu%3Dhttps%253A%252F%252Ft.co%252FLXtg5UMy39%253Fssr%253Dtrue",
      runtimeConfig: FAST_TEST_CONFIG
    });

    expect(report.verdict).toBe("malicious");
    expect(report.url.input).toContain("facebook.com/login/");
    expect(report.url.analysisStart).toBe("https://t.co/LXtg5UMy39?ssr=true");
    expect(report.url.final).toBe("https://contactparcelfedex.com/");
    expect(report.url.navigationChain.filter((step) => step.kind === "wrapper_param")).toHaveLength(2);
    expect(report.technicalIndicators.wrapperResolution.wrapperHosts).toContain("www.facebook.com");
    expect(report.findings.some((item) => item.id === "url_known_redirect_wrapper")).toBe(true);
    expect(report.findings.some((item) => item.id === "url_nested_target_extracted")).toBe(true);
    expect(report.findings.some((item) => item.id === "url_final_destination_mismatch")).toBe(true);
  });
});
