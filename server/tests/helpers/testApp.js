import crypto from "crypto";
import fs from "fs/promises";
import os from "os";
import path from "path";
import request from "supertest";
import { expect } from "vitest";
import { createApp } from "../../src/app/createApp.js";

const tempRoots = [];

export async function setupTestApp({
  freeTierDailyScanLimit = 40,
  scanner = null,
  urlScanner = null,
  websiteSafetyScanner = null,
  configOverrides = {}
} = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-test-"));
  const uploadDir = path.join(root, "uploads");
  const dataFilePath = path.join(root, "store.json");

  tempRoots.push(root);

  const mockScanner = async ({ originalName, declaredMimeType }) => ({
    id: `scan_${Math.random().toString(36).slice(2, 10)}`,
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    verdict: "clean",
    riskScore: 3,
    file: {
      originalName,
      extension: path.extname(originalName || "").toLowerCase() || "(none)",
      size: 10,
      sizeDisplay: "10 B",
      declaredMimeType: declaredMimeType || "unknown",
      detectedMimeType: "text/plain",
      detectedFileType: "txt",
      magicType: "Text",
      entropy: 1.11,
      printableRatio: 1,
      hashes: {
        md5: "x",
        sha1: "y",
        sha256: "z"
      }
    },
    findings: [],
    engines: {
      heuristics: {
        status: "completed",
        matchedRules: [],
        findingCount: 0
      },
      clamav: {
        status: "disabled",
        detail: "disabled"
      },
      virustotal: {
        status: "disabled",
        detail: "disabled"
      }
    },
    recommendations: ["Safe to continue"]
  });

  const mockUrlScanner = async ({ url }) => {
    const parsed = new URL(String(url || "https://example.com"));

    return {
      id: `scan_${Math.random().toString(36).slice(2, 10)}`,
      createdAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      sourceType: "url",
      verdict: "clean",
      riskScore: 5,
      file: {
        originalName: parsed.toString(),
        extension: "(url)",
        size: 512,
        sizeDisplay: "512 B",
        declaredMimeType: "text/url",
        detectedMimeType: "text/html",
        detectedFileType: "url",
        magicType: "URL target",
        entropy: 0,
        printableRatio: 1,
        hashes: {
          md5: crypto.createHash("md5").update(parsed.toString()).digest("hex"),
          sha1: crypto.createHash("sha1").update(parsed.toString()).digest("hex"),
          sha256: crypto.createHash("sha256").update(parsed.toString()).digest("hex")
        }
      },
      findings: [],
      engines: {
        heuristics: {
          status: "completed",
          matchedRules: [],
          findingCount: 0
        },
        urlFetch: {
          status: "ok",
          detail: "URL fetched successfully.",
          statusCode: 200,
          finalUrl: parsed.toString(),
          redirects: [],
          truncated: false
        },
        ssrfGuard: {
          status: "passed",
          blockedReason: null,
          resolvedAddresses: []
        }
      },
      recommendations: ["No high-risk indicators detected from this first-pass URL scan."],
      url: {
        input: parsed.toString(),
        normalized: parsed.toString(),
        final: parsed.toString(),
        protocol: parsed.protocol.replace(/:$/, ""),
        hostname: parsed.hostname,
        statusCode: 200,
        contentType: "text/html",
        title: "Example",
        redirects: [],
        resolvedAddresses: [],
        truncated: false
      }
    };
  };

  const mockWebsiteSafetyScanner = async ({ url }) => {
    const parsed = new URL(String(url || "https://example.com"));

    return {
      id: `scan_${Math.random().toString(36).slice(2, 10)}`,
      createdAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      sourceType: "website",
      verdict: "suspicious",
      riskScore: 32,
      file: {
        originalName: parsed.toString(),
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
          md5: crypto.createHash("md5").update(parsed.toString()).digest("hex"),
          sha1: crypto.createHash("sha1").update(parsed.toString()).digest("hex"),
          sha256: crypto.createHash("sha256").update(parsed.toString()).digest("hex")
        }
      },
      findings: [
        {
          id: "website_headers_missing",
          severity: "medium",
          category: "Headers",
          weight: 8,
          title: "Missing security headers",
          description: "The target is missing one or more recommended headers.",
          evidence: "content-security-policy"
        }
      ],
      recommendations: ["Harden missing headers and validate ownership before trust decisions."],
      plainLanguageReasons: ["The target is missing one or more recommended headers."],
      technicalIndicators: {
        missingSecurityHeaders: ["content-security-policy"]
      },
      websiteSafety: {
        score: 68,
        verdict: "suspicious",
        checkedAt: new Date().toISOString(),
        url: {
          input: parsed.toString(),
          normalized: parsed.toString(),
          final: parsed.toString(),
          hostname: parsed.hostname,
          protocol: parsed.protocol.replace(/:$/, "")
        },
        modules: {
          normalization: {
            input: parsed.toString(),
            normalized: parsed.toString()
          },
          dnsDomain: {
            status: "completed",
            ageDays: 150
          },
          ssl: {
            status: "completed",
            certIssuer: "Example CA"
          },
          headers: {
            status: "completed",
            missing: ["content-security-policy"]
          },
          content: {
            status: "completed",
            suspiciousKeywords: []
          },
          redirects: {
            status: "completed",
            count: 0,
            crossDomainCount: 0
          },
          reputation: {
            flagged: false,
            flaggedProviders: [],
            flaggedThreats: []
          },
          vulnerabilityChecks: {
            status: "completed",
            exposures: [],
            adminEndpoints: []
          }
        }
      },
      engines: {
        normalization: { status: "completed" },
        fetch: { status: "ok", statusCode: 200 },
        dnsDomain: { status: "completed" },
        ssl: { status: "completed" },
        headers: { status: "completed" },
        content: { status: "completed" },
        redirects: { status: "completed" },
        reputation: { status: "clean" },
        vulnerabilityChecks: { status: "completed" }
      },
      url: {
        input: parsed.toString(),
        normalized: parsed.toString(),
        final: parsed.toString(),
        protocol: parsed.protocol.replace(/:$/, ""),
        hostname: parsed.hostname
      }
    };
  };

  const { app } = await createApp({
    scanner: scanner || mockScanner,
    urlScanner: urlScanner || mockUrlScanner,
    websiteSafetyScanner: websiteSafetyScanner || mockWebsiteSafetyScanner,
    dataFilePath,
    configOverrides: {
      uploadDir,
      dataFilePath,
      enableClamAv: false,
      freeTierDailyScanLimit,
      requestsPerWindow: 5000,
      requestWindowMinutes: 15,
      jwtAccessSecret: "test-secret",
      logLevel: "silent",
      ...configOverrides
    }
  });

  return app;
}

export async function registerAndGetToken(app, email = "user@example.com", password = "StrongPass!123", name = "") {
  const username = String(name || "").trim() || email.split("@")[0] || "tester";
  const response = await request(app).post("/api/auth/register").send({
    email,
    password,
    name: username
  });

  expect(response.status).toBe(201);

  return {
    accessToken: response.body.accessToken,
    refreshToken: response.body.refreshToken,
    user: response.body.user
  };
}

export async function waitForJobCompletion(app, token, jobId, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const response = await request(app).get(`/api/scans/jobs/${jobId}`).set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);

    if (response.body.job.status === "completed" || response.body.job.status === "failed") {
      return response.body.job;
    }

    await new Promise((resolve) => setTimeout(resolve, 40));
  }

  throw new Error(`Job ${jobId} did not complete within timeout`);
}

export async function cleanupTestRoots() {
  const roots = tempRoots.splice(0);
  await Promise.all(
    roots.map(async (dir) => {
      for (let attempt = 0; attempt < 4; attempt += 1) {
        try {
          await fs.rm(dir, { recursive: true, force: true });
          return;
        } catch (error) {
          if (attempt === 3) {
            throw error;
          }
          await new Promise((resolve) => setTimeout(resolve, 50 * (attempt + 1)));
        }
      }
    })
  );
}
