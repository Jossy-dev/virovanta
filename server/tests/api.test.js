import fs from "fs/promises";
import os from "os";
import path from "path";
import crypto from "crypto";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../src/app/createApp.js";
import { hashSecret } from "../src/utils/security.js";

const tempRoots = [];

async function setupTestApp({ freeTierDailyScanLimit = 40, scanner = null } = {}) {
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

  const { app } = await createApp({
    scanner: scanner || mockScanner,
    dataFilePath,
    configOverrides: {
      uploadDir,
      dataFilePath,
      enableClamAv: false,
      freeTierDailyScanLimit,
      requestsPerWindow: 5000,
      requestWindowMinutes: 15,
      jwtAccessSecret: "test-secret",
      logLevel: "silent"
    }
  });

  return app;
}

async function registerAndGetToken(app, email = "user@example.com", password = "StrongPass!123", name = "") {
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

async function waitForJobCompletion(app, token, jobId, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const response = await request(app)
      .get(`/api/scans/jobs/${jobId}`)
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);

    if (response.body.job.status === "completed" || response.body.job.status === "failed") {
      return response.body.job;
    }

    await new Promise((resolve) => setTimeout(resolve, 40));
  }

  throw new Error(`Job ${jobId} did not complete within timeout`);
}

async function waitForNotification(app, token, matcher, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const response = await request(app)
      .get("/api/auth/notifications?limit=20")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);

    const notification = (response.body.notifications || []).find(matcher);
    if (notification) {
      return {
        notification,
        body: response.body
      };
    }

    await new Promise((resolve) => setTimeout(resolve, 40));
  }

  throw new Error("Notification did not arrive within timeout");
}

afterEach(async () => {
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
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
      }
    })
  );
});

describe("ViroVanta API", () => {
  it("allows guest quick scan without authentication", async () => {
    const app = await setupTestApp();

    const response = await request(app).post("/api/public/quick-scan").attach("file", Buffer.from("guest"), "guest.txt");

    expect(response.status).toBe(200);
    expect(response.body.mode).toBe("guest");
    expect(response.body.report).toBeTruthy();
    expect(response.body.report.file.originalName).toBe("guest.txt");
  });

  it("registers user and returns profile via bearer token", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app);

    const me = await request(app).get("/api/auth/me").set("Authorization", `Bearer ${session.accessToken}`);

    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe("user@example.com");
    expect(me.body.user.role).toBe("admin");
  });

  it("keeps the public health endpoint minimal", async () => {
    const app = await setupTestApp();

    const health = await request(app).get("/api/health");

    expect(health.status).toBe(200);
    expect(health.body.status).toBe("ok");
    expect(health.body.metrics).toBeUndefined();
    expect(health.body.capabilities).toBeUndefined();
  });

  it("checks username availability and blocks duplicate usernames", async () => {
    const app = await setupTestApp();
    await registerAndGetToken(app, "first@example.com", "StrongPass!123", "securitylead");

    const availability = await request(app).get("/api/auth/username-availability").query({
      username: "securitylead"
    });

    expect(availability.status).toBe(200);
    expect(availability.body.available).toBe(false);
    expect(Array.isArray(availability.body.suggestions)).toBe(true);
    expect(availability.body.suggestions.length).toBeGreaterThan(0);

    const duplicate = await request(app).post("/api/auth/register").send({
      email: "second@example.com",
      password: "StrongPass!123",
      name: "securitylead"
    });

    expect(duplicate.status).toBe(409);
    expect(duplicate.body.error.code).toBe("AUTH_USERNAME_EXISTS");
  });

  it("accepts forgot-password requests without revealing account existence", async () => {
    const app = await setupTestApp();
    await registerAndGetToken(app, "forgot@example.com");

    const knownEmail = await request(app).post("/api/auth/forgot-password").send({
      email: "forgot@example.com"
    });

    expect(knownEmail.status).toBe(202);
    expect(knownEmail.body.accepted).toBe(true);

    const unknownEmail = await request(app).post("/api/auth/forgot-password").send({
      email: "missing@example.com"
    });

    expect(unknownEmail.status).toBe(202);
    expect(unknownEmail.body.accepted).toBe(true);
  });

  it("resets password with a valid local reset token", async () => {
    const app = await setupTestApp();
    await registerAndGetToken(app, "reset@example.com", "StrongPass!123", "resetuser");

    const resetToken = "rst_local_reset_token_test_abcdefghijklmnopqrstuvwxyz";
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    await app.locals.services.store.write((state) => {
      const user = state.users.find((candidate) => candidate.email === "reset@example.com");
      if (!user) {
        throw new Error("Expected reset test user to exist");
      }

      user.passwordResetRequests = [
        {
          id: `pr_${crypto.randomUUID()}`,
          tokenHash: hashSecret(resetToken),
          expiresAt,
          usedAt: null,
          createdAt: new Date().toISOString()
        }
      ];
    });

    const reset = await request(app).post("/api/auth/reset-password").send({
      resetToken,
      password: "DifferentPass!456"
    });

    expect(reset.status).toBe(200);
    expect(reset.body.updated).toBe(true);

    const loginWithNewPassword = await request(app).post("/api/auth/login").send({
      email: "reset@example.com",
      password: "DifferentPass!456"
    });

    expect(loginWithNewPassword.status).toBe(200);
    expect(loginWithNewPassword.body.accessToken).toBeTruthy();
  });

  it("queues scan job and produces a report", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app);

    const submit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("harmless"), "sample.txt");

    expect(submit.status).toBe(202);
    expect(submit.body.job.status).toBe("queued");

    const finished = await waitForJobCompletion(app, session.accessToken, submit.body.job.id);
    expect(finished.status).toBe("completed");

    const reports = await request(app)
      .get("/api/scans/reports")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(reports.status).toBe(200);
    expect(reports.body.reports.length).toBeGreaterThan(0);
  });

  it("ties report and analytics access to the authenticated user account", async () => {
    const app = await setupTestApp({
      scanner: async ({ originalName, declaredMimeType }) => {
        const malicious = originalName.includes("mal");

        return {
          id: `scan_${Math.random().toString(36).slice(2, 10)}`,
          createdAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          verdict: malicious ? "malicious" : "clean",
          riskScore: malicious ? 91 : 5,
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
              md5: originalName,
              sha1: originalName,
              sha256: originalName
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
          recommendations: ["Review results"]
        };
      }
    });
    const owner = await registerAndGetToken(app, "owner@example.com");
    const outsider = await registerAndGetToken(app, "outsider@example.com");

    const ownerSubmit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${owner.accessToken}`)
      .attach("file", Buffer.from("owner"), "owner-mal.txt");

    const outsiderSubmit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${outsider.accessToken}`)
      .attach("file", Buffer.from("outsider"), "outsider-clean.txt");

    const ownerFinished = await waitForJobCompletion(app, owner.accessToken, ownerSubmit.body.job.id);
    await waitForJobCompletion(app, outsider.accessToken, outsiderSubmit.body.job.id);

    const forbiddenReport = await request(app)
      .get(`/api/scans/reports/${ownerFinished.reportId}`)
      .set("Authorization", `Bearer ${outsider.accessToken}`);

    expect(forbiddenReport.status).toBe(403);
    expect(forbiddenReport.body.error.code).toBe("SCAN_FORBIDDEN");

    const outsiderAnalytics = await request(app)
      .get("/api/scans/analytics")
      .set("Authorization", `Bearer ${outsider.accessToken}`);

    expect(outsiderAnalytics.status).toBe(200);
    expect(outsiderAnalytics.body.analytics.summary.totalReports).toBe(1);
    expect(outsiderAnalytics.body.analytics.summary.maliciousReports).toBe(0);
    expect(outsiderAnalytics.body.analytics.postureBreakdown).toEqual([
      { label: "Clean", value: 1 },
      { label: "Suspicious", value: 0 },
      { label: "Malicious", value: 0 }
    ]);
  });

  it("stores report-ready notifications and marks them as viewed", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app, "notify-report@example.com");

    const submit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("harmless"), "sample.txt");

    expect(submit.status).toBe(202);

    await waitForJobCompletion(app, session.accessToken, submit.body.job.id);

    const { notification, body } = await waitForNotification(
      app,
      session.accessToken,
      (candidate) => candidate.type === "report_ready"
    );

    expect(body.unreadCount).toBeGreaterThanOrEqual(1);
    expect(notification.title).toBe("Report ready");
    expect(notification.tone).toBe("success");
    expect(notification.detail).toMatch(/sample\.txt finished scanning/i);
    expect(notification.readAt).toBeNull();

    const markRead = await request(app)
      .post("/api/auth/notifications/read")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .send({});

    expect(markRead.status).toBe(200);
    expect(markRead.body.updated).toBeGreaterThanOrEqual(1);

    const afterRead = await request(app)
      .get("/api/auth/notifications?limit=20")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(afterRead.status).toBe(200);
    expect(afterRead.body.unreadCount).toBe(0);
    const storedNotification = afterRead.body.notifications.find((candidate) => candidate.id === notification.id);
    expect(storedNotification?.readAt).toBeTruthy();
  });

  it("queues multiple scan jobs in a single authenticated upload", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app, "batch@example.com");

    const submit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("files", Buffer.from("alpha"), "alpha.txt")
      .attach("files", Buffer.from("beta"), "beta.txt");

    expect(submit.status).toBe(202);
    expect(Array.isArray(submit.body.jobs)).toBe(true);
    expect(submit.body.jobs).toHaveLength(2);
    expect(submit.body.acceptedFiles).toBe(2);

    await Promise.all(submit.body.jobs.map((job) => waitForJobCompletion(app, session.accessToken, job.id)));

    const reports = await request(app)
      .get("/api/scans/reports")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(reports.status).toBe(200);
    expect(reports.body.reports.length).toBeGreaterThanOrEqual(2);
  });

  it("returns analytics from stored jobs and reports without placeholder verdict counts", async () => {
    const app = await setupTestApp({
      scanner: async ({ originalName, declaredMimeType }) => {
        const suspicious = originalName.includes("warn");

        return {
          id: `scan_${Math.random().toString(36).slice(2, 10)}`,
          createdAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          verdict: suspicious ? "suspicious" : "clean",
          riskScore: suspicious ? 58 : 8,
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
              md5: originalName,
              sha1: originalName,
              sha256: originalName
            }
          },
          findings: suspicious
            ? [
                {
                  id: "finding_warn",
                  title: "Suspicious pattern",
                  description: "Elevated suspicious indicators.",
                  evidence: "warn",
                  severity: "high"
                }
              ]
            : [],
          engines: {
            heuristics: {
              status: "completed",
              matchedRules: [],
              findingCount: suspicious ? 1 : 0
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
          recommendations: ["Review results"]
        };
      }
    });
    const session = await registerAndGetToken(app, "analytics@example.com");

    const first = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("alpha"), "alpha.txt");

    const second = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("warn"), "warn.txt");

    await waitForJobCompletion(app, session.accessToken, first.body.job.id);
    await waitForJobCompletion(app, session.accessToken, second.body.job.id);

    const analytics = await request(app)
      .get("/api/scans/analytics")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(analytics.status).toBe(200);
    expect(analytics.body.analytics.summary.totalReports).toBe(2);
    expect(analytics.body.analytics.summary.cleanReports).toBe(1);
    expect(analytics.body.analytics.summary.suspiciousReports).toBe(1);
    expect(analytics.body.analytics.summary.maliciousReports).toBe(0);
    expect(analytics.body.analytics.postureBreakdown).toEqual([
      { label: "Clean", value: 1 },
      { label: "Suspicious", value: 1 },
      { label: "Malicious", value: 0 }
    ]);
    expect(analytics.body.analytics.fileTypeBreakdown).toEqual([{ label: "TXT", value: 2 }]);
  });

  it("creates share links and adds known-file intelligence", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app, "intel@example.com");

    const firstSubmit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("same-content"), "same.txt");

    expect(firstSubmit.status).toBe(202);

    const firstFinished = await waitForJobCompletion(app, session.accessToken, firstSubmit.body.job.id);
    expect(firstFinished.status).toBe("completed");
    expect(firstFinished.reportId).toBeTruthy();

    const firstReportResponse = await request(app)
      .get(`/api/scans/reports/${firstFinished.reportId}`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(firstReportResponse.status).toBe(200);
    expect(firstReportResponse.body.report.intel.hashSeenBefore).toBe(false);
    expect(firstReportResponse.body.report.intel.previousMatches).toBe(0);

    const shareResponse = await request(app)
      .post(`/api/scans/reports/${firstFinished.reportId}/share`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(shareResponse.status).toBe(200);
    expect(shareResponse.body.publicApiPath).toContain("/api/public/shared-reports/");
    expect(shareResponse.body.shareToken).toBeTruthy();

    const sharedReport = await request(app).get(shareResponse.body.publicApiPath);
    expect(sharedReport.status).toBe(200);
    expect(sharedReport.body.shared).toBe(true);
    expect(sharedReport.body.report.id).toBe(firstFinished.reportId);
    expect(sharedReport.body.report.signature).toBeTruthy();
    expect(sharedReport.body.integrity?.valid).toBe(true);

    const secondSubmit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("same-content"), "same.txt");

    expect(secondSubmit.status).toBe(202);

    const secondFinished = await waitForJobCompletion(app, session.accessToken, secondSubmit.body.job.id);
    expect(secondFinished.status).toBe("completed");
    expect(secondFinished.reportId).toBeTruthy();

    const secondReportResponse = await request(app)
      .get(`/api/scans/reports/${secondFinished.reportId}`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(secondReportResponse.status).toBe(200);
    expect(secondReportResponse.body.report.intel.hashSeenBefore).toBe(true);
    expect(secondReportResponse.body.report.intel.previousMatches).toBeGreaterThanOrEqual(1);
  });

  it("signs reports and verifies integrity with IOC and MITRE ATT&CK enrichment", async () => {
    const app = await setupTestApp({
      scanner: async ({ originalName, declaredMimeType }) => ({
        id: `scan_${Math.random().toString(36).slice(2, 10)}`,
        createdAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        verdict: "suspicious",
        riskScore: 64,
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
            md5: "2f249230a8e7c2bf6005ccd2679259ec",
            sha1: "552f87f495d8ab90f2bc1618f90f2f9f17bb0f6f",
            sha256: "58ecf218d0ecf1052866f8ef89ea73385f24f6e53b39f5faca1581803fef6a62"
          }
        },
        findings: [
          {
            id: "encoded_powershell",
            title: "Encoded PowerShell execution pattern",
            description: "PowerShell downloader observed.",
            evidence: "powershell -enc aGVsbG8= https://bad.example.com 203.0.113.50 attacker@example.com",
            severity: "critical"
          }
        ],
        engines: {
          heuristics: {
            status: "completed",
            matchedRules: ["encoded_powershell"],
            findingCount: 1
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
        recommendations: ["Block bad.example.com at the gateway."]
      })
    });

    const session = await registerAndGetToken(app, "integrity@example.com");

    const submit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("intel"), "intel.txt");

    expect(submit.status).toBe(202);

    const finished = await waitForJobCompletion(app, session.accessToken, submit.body.job.id);
    expect(finished.status).toBe("completed");
    expect(finished.reportId).toBeTruthy();

    const reportResponse = await request(app)
      .get(`/api/scans/reports/${finished.reportId}`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(reportResponse.status).toBe(200);
    expect(reportResponse.body.report.signature).toBeTruthy();
    expect(reportResponse.body.report.iocs.urls).toContain("https://bad.example.com");
    expect(reportResponse.body.report.iocs.domains).toContain("bad.example.com");
    expect(reportResponse.body.report.iocs.ips).toContain("203.0.113.50");
    expect(reportResponse.body.report.iocs.emails).toContain("attacker@example.com");
    expect(reportResponse.body.report.attackMapping.techniques.some((item) => item.id === "T1059.001")).toBe(true);

    const integrityResponse = await request(app)
      .get(`/api/scans/reports/${finished.reportId}/integrity`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(integrityResponse.status).toBe(200);
    expect(integrityResponse.body.integrity.valid).toBe(true);

    await app.locals.services.store.write((state) => {
      const storedReport = state.reports.find((candidate) => candidate.id === finished.reportId);
      if (!storedReport) {
        throw new Error("Expected report to exist for tamper test");
      }

      storedReport.riskScore = 0;
    });

    const tamperedIntegrityResponse = await request(app)
      .get(`/api/scans/reports/${finished.reportId}/integrity`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(tamperedIntegrityResponse.status).toBe(200);
    expect(tamperedIntegrityResponse.body.integrity.valid).toBe(false);
    expect(tamperedIntegrityResponse.body.integrity.reason).toBe("payload_hash_mismatch");
  });

  it("enforces free-tier daily scan quota", async () => {
    const app = await setupTestApp({ freeTierDailyScanLimit: 1 });
    await registerAndGetToken(app, "admin-quota@example.com");
    const session = await registerAndGetToken(app, "quota-user@example.com");

    const first = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("one"), "one.txt");

    expect(first.status).toBe(202);

    const second = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("two"), "two.txt");

    expect(second.status).toBe(429);
    expect(second.body.error.code).toBe("SCAN_QUOTA_EXCEEDED");
  });

  it("rejects a batch upload that exceeds the remaining daily quota", async () => {
    const app = await setupTestApp({ freeTierDailyScanLimit: 1 });
    await registerAndGetToken(app, "admin-batch@example.com");
    const session = await registerAndGetToken(app, "batch-quota@example.com");

    const submit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("files", Buffer.from("first"), "first.txt")
      .attach("files", Buffer.from("second"), "second.txt");

    expect(submit.status).toBe(429);
    expect(submit.body.error.code).toBe("SCAN_QUOTA_EXCEEDED");
    expect(submit.body.error.details.requested).toBe(2);

    const notifications = await request(app)
      .get("/api/auth/notifications?limit=20")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(notifications.status).toBe(200);
    const quotaWarning = notifications.body.notifications.find((candidate) => candidate.type === "usage_limit_warning");
    expect(quotaWarning).toBeTruthy();
    expect(quotaWarning.title).toBe("Batch exceeds remaining usage");
    expect(quotaWarning.tone).toBe("warning");
  });

  it("recalculates usage from the last 24 hours when the user logs in", async () => {
    const app = await setupTestApp({ freeTierDailyScanLimit: 1 });
    await registerAndGetToken(app, "admin-rolling@example.com");
    const session = await registerAndGetToken(app, "rolling@example.com");

    const first = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("first"), "first.txt");

    expect(first.status).toBe(202);

    await waitForJobCompletion(app, session.accessToken, first.body.job.id);

    await app.locals.services.store.write((state) => {
      const agedTimestamp = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
      const job = state.jobs.find((candidate) => candidate.id === first.body.job.id);
      const user = state.users.find((candidate) => candidate.id === session.user.id);

      job.createdAt = agedTimestamp;
      user.usage = {
        windowStartedAt: new Date().toISOString(),
        scans: 99
      };
    });

    const me = await request(app).get("/api/auth/me").set("Authorization", `Bearer ${session.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.usage.used).toBe(0);
    expect(me.body.usage.remaining).toBe(1);

    const second = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("second"), "second.txt");

    expect(second.status).toBe(202);
    expect(second.body.quota.used).toBe(1);
  });

  it("supports API key auth and revocation", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app);

    const keyCreate = await request(app)
      .post("/api/auth/api-keys")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .send({ name: "automation" });

    expect(keyCreate.status).toBe(201);
    expect(keyCreate.body.apiKey).toContain("svk_");

    const apiKey = keyCreate.body.apiKey;

    const meWithApiKey = await request(app).get("/api/auth/me").set("x-api-key", apiKey);
    expect(meWithApiKey.status).toBe(200);
    expect(meWithApiKey.body.authMethod).toBe("api_key");

    await request(app)
      .delete(`/api/auth/api-keys/${keyCreate.body.metadata.id}`)
      .set("Authorization", `Bearer ${session.accessToken}`)
      .expect(204);

    const shouldFail = await request(app).get("/api/auth/me").set("x-api-key", apiKey);
    expect(shouldFail.status).toBe(401);
  });

  it("enforces API key scopes on scan endpoints", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app, "scopes@example.com");

    const submitWithBearer = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("scope-seed"), "scope-seed.txt");

    expect(submitWithBearer.status).toBe(202);
    await waitForJobCompletion(app, session.accessToken, submitWithBearer.body.job.id);

    const scopedKeyCreate = await request(app)
      .post("/api/auth/api-keys")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .send({
        name: "read-only-jobs",
        scopes: ["jobs:read"]
      });

    expect(scopedKeyCreate.status).toBe(201);
    expect(scopedKeyCreate.body.metadata.scopes).toEqual(["jobs:read"]);

    const listJobs = await request(app).get("/api/scans/jobs").set("x-api-key", scopedKeyCreate.body.apiKey);
    expect(listJobs.status).toBe(200);
    expect(Array.isArray(listJobs.body.jobs)).toBe(true);

    const submitWithApiKey = await request(app)
      .post("/api/scans/jobs")
      .set("x-api-key", scopedKeyCreate.body.apiKey)
      .attach("file", Buffer.from("scope-denied"), "scope-denied.txt");

    expect(submitWithApiKey.status).toBe(403);
    expect(submitWithApiKey.body.error.code).toBe("AUTH_API_KEY_SCOPE_REQUIRED");
    expect(submitWithApiKey.body.error.details.requiredScopes).toEqual(["jobs:write"]);
  });

  it("blocks API keys from account-management endpoints and marks sensitive responses as no-store", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app, "api-guard@example.com");

    const keyCreate = await request(app)
      .post("/api/auth/api-keys")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .send({ name: "automation" });

    expect(keyCreate.status).toBe(201);

    const apiKey = keyCreate.body.apiKey;

    const me = await request(app).get("/api/auth/me").set("Authorization", `Bearer ${session.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.headers["cache-control"]).toContain("no-store");

    const listKeysWithApiKey = await request(app).get("/api/auth/api-keys").set("x-api-key", apiKey);
    expect(listKeysWithApiKey.status).toBe(403);
    expect(listKeysWithApiKey.body.error.code).toBe("AUTH_METHOD_FORBIDDEN");

    const notificationsWithApiKey = await request(app).get("/api/auth/notifications").set("x-api-key", apiKey);
    expect(notificationsWithApiKey.status).toBe(403);
    expect(notificationsWithApiKey.body.error.code).toBe("AUTH_METHOD_FORBIDDEN");
  });

  it("creates a notification when an API key is generated", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app, "notify-key@example.com");

    const keyCreate = await request(app)
      .post("/api/auth/api-keys")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .send({ name: "automation" });

    expect(keyCreate.status).toBe(201);

    const notifications = await request(app)
      .get("/api/auth/notifications?limit=20")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(notifications.status).toBe(200);
    const apiKeyNotification = notifications.body.notifications.find((candidate) => candidate.type === "api_key_created");
    expect(apiKeyNotification).toBeTruthy();
    expect(apiKeyNotification.title).toBe("API key created");
    expect(apiKeyNotification.tone).toBe("info");
    expect(apiKeyNotification.detail).toContain("automation");
  });

  it("creates a notification when an API key is revoked", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app, "notify-revoke@example.com");

    const keyCreate = await request(app)
      .post("/api/auth/api-keys")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .send({ name: "temporary-access" });

    expect(keyCreate.status).toBe(201);

    const revoke = await request(app)
      .delete(`/api/auth/api-keys/${keyCreate.body.metadata.id}`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(revoke.status).toBe(204);

    const notifications = await request(app)
      .get("/api/auth/notifications?limit=20")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(notifications.status).toBe(200);
    const revokedNotification = notifications.body.notifications.find((candidate) => candidate.type === "api_key_revoked");
    expect(revokedNotification).toBeTruthy();
    expect(revokedNotification.title).toBe("API key revoked");
    expect(revokedNotification.tone).toBe("warning");
    expect(revokedNotification.detail).toContain("temporary-access");
  });

  it("creates a notification when a share link is generated", async () => {
    const app = await setupTestApp();
    const session = await registerAndGetToken(app, "notify-share@example.com");

    const submit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("shareable"), "shareable.txt");

    expect(submit.status).toBe(202);

    const finished = await waitForJobCompletion(app, session.accessToken, submit.body.job.id);
    expect(finished.status).toBe("completed");

    const share = await request(app)
      .post(`/api/scans/reports/${finished.reportId}/share`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(share.status).toBe(200);

    const notifications = await request(app)
      .get("/api/auth/notifications?limit=20")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(notifications.status).toBe(200);
    const shareNotification = notifications.body.notifications.find((candidate) => candidate.type === "report_share_created");
    expect(shareNotification).toBeTruthy();
    expect(shareNotification.title).toBe("Share link created");
    expect(shareNotification.tone).toBe("info");
    expect(shareNotification.detail).toContain("shareable.txt");
  });

  it("creates a warning notification when usage is almost exhausted", async () => {
    const app = await setupTestApp({ freeTierDailyScanLimit: 10 });
    await registerAndGetToken(app, "notify-admin@example.com");
    const session = await registerAndGetToken(app, "notify-usage@example.com");

    await app.locals.services.store.write((state) => {
      const now = new Date().toISOString();

      state.jobs.unshift(
        ...Array.from({ length: 7 }, (_, index) => ({
          id: `seed_job_${index + 1}`,
          userId: session.user.id,
          status: "completed",
          reportId: null,
          originalName: `seed-${index + 1}.txt`,
          createdAt: now,
          updatedAt: now,
          completedAt: now,
          size: 8,
          mimeType: "text/plain",
          storagePath: null,
          source: "upload"
        }))
      );
    });

    const quota = await app.locals.services.authService.consumeDailyQuota(session.user.id);

    expect(quota.allowed).toBe(true);
    expect(quota.remaining).toBe(2);

    const notifications = await request(app)
      .get("/api/auth/notifications?limit=20")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(notifications.status).toBe(200);
    const usageWarning = notifications.body.notifications.find((candidate) => candidate.type === "usage_limit_warning");
    expect(usageWarning).toBeTruthy();
    expect(usageWarning.title).toBe("Usage limit almost reached");
    expect(usageWarning.tone).toBe("warning");
    expect(usageWarning.detail).toContain("2 scans left");
  });

  it("creates a notification when a scan fails", async () => {
    const app = await setupTestApp({
      scanner: async () => {
        throw new Error("Scanner backend unavailable.");
      }
    });
    const session = await registerAndGetToken(app, "notify-failed-scan@example.com");

    const submit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("broken"), "broken.txt");

    expect(submit.status).toBe(202);

    const failed = await waitForJobCompletion(app, session.accessToken, submit.body.job.id);
    expect(failed.status).toBe("failed");

    const notifications = await request(app)
      .get("/api/auth/notifications?limit=20")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(notifications.status).toBe(200);
    const failedNotification = notifications.body.notifications.find((candidate) => candidate.type === "scan_failed");
    expect(failedNotification).toBeTruthy();
    expect(failedNotification.title).toBe("Scan failed");
    expect(failedNotification.tone).toBe("danger");
    expect(failedNotification.detail).toContain("broken.txt");
  });

  it("restricts admin endpoints to admin role", async () => {
    const app = await setupTestApp();
    const admin = await registerAndGetToken(app, "admin@example.com");
    const user = await registerAndGetToken(app, "user2@example.com");

    const forbidden = await request(app).get("/api/admin/metrics").set("Authorization", `Bearer ${user.accessToken}`);
    expect(forbidden.status).toBe(403);

    const allowed = await request(app).get("/api/admin/metrics").set("Authorization", `Bearer ${admin.accessToken}`);
    expect(allowed.status).toBe(200);
    expect(allowed.body.metrics.users).toBeGreaterThanOrEqual(2);
  });
});
