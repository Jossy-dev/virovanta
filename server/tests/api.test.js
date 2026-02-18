import fs from "fs/promises";
import os from "os";
import path from "path";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../src/app/createApp.js";

const tempRoots = [];

async function setupTestApp({ freeTierDailyScanLimit = 40 } = {}) {
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
    scanner: mockScanner,
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

async function registerAndGetToken(app, email = "user@example.com", password = "StrongPass!123") {
  const response = await request(app).post("/api/auth/register").send({
    email,
    password,
    name: "Tester"
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
