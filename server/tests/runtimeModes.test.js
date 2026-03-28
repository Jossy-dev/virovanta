import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { cleanupTestRoots, registerAndGetToken, setupTestApp } from "./helpers/testApp.js";

afterEach(async () => {
  await cleanupTestRoots();
});

describe("runtime modes and readiness", () => {
  it("reports ready in the default combined local mode", async () => {
    const app = await setupTestApp();

    const readiness = await request(app).get("/api/health/ready");

    expect(readiness.status).toBe(200);
    expect(readiness.body.ready).toBe(true);
    expect(readiness.body.mode).toBe("all");
    expect(readiness.body.components.queue.provider).toBe("local");
    expect(readiness.body.components.queue.ready).toBe(true);
    expect(readiness.body.components.store.driver).toBe("file");
    expect(readiness.body.components.rateLimit.store).toBe("memory");
  });

  it("reports worker-only readiness when running without the API server role", async () => {
    const app = await setupTestApp({
      configOverrides: {
        runApiServer: false,
        runScanWorker: true
      }
    });

    const readiness = await request(app).get("/api/health/ready");

    expect(readiness.status).toBe(200);
    expect(readiness.body.ready).toBe(true);
    expect(readiness.body.mode).toBe("worker");
    expect(readiness.body.components.queue.workerEnabled).toBe(true);
  });

  it("surfaces queue startup failures in API-only BullMQ mode", async () => {
    const app = await setupTestApp({
      configOverrides: {
        runApiServer: true,
        runScanWorker: false,
        queueProvider: "bullmq",
        redisUrl: ""
      }
    });

    await new Promise((resolve) => setTimeout(resolve, 20));

    const readiness = await request(app).get("/api/health/ready");

    expect(readiness.status).toBe(503);
    expect(readiness.body.ready).toBe(false);
    expect(readiness.body.mode).toBe("api");
    expect(readiness.body.components.queue.provider).toBe("bullmq");
    expect(readiness.body.components.queue.status).toBe("degraded");
    expect(readiness.body.alerts.some((alert) => alert.component === "queue")).toBe(true);
  });

  it("rejects Redis-backed rate limiting so Redis stays queue-only", async () => {
    await expect(
      setupTestApp({
        configOverrides: {
          rateLimitStore: "redis",
          redisUrl: "redis://localhost:6379"
        }
      })
    ).rejects.toThrow(/Redis is reserved for BullMQ scan queue traffic only/i);
  });

  it("rejects dedicated BullMQ worker modes unless split topology is enabled", async () => {
    await expect(
      setupTestApp({
        configOverrides: {
          queueProvider: "bullmq",
          redisUrl: "redis://localhost:6379",
          objectStorageProvider: "s3",
          runApiServer: false,
          runScanWorker: true,
          scanWorkerMode: "file",
          bullmqQueueTopology: "single"
        }
      })
    ).rejects.toThrow(/BULLMQ_QUEUE_TOPOLOGY=split/i);
  });

  it("includes runtime details in admin metrics for operational monitoring", async () => {
    const app = await setupTestApp();
    const admin = await registerAndGetToken(app, "admin-monitor@example.com", "StrongPass!123", "admin");

    const metrics = await request(app).get("/api/admin/metrics").set("Authorization", `Bearer ${admin.accessToken}`);

    expect(metrics.status).toBe(200);
    expect(metrics.body.metrics.users).toBeGreaterThanOrEqual(1);
    expect(metrics.body.runtime.mode).toBe("all");
    expect(metrics.body.runtime.components.queue.ready).toBe(true);
    expect(metrics.body.runtime.components.store.ready).toBe(true);
  });
});
