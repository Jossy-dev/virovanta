import { describe, expect, it, vi } from "vitest";
import { WorkspaceService } from "../src/services/workspaceService.js";

describe("WorkspaceService", () => {
  it("dispatches due monitors into the correct scan queues", async () => {
    const store = {
      claimDueMonitors: vi.fn(async () => [
        {
          id: "monitor_site",
          userId: "usr_1",
          targetType: "website",
          target: "https://portal.example.com",
          cadenceHours: 24
        },
        {
          id: "monitor_url",
          userId: "usr_2",
          targetType: "url",
          target: "https://login.example.com/reset",
          cadenceHours: 12
        }
      ])
    };
    const enqueueWebsiteSafetyScan = vi.fn(async ({ userId, url }) => ({ id: `job_site_${userId}`, targetUrl: url }));
    const enqueueUrlScan = vi.fn(async ({ userId, url }) => ({ id: `job_url_${userId}`, targetUrl: url }));
    const workspaceService = new WorkspaceService({
      store,
      config: {},
      logger: {
        warn: vi.fn()
      }
    });

    const result = await workspaceService.dispatchDueMonitors({
      limit: 5,
      enqueueUrlScan,
      enqueueWebsiteSafetyScan
    });

    expect(store.claimDueMonitors).toHaveBeenCalledWith(expect.objectContaining({ limit: 5 }));
    expect(enqueueWebsiteSafetyScan).toHaveBeenCalledWith({
      userId: "usr_1",
      url: "https://portal.example.com"
    });
    expect(enqueueUrlScan).toHaveBeenCalledWith({
      userId: "usr_2",
      url: "https://login.example.com/reset"
    });
    expect(result.claimed).toBe(2);
    expect(result.enqueued).toBe(2);
    expect(result.jobs).toHaveLength(2);
  });

  it("returns an empty result when no due monitors are available", async () => {
    const workspaceService = new WorkspaceService({
      store: {
        claimDueMonitors: vi.fn(async () => [])
      },
      config: {},
      logger: {
        warn: vi.fn()
      }
    });

    const result = await workspaceService.dispatchDueMonitors({
      limit: 3,
      enqueueUrlScan: vi.fn(),
      enqueueWebsiteSafetyScan: vi.fn()
    });

    expect(result).toEqual({
      claimed: 0,
      enqueued: 0,
      jobs: [],
      monitors: []
    });
  });

  it("pauses a monitor without scheduling another automatic run", async () => {
    const store = {
      findMonitorById: vi.fn(async () => ({
        id: "monitor_1",
        userId: "usr_1",
        cadenceHours: 24,
        status: "active",
        deletedAt: null
      })),
      updateMonitorStatus: vi.fn(async (input) => ({
        id: input.monitorId,
        userId: input.userId,
        cadenceHours: 24,
        status: input.status,
        nextCheckAt: input.nextCheckAt,
        deletedAt: null
      }))
    };
    const workspaceService = new WorkspaceService({
      store,
      config: {},
      logger: {
        warn: vi.fn()
      }
    });

    const monitor = await workspaceService.updateMonitorStatus("usr_1", "monitor_1", "paused");

    expect(store.updateMonitorStatus).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "usr_1",
        monitorId: "monitor_1",
        status: "paused",
        nextCheckAt: null
      })
    );
    expect(monitor.status).toBe("paused");
    expect(monitor.nextCheckAt).toBeNull();
  });

  it("resumes a paused monitor with a fresh next check time", async () => {
    const store = {
      findMonitorById: vi.fn(async () => ({
        id: "monitor_1",
        userId: "usr_1",
        cadenceHours: 12,
        status: "paused",
        deletedAt: null
      })),
      updateMonitorStatus: vi.fn(async (input) => ({
        id: input.monitorId,
        userId: input.userId,
        cadenceHours: 12,
        status: input.status,
        nextCheckAt: input.nextCheckAt,
        deletedAt: null
      }))
    };
    const workspaceService = new WorkspaceService({
      store,
      config: {},
      logger: {
        warn: vi.fn()
      }
    });

    const beforeResumeMs = Date.now();
    const monitor = await workspaceService.updateMonitorStatus("usr_1", "monitor_1", "active");
    const resumedNextCheckMs = Date.parse(monitor.nextCheckAt);

    expect(store.updateMonitorStatus).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "usr_1",
        monitorId: "monitor_1",
        status: "active"
      })
    );
    expect(Number.isFinite(resumedNextCheckMs)).toBe(true);
    expect(resumedNextCheckMs).toBeGreaterThan(beforeResumeMs);
    expect(monitor.status).toBe("active");
  });
});
