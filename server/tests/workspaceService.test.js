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
});
