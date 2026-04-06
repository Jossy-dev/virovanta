import { describe, expect, it } from "vitest";
import { buildWorkspaceEntitlements, createDefaultWorkspaceProfile } from "../src/utils/workspaceEntitlements.js";

describe("workspace entitlements", () => {
  it("falls back to plan defaults when override fields are unset", () => {
    const profile = createDefaultWorkspaceProfile("usr_test");
    const entitlements = buildWorkspaceEntitlements(profile, {}, new Date("2026-03-30T00:00:00.000Z"));

    expect(entitlements.planId).toBe("free");
    expect(entitlements.limits.apiKeys).toBe(3);
    expect(entitlements.limits.monitors).toBe(3);
    expect(entitlements.limits.webhooks).toBe(1);
    expect(entitlements.limits.retentionDays).toBe(90);
  });

  it("honors explicit non-negative overrides when present", () => {
    const entitlements = buildWorkspaceEntitlements(
      {
        ...createDefaultWorkspaceProfile("usr_test"),
        apiKeyLimitOverride: 8,
        monitorLimitOverride: 12,
        webhookLimitOverride: 4,
        retentionDaysOverride: 180
      },
      {},
      new Date("2026-03-30T00:00:00.000Z")
    );

    expect(entitlements.limits.apiKeys).toBe(8);
    expect(entitlements.limits.monitors).toBe(12);
    expect(entitlements.limits.webhooks).toBe(4);
    expect(entitlements.limits.retentionDays).toBe(180);
  });
});
