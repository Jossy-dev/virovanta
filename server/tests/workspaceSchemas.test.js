import { describe, expect, it } from "vitest";
import { createMonitorSchema, updateMonitorStatusSchema } from "../src/validation/workspaceSchemas.js";

describe("createMonitorSchema", () => {
  it("requires a website target when creating a website monitor", () => {
    const result = createMonitorSchema.safeParse({
      name: "Vendor monitor",
      targetType: "website",
      target: "",
      cadenceHours: 24,
      notes: ""
    });

    expect(result.success).toBe(false);
    expect(result.error.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ["target"],
          message: "Website target is required."
        })
      ])
    );
  });

  it("reports an invalid website target as a URL problem instead of a character-count problem", () => {
    const result = createMonitorSchema.safeParse({
      name: "Vendor monitor",
      targetType: "website",
      target: "not a website",
      cadenceHours: 24,
      notes: ""
    });

    expect(result.success).toBe(false);
    expect(result.error.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ["target"],
          message: "Enter a valid website URL or hostname."
        })
      ])
    );
  });

  it("rejects single-word text that is not a real hostname or website endpoint", () => {
    const result = createMonitorSchema.safeParse({
      name: "Vendor monitor",
      targetType: "website",
      target: "hello",
      cadenceHours: 24,
      notes: ""
    });

    expect(result.success).toBe(false);
    expect(result.error.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ["target"],
          message: "Enter a valid website URL or hostname."
        })
      ])
    );
  });

  it("accepts hostnames without an explicit scheme", () => {
    const result = createMonitorSchema.safeParse({
      name: "Vendor monitor",
      targetType: "website",
      target: "vendor.example.com",
      cadenceHours: 24,
      notes: ""
    });

    expect(result.success).toBe(true);
  });
});

describe("updateMonitorStatusSchema", () => {
  it("allows pausing and resuming monitors only", () => {
    expect(updateMonitorStatusSchema.safeParse({ status: "paused" }).success).toBe(true);
    expect(updateMonitorStatusSchema.safeParse({ status: "active" }).success).toBe(true);
    expect(updateMonitorStatusSchema.safeParse({ status: "deleted" }).success).toBe(false);
  });
});
