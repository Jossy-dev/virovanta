import { describe, expect, it, vi } from "vitest";
import { getFileScanEngineUsage, mergeCollectionById, parseErrorMessage, selectHighlightedJob, triggerBlobDownload } from "./appUtils";

describe("triggerBlobDownload", () => {
  it("keeps the object URL alive until after the browser click has been handed off", async () => {
    let cleanupCallback = null;
    const anchor = {
      click: vi.fn(),
      remove: vi.fn(),
      style: {}
    };
    const documentRef = {
      body: {
        appendChild: vi.fn()
      },
      createElement: vi.fn(() => anchor)
    };
    const urlApi = {
      createObjectURL: vi.fn(() => "blob:test-pdf"),
      revokeObjectURL: vi.fn()
    };
    const windowRef = {
      requestAnimationFrame: vi.fn((callback) => callback()),
      setTimeout: vi.fn((callback) => {
        cleanupCallback = callback;
        return 1;
      })
    };

    await triggerBlobDownload(new Blob(["pdf"]), "report.pdf", { documentRef, urlApi, windowRef });

    expect(documentRef.createElement).toHaveBeenCalledWith("a");
    expect(documentRef.body.appendChild).toHaveBeenCalledWith(anchor);
    expect(anchor.click).toHaveBeenCalledTimes(1);
    expect(urlApi.revokeObjectURL).not.toHaveBeenCalled();
    expect(windowRef.setTimeout).toHaveBeenCalledTimes(1);

    cleanupCallback?.();

    expect(anchor.remove).toHaveBeenCalledTimes(1);
    expect(urlApi.revokeObjectURL).toHaveBeenCalledWith("blob:test-pdf");
  });
});

describe("parseErrorMessage", () => {
  it("prefers field-level validation details over the generic payload error message", () => {
    const message = parseErrorMessage(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid request payload.",
          details: [{ path: "name", message: "Required" }]
        }
      },
      "Request failed"
    );

    expect(message).toBe("Name is required.");
  });

  it("formats non-required validation messages with the field label", () => {
    const message = parseErrorMessage(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid request payload.",
          details: [{ path: "targetType", message: "Invalid enum value. Expected 'url' | 'website'" }]
        }
      },
      "Request failed"
    );

    expect(message).toBe("Target Type: Invalid enum value. Expected 'url' | 'website'");
  });
});

describe("selectHighlightedJob", () => {
  it("keeps a pending active job highlighted when the jobs list has not caught up yet", () => {
    const activeJob = {
      id: "job_new_1",
      status: "queued",
      sourceType: "website"
    };
    const olderJob = {
      id: "job_old_1",
      status: "completed",
      sourceType: "url"
    };

    const highlighted = selectHighlightedJob([olderJob], activeJob);

    expect(highlighted).toEqual(activeJob);
  });
});

describe("mergeCollectionById", () => {
  it("merges updated items by id and keeps the newest entries first", () => {
    const merged = mergeCollectionById(
      [
        {
          id: "job_old",
          status: "queued",
          createdAt: "2026-03-16T18:08:06.410Z"
        },
        {
          id: "job_older",
          status: "completed",
          createdAt: "2026-03-15T10:00:00.000Z",
          completedAt: "2026-03-15T10:05:00.000Z"
        }
      ],
      [
        {
          id: "job_old",
          status: "completed",
          createdAt: "2026-03-16T18:08:06.410Z",
          completedAt: "2026-03-16T18:10:00.000Z"
        },
        {
          id: "job_new",
          status: "queued",
          createdAt: "2026-03-16T18:11:00.000Z"
        }
      ]
    );

    expect(merged.map((item) => item.id)).toEqual(["job_new", "job_old", "job_older"]);
    expect(merged.find((item) => item.id === "job_old")).toMatchObject({
      status: "completed",
      completedAt: "2026-03-16T18:10:00.000Z"
    });
  });
});

describe("getFileScanEngineUsage", () => {
  it("maps file scan engines to used and not-used badges", () => {
    const usage = getFileScanEngineUsage({
      sourceType: "file",
      engines: {
        clamav: {
          status: "clean"
        },
        yara: {
          status: "disabled"
        }
      }
    });

    expect(usage).toEqual([
      {
        label: "ClamAV",
        used: true,
        badge: "Used",
        detail: "ClamAV status: clean"
      },
      {
        label: "YARA",
        used: false,
        badge: "Not Used",
        detail: "YARA status: disabled"
      }
    ]);
  });

  it("returns no engine usage rows for URL-based reports", () => {
    expect(
      getFileScanEngineUsage({
        sourceType: "url",
        engines: {
          clamav: {
            status: "clean"
          }
        }
      })
    ).toEqual([]);
  });
});
