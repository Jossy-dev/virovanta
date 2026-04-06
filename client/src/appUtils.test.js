import { describe, expect, it, vi } from "vitest";
import { triggerBlobDownload } from "./appUtils";

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
