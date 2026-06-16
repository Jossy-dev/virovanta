import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ProjectsView } from "./ProjectsView";

const BASE_JOB = Object.freeze({
  id: "job_1",
  sourceType: "file",
  status: "processing",
  createdAt: "2026-06-09T10:00:00.000Z",
  startedAt: "2026-06-09T10:00:05.000Z",
  completedAt: null,
  progressPercent: 48,
  progressStage: "Running file heuristics",
  progressDetail: "Inspecting file type, hashes, and scan engine findings.",
  originalName: "invoice-review.pdf",
  fileSize: 128000,
  targetUrl: null,
  reportId: null,
  errorMessage: null
});

function renderProjectsView(props = {}) {
  return render(
    <ProjectsView
      selectedFiles={[]}
      searchQuery=""
      maxFilesPerBatch={10}
      maxUploadMb={25}
      quotaText="39 scans remaining"
      isSubmittingScan={false}
      onSelectFiles={vi.fn()}
      onSubmitScan={vi.fn()}
      onResolveUrlScanTargets={vi.fn(async () => null)}
      onSubmitUrlScans={vi.fn(async () => [])}
      onClearSelectedFiles={vi.fn()}
      onCancelJob={vi.fn(async () => {})}
      jobs={[BASE_JOB]}
      activeJob={BASE_JOB}
      onOpenReportWorkspace={vi.fn()}
      formatDateTime={(value) => `formatted:${value}`}
      formatBytes={(value) => `${value} bytes`}
      pluralize={(label, count) => `${count} ${label}${count === 1 ? "" : "s"}`}
      {...props}
    />
  );
}

describe("ProjectsView", () => {
  it("shows queue progress details and lets analysts cancel a pending job", async () => {
    const user = userEvent.setup();
    const onCancelJob = vi.fn(async () => {});

    renderProjectsView({ onCancelJob });

    expect(screen.getAllByText(/running file heuristics/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/48%/i).length).toBeGreaterThan(0);

    await user.click(screen.getAllByRole("button", { name: /^cancel$/i })[0]);

    await waitFor(() => {
      expect(onCancelJob).toHaveBeenCalledWith("job_1");
    });
  });
});
