import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { WebsiteSafetyView } from "./WebsiteSafetyView";

const PENDING_WEBSITE_JOB = Object.freeze({
  id: "job_site_1",
  sourceType: "website",
  status: "processing",
  createdAt: "2026-06-09T11:00:00.000Z",
  startedAt: "2026-06-09T11:00:04.000Z",
  completedAt: null,
  progressPercent: 42,
  progressStage: "Collecting website evidence",
  progressDetail: "Running DNS, TLS, header, and content checks.",
  originalName: "https://portal.example.com",
  fileSize: 0,
  targetUrl: "https://portal.example.com",
  reportId: null,
  errorMessage: null
});

function renderWebsiteSafetyView(props = {}) {
  return render(
    <WebsiteSafetyView
      searchQuery=""
      jobs={[PENDING_WEBSITE_JOB]}
      reports={[]}
      activeReport={null}
      isSubmittingScan={false}
      onSubmitWebsiteSafetyScan={vi.fn(async () => {})}
      onCancelJob={vi.fn(async () => {})}
      onOpenReport={vi.fn(async () => {})}
      onDownloadReportPdf={vi.fn(async () => {})}
      formatDateTime={(value) => `formatted:${value}`}
      formatVerdictLabel={(value) => value}
      {...props}
    />
  );
}

describe("WebsiteSafetyView", () => {
  it("shows queue progress for pending website jobs and supports cancellation", async () => {
    const user = userEvent.setup();
    const onCancelJob = vi.fn(async () => {});

    renderWebsiteSafetyView({ onCancelJob });

    expect(screen.getByText(/collecting website evidence/i)).toBeInTheDocument();
    expect(screen.getByText(/42%/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^cancel$/i }));

    await waitFor(() => {
      expect(onCancelJob).toHaveBeenCalledWith("job_site_1");
    });
  });
});
