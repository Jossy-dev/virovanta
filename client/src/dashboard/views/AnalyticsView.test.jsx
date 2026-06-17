import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AnalyticsView } from "./AnalyticsView";

function renderAnalyticsView() {
  return render(
    <AnalyticsView
      analytics={{
        comparisonWindowDays: 30,
        summary: {
          totalReports: 6,
          cleanRate: 66.6,
          averageRiskScore: 34,
          failedJobs: 1
        },
        windows: {
          current: {
            reports: 4,
            cleanRate: 75,
            averageRiskScore: 30,
            failedJobs: 1
          },
          previous: {
            reports: 2,
            cleanRate: 50,
            averageRiskScore: 40,
            failedJobs: 0
          }
        },
        postureBreakdown: [
          { label: "Clean", value: 4 },
          { label: "Unknown", value: 0 },
          { label: "Suspicious", value: 2 },
          { label: "Malicious", value: 0 }
        ],
        queueBreakdown: [
          { label: "Queued", value: 2 },
          { label: "Processing", value: 1 },
          { label: "Completed", value: 5 },
          { label: "Failed", value: 1 }
        ],
        timeSeries: [
          { month: "Jan", jobs: 1, reports: 1, flagged: 0 },
          { month: "Feb", jobs: 2, reports: 1, flagged: 1 }
        ],
        fileTypeBreakdown: [],
        latestReport: null,
        highestRiskReport: null
      }}
      formatDateTime={(value) => String(value || "")}
      themePalette={{
        pie: ["#1f8f5c", "#f59e0b", "#2563eb", "#dc2626"],
        primary: "#1f8f5c",
        grid: "#e2e8f0",
        axis: "#64748b"
      }}
      onSelectPosture={() => {}}
    />
  );
}

describe("AnalyticsView", () => {
  it("shows a visible queue outcome color key", () => {
    renderAnalyticsView();

    expect(screen.getByText(/accepted and waiting for an available worker/i)).toBeInTheDocument();
    expect(screen.getByText(/actively scanning or finishing an in-flight check/i)).toBeInTheDocument();
    expect(screen.getByText(/finished successfully and saved as a report/i)).toBeInTheDocument();
    expect(screen.getByText(/stopped before a report could be completed/i)).toBeInTheDocument();
  });
});
