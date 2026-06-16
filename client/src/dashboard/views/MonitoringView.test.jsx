import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { MonitoringView } from "./MonitoringView";

const BASE_MONITOR = Object.freeze({
  id: "monitor_1",
  name: "Vendor login monitor",
  targetType: "website",
  target: "https://portal.example.com/login",
  cadenceHours: 24,
  status: "active",
  lastVerdict: null,
  lastRiskScore: null,
  lastChangeSummary: [],
  nextCheckAt: "2026-06-10T08:00:00.000Z",
  deletedAt: null
});

function renderMonitoringView(props = {}) {
  return render(
    <MonitoringView
      monitors={[BASE_MONITOR]}
      workspaceSummary={{
        entitlements: {
          limits: {
            monitors: 3
          }
        }
      }}
      isCreatingMonitor={false}
      onCreateMonitor={vi.fn(async () => {})}
      onRunMonitor={vi.fn(async () => {})}
      onUpdateMonitorStatus={vi.fn(async () => {})}
      onDeleteMonitor={vi.fn(async () => {})}
      formatDateTime={(value) => `formatted:${value}`}
      {...props}
    />
  );
}

describe("MonitoringView", () => {
  it("asks for confirmation before deleting a monitor", async () => {
    const user = userEvent.setup();
    const onDeleteMonitor = vi.fn(async () => {});
    renderMonitoringView({ onDeleteMonitor });

    await user.click(screen.getAllByRole("button", { name: /^delete$/i })[0]);

    expect(onDeleteMonitor).not.toHaveBeenCalled();

    const dialog = screen.getByRole("dialog", { name: /delete monitor/i });
    expect(within(dialog).getByText(/stop future re-alert checks/i)).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: /delete monitor/i }));

    await waitFor(() => {
      expect(onDeleteMonitor).toHaveBeenCalledWith("monitor_1");
    });
  });

  it("shows a subtle loading state on run now while the request is in flight", async () => {
    const user = userEvent.setup();
    let resolveRun = null;
    const onRunMonitor = vi.fn(
      () =>
        new Promise((resolve) => {
          resolveRun = resolve;
        })
    );

    renderMonitoringView({ onRunMonitor });

    await user.click(screen.getAllByRole("button", { name: /run now/i })[0]);

    expect(onRunMonitor).toHaveBeenCalledWith("monitor_1");
    expect(screen.getAllByRole("button", { name: /running/i })[0]).toBeDisabled();

    resolveRun?.();

    await waitFor(() => {
      expect(screen.getAllByRole("button", { name: /run now/i })[0]).not.toBeDisabled();
    });
  });

  it("lets analysts pause a monitor from the list", async () => {
    const user = userEvent.setup();
    const onUpdateMonitorStatus = vi.fn(async () => {});
    renderMonitoringView({ onUpdateMonitorStatus });

    await user.click(screen.getAllByRole("button", { name: /^pause$/i })[0]);

    await waitFor(() => {
      expect(onUpdateMonitorStatus).toHaveBeenCalledWith("monitor_1", "paused");
    });
  });
});
