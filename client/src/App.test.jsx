import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { SESSION_STORAGE_KEY } from "./appConfig";

function mockGuestStatus() {
  return new Response(
    JSON.stringify({
      quickScanEnabled: true,
      maxUploadMb: 8,
      message: ""
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }
  );
}

function createDashboardFetchMock({ notifications = [], analytics = null } = {}) {
  return vi.fn(async (input, init = {}) => {
    const url = String(input);
    const method = String(init?.method || "GET").toUpperCase();

    if (url.endsWith("/api/auth/me")) {
      return new Response(
        JSON.stringify({
          user: {
            username: "analyst_ops",
            name: "analyst_ops",
            email: "analyst@example.com",
            role: "user"
          },
          usage: {
            windowStartedAt: "2026-03-13T00:00:00.000Z",
            used: 1,
            remaining: 39,
            limit: 40
          },
          scanLimits: {
            maxFilesPerBatch: 10,
            maxUploadMb: 25
          },
          authMethod: "bearer"
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (url.includes("/api/scans/jobs")) {
      return new Response(JSON.stringify({ jobs: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/scans/reports")) {
      return new Response(JSON.stringify({ reports: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/scans/analytics")) {
      return new Response(
        JSON.stringify({
          analytics:
            analytics || {
              comparisonWindowDays: 30,
              summary: {
                totalJobs: 0,
                activeJobs: 0,
                queuedJobs: 0,
                processingJobs: 0,
                completedJobs: 0,
                failedJobs: 0,
                totalReports: 0,
                cleanReports: 0,
                suspiciousReports: 0,
                maliciousReports: 0,
                flaggedReports: 0,
                cleanRate: 0,
                averageRiskScore: 0,
                highestRiskScore: 0
              },
              windows: {
                current: {
                  reports: 0,
                  flaggedReports: 0,
                  cleanRate: 0,
                  averageRiskScore: 0,
                  failedJobs: 0
                },
                previous: {
                  reports: 0,
                  flaggedReports: 0,
                  cleanRate: 0,
                  averageRiskScore: 0,
                  failedJobs: 0
                }
              },
              timeSeries: [
                { month: "Oct", jobs: 0, reports: 0, flagged: 0 },
                { month: "Nov", jobs: 0, reports: 0, flagged: 0 }
              ],
              postureBreakdown: [
                { label: "Clean", value: 0 },
                { label: "Suspicious", value: 0 },
                { label: "Malicious", value: 0 }
              ],
              queueBreakdown: [
                { label: "Queued", value: 0 },
                { label: "Processing", value: 0 },
                { label: "Completed", value: 0 },
                { label: "Failed", value: 0 }
              ],
              riskDistribution: [
                { label: "0-24", value: 0 },
                { label: "25-49", value: 0 },
                { label: "50-74", value: 0 },
                { label: "75-100", value: 0 }
              ],
              fileTypeBreakdown: [],
              latestReport: null,
              highestRiskReport: null
            }
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (url.includes("/api/auth/api-keys")) {
      return new Response(JSON.stringify({ keys: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.endsWith("/api/auth/notifications/read") && method === "POST") {
      return new Response(JSON.stringify({ updated: 1 }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/auth/notifications")) {
      return new Response(
        JSON.stringify({
          notifications,
          unreadCount: notifications.filter((item) => !item.readAt).length
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (url.endsWith("/api/public/status")) {
      return mockGuestStatus();
    }

    throw new Error(`Unexpected fetch: ${method} ${url}`);
  });
}

function setDesktopMatchMedia(matches) {
  const originalMatchMedia = window.matchMedia;
  window.matchMedia = vi.fn().mockImplementation((query) => ({
    matches: query === "(min-width: 1024px)" ? matches : false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn()
  }));

  return () => {
    window.matchMedia = originalMatchMedia;
  };
}

describe("App", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
    window.history.replaceState({}, "", "/");
  });

  it("renders the landing route when no session exists", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input) => {
        const url = String(input);

        if (url.endsWith("/api/public/status")) {
          return mockGuestStatus();
        }

        throw new Error(`Unexpected fetch: ${url}`);
      })
    );

    render(<App />);

    expect(await screen.findByRole("heading", { name: /quick guest scan/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /create account/i })).toBeInTheDocument();
  });

  it("uses browser-friendly credential semantics on sign-in and sign-up routes", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input) => {
        const url = String(input);

        if (url.endsWith("/api/public/status")) {
          return mockGuestStatus();
        }

        if (url.includes("/api/auth/username-availability")) {
          return new Response(JSON.stringify({ available: true, suggestions: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        throw new Error(`Unexpected fetch: ${url}`);
      })
    );

    window.history.replaceState({}, "", "/signin");
    const { unmount } = render(<App />);

    const signInEmail = await screen.findByLabelText(/email address/i);
    expect(signInEmail).toHaveAttribute("name", "email");
    expect(signInEmail).toHaveAttribute("autocomplete", "username");
    expect(screen.getByRole("checkbox", { name: /remember me/i })).toBeChecked();

    unmount();
    window.history.replaceState({}, "", "/signup");
    render(<App />);

    const signUpUsername = await screen.findByLabelText(/^username$/i);
    const signUpEmail = screen.getByLabelText(/email address/i);
    expect(signUpUsername).toHaveAttribute("autocomplete", "nickname");
    expect(signUpEmail).toHaveAttribute("autocomplete", "username");
    expect(screen.getByLabelText(/^password$/i)).toHaveAttribute("autocomplete", "new-password");
  });

  it("shows confirmation modal when signup needs email verification", async () => {
    window.history.replaceState({}, "", "/signup");

    const fetchMock = vi.fn(async (input, init = {}) => {
      const url = String(input);
      const method = String(init?.method || "GET").toUpperCase();

      if (url.endsWith("/api/public/status")) {
        return mockGuestStatus();
      }

      if (url.includes("/api/auth/username-availability")) {
        return new Response(
          JSON.stringify({
            available: true,
            suggestions: []
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      if (url.endsWith("/api/auth/register") && method === "POST") {
        return new Response(
          JSON.stringify({
            requiresEmailConfirmation: true,
            email: "person@example.com",
            message: "Registration submitted. Confirm your email, then sign in."
          }),
          {
            status: 202,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    await userEvent.type(await screen.findByPlaceholderText(/your username/i), "tester");
    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.type(screen.getByLabelText(/^password$/i), "StrongPass!1234");
    await userEvent.type(screen.getByPlaceholderText(/confirm your password/i), "StrongPass!1234");
    await userEvent.click(screen.getByRole("button", { name: /^sign up$/i }));

    expect(await screen.findByRole("heading", { name: /account created\. verify your email\./i })).toBeInTheDocument();
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/verification sent to/i)).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: /sign in/i })).toBeInTheDocument();

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/auth/register"),
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("shows username suggestions when selected username is already taken", async () => {
    window.history.replaceState({}, "", "/signup");

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input) => {
        const url = String(input);

        if (url.endsWith("/api/public/status")) {
          return mockGuestStatus();
        }

        if (url.includes("/api/auth/username-availability")) {
          return new Response(
            JSON.stringify({
              available: false,
              suggestions: ["securitylead_secure", "securitylead_ops", "securitylead_2026"]
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" }
            }
          );
        }

        throw new Error(`Unexpected fetch: ${url}`);
      })
    );

    render(<App />);

    await userEvent.type(await screen.findByPlaceholderText(/your username/i), "securitylead");

    expect(await screen.findByText(/username is taken/i)).toBeInTheDocument();
    const suggestion = await screen.findByRole("button", { name: /securitylead_secure/i });
    await userEvent.click(suggestion);

    expect(screen.getByPlaceholderText(/your username/i)).toHaveValue("securitylead_secure");
  });

  it("renders reset-password route when a recovery token is present in the URL hash", async () => {
    window.history.replaceState({}, "", "/#type=recovery&access_token=recovery-token-abcdefghijklmnopqrstuvwxyz&email=person@example.com");

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input) => {
        const url = String(input);

        if (url.endsWith("/api/public/status")) {
          return mockGuestStatus();
        }

        return new Response(JSON.stringify({}), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      })
    );

    render(<App />);

    expect(await screen.findByRole("heading", { name: /set a new password/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /update password/i })).toBeInTheDocument();
  });

  it("renders the routed dashboard shell and keeps scan/settings workflows accessible", async () => {
    const restoreMatchMedia = setDesktopMatchMedia(true);
    window.history.replaceState({}, "", "/app/dashboard");

    localStorage.setItem(
      SESSION_STORAGE_KEY,
      JSON.stringify({
        accessToken: "access-token",
        refreshToken: "refresh-token",
        user: {
          username: "analyst_ops",
          name: "analyst_ops",
          email: "analyst@example.com",
          role: "user"
        },
        usage: null
      })
    );

    const fetchMock = createDashboardFetchMock({
      notifications: [
        {
          id: "notification_1",
          type: "report_ready",
          tone: "success",
          title: "Report ready",
          detail: "sample.txt finished scanning with a clean verdict.",
          createdAt: "2026-03-14T10:00:00.000Z",
          readAt: null
        }
      ]
    });

    vi.stubGlobal("fetch", fetchMock);

    try {
      render(<App />);

      expect(await screen.findByRole("heading", { name: /welcome back, analyst_ops/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /analytics/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /projects/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /history/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /view reports/i })).toBeInTheDocument();
      expect(screen.getByLabelText(/select scan files/i)).toHaveAttribute("multiple");
      expect(screen.queryByText(/automation access/i)).not.toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: /notifications/i }));
      expect(await screen.findByText(/sample\.txt finished scanning with a clean verdict\./i)).toBeInTheDocument();

      await userEvent.click(screen.getByRole("button", { name: /settings/i }));

      expect(await screen.findByText(/automation access/i)).toBeInTheDocument();
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("/api/auth/notifications/read"),
        expect.objectContaining({ method: "POST" })
      );
    } finally {
      restoreMatchMedia();
    }
  });

  it("opens the mobile navigation drawer from the hamburger menu", async () => {
    const restoreMatchMedia = setDesktopMatchMedia(false);
    window.history.replaceState({}, "", "/app/dashboard");

    localStorage.setItem(
      SESSION_STORAGE_KEY,
      JSON.stringify({
        accessToken: "access-token",
        refreshToken: "refresh-token",
        user: {
          username: "analyst_ops",
          name: "analyst_ops",
          email: "analyst@example.com",
          role: "user"
        },
        usage: null
      })
    );

    vi.stubGlobal("fetch", createDashboardFetchMock());

    try {
      render(<App />);

      expect(await screen.findByRole("heading", { name: /welcome back, analyst_ops/i })).toBeInTheDocument();

      const overlay = screen.getByLabelText(/close navigation/i);
      expect(overlay).toHaveAttribute("data-mobile-state", "closed");

      await userEvent.click(screen.getByRole("button", { name: /open navigation/i }));

      expect(overlay).toHaveAttribute("data-mobile-state", "open");
      expect(document.querySelector('aside[data-mobile-state="open"]')).not.toBeNull();
    } finally {
      restoreMatchMedia();
    }
  });

  it("renders analytics from stored values and shows zero states without placeholder counts", async () => {
    const restoreMatchMedia = setDesktopMatchMedia(true);
    window.history.replaceState({}, "", "/app/analytics");

    localStorage.setItem(
      SESSION_STORAGE_KEY,
      JSON.stringify({
        accessToken: "access-token",
        refreshToken: "refresh-token",
        user: {
          username: "analyst_ops",
          name: "analyst_ops",
          email: "analyst@example.com",
          role: "user"
        },
        usage: null
      })
    );

    const fetchMock = createDashboardFetchMock({
        analytics: {
          comparisonWindowDays: 30,
          summary: {
            totalJobs: 2,
            activeJobs: 1,
            queuedJobs: 1,
            processingJobs: 0,
            completedJobs: 1,
            failedJobs: 0,
            totalReports: 1,
            cleanReports: 1,
            suspiciousReports: 0,
            maliciousReports: 0,
            flaggedReports: 0,
            cleanRate: 100,
            averageRiskScore: 16,
            highestRiskScore: 16
          },
          windows: {
            current: {
              reports: 1,
              flaggedReports: 0,
              cleanRate: 100,
              averageRiskScore: 16,
              failedJobs: 0
            },
            previous: {
              reports: 0,
              flaggedReports: 0,
              cleanRate: 0,
              averageRiskScore: 0,
              failedJobs: 0
            }
          },
          timeSeries: [
            { month: "Jan", jobs: 1, reports: 1, flagged: 0 },
            { month: "Feb", jobs: 1, reports: 0, flagged: 0 }
          ],
          postureBreakdown: [
            { label: "Clean", value: 1 },
            { label: "Suspicious", value: 0 },
            { label: "Malicious", value: 0 }
          ],
          queueBreakdown: [
            { label: "Queued", value: 1 },
            { label: "Processing", value: 0 },
            { label: "Completed", value: 1 },
            { label: "Failed", value: 0 }
          ],
          riskDistribution: [
            { label: "0-24", value: 1 },
            { label: "25-49", value: 0 },
            { label: "50-74", value: 0 },
            { label: "75-100", value: 0 }
          ],
          fileTypeBreakdown: [{ label: "TXT", value: 1 }],
          latestReport: {
            id: "report_1",
            fileName: "sample.txt",
            verdict: "clean",
            riskScore: 16,
            completedAt: "2026-03-14T10:00:00.000Z"
          },
          highestRiskReport: {
            id: "report_1",
            fileName: "sample.txt",
            verdict: "clean",
            riskScore: 16,
            completedAt: "2026-03-14T10:00:00.000Z"
          }
        }
      });
    vi.stubGlobal("fetch", fetchMock);

    try {
      render(<App />);

      expect(await screen.findByText(/1 reports stored/i)).toBeInTheDocument();
      expect(screen.getByText(/reports stored/i)).toBeInTheDocument();
      expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("/api/scans/analytics"), expect.anything());
      expect(screen.queryByText(/^12$/)).not.toBeInTheDocument();
      expect(screen.queryByText(/^5$/)).not.toBeInTheDocument();
      expect(screen.queryByText(/^2$/)).not.toBeInTheDocument();
    } finally {
      restoreMatchMedia();
    }
  });
});
