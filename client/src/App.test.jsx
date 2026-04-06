import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

function createDashboardFetchMock({
  notifications = [],
  analytics = null,
  jobs = [],
  reports = [],
  reportDetailsById = {},
  monitors = [],
  webhooks = [],
  webhookDeliveries = [],
  auditEvents = [],
  userId = "user_1",
  onUrlResolve = null,
  onUrlScanSubmit = null
} = {}) {
  return vi.fn(async (input, init = {}) => {
    const url = String(input);
    const method = String(init?.method || "GET").toUpperCase();
    const relativeUrl = url.startsWith("http") ? new URL(url).pathname + new URL(url).search : url;

    if (url.endsWith("/api/auth/me")) {
      return new Response(
        JSON.stringify({
          user: {
            id: userId,
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
          workspace: {
            profile: {
              planId: "free",
              effectivePlanId: "free",
              planName: "Free",
              headline: "Best for individual evaluation and lightweight triage"
            },
            trial: {
              status: "available",
              trialPlanId: "pro",
              trialStartedAt: null,
              trialEndsAt: null,
              trialDays: 14
            },
            billing: {
              provider: null,
              customerId: null,
              subscriptionId: null,
              status: "not_configured"
            },
            entitlements: {
              limits: {
                dailyScans: 40,
                monitors: 3,
                webhooks: 1,
                apiKeys: 3,
                shareTtlHours: 72,
                retentionDays: 90
              },
              features: {
                comments: true,
                workflow: true,
                monitoring: true,
                webhooks: true
              }
            },
            usage: {
              scans: {
                windowStartedAt: "2026-03-13T00:00:00.000Z",
                used: 1,
                remaining: 39,
                limit: 40
              },
              monitorsActive: monitors.length,
              webhooksActive: webhooks.length,
              apiKeysActive: 0
            },
            upgradePath: {
              recommendedPlanId: "pro",
              trialAvailable: true
            }
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

    if (url.includes("/api/workspace/summary")) {
      return new Response(
        JSON.stringify({
          workspace: {
            profile: {
              planId: "free",
              effectivePlanId: "free",
              planName: "Free",
              headline: "Best for individual evaluation and lightweight triage"
            },
            trial: {
              status: "available",
              trialPlanId: "pro",
              trialStartedAt: null,
              trialEndsAt: null,
              trialDays: 14
            },
            billing: {
              provider: null,
              customerId: null,
              subscriptionId: null,
              status: "not_configured"
            },
            entitlements: {
              limits: {
                dailyScans: 40,
                monitors: 3,
                webhooks: 1,
                apiKeys: 3,
                shareTtlHours: 72,
                retentionDays: 90
              },
              features: {
                comments: true,
                workflow: true,
                monitoring: true,
                webhooks: true
              }
            },
            usage: {
              scans: {
                windowStartedAt: "2026-03-13T00:00:00.000Z",
                used: 1,
                remaining: 39,
                limit: 40
              },
              monitorsActive: monitors.length,
              webhooksActive: webhooks.length,
              apiKeysActive: 0
            },
            upgradePath: {
              recommendedPlanId: "pro",
              trialAvailable: true
            }
          }
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (url.includes("/api/workspace/monitors")) {
      return new Response(JSON.stringify({ monitors }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/workspace/webhooks/deliveries")) {
      return new Response(JSON.stringify({ deliveries: webhookDeliveries }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/workspace/webhooks")) {
      return new Response(JSON.stringify({ webhooks }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/workspace/audit")) {
      return new Response(JSON.stringify({ events: auditEvents }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/scans/jobs")) {
      return new Response(JSON.stringify({ jobs }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/scans/links/resolve") && method === "POST") {
      const body = init?.body ? JSON.parse(init.body) : {};
      onUrlResolve?.(body);

      return new Response(
        JSON.stringify({
          resolution: {
            inputMode: "message",
            primaryUrl: "https://secure-billing.example.com/login/reset",
            extracted: true,
            candidateCount: 2,
            source: "explicit",
            candidates: [
              {
                rank: 1,
                url: "https://secure-billing.example.com/login/reset",
                hostname: "secure-billing.example.com",
                source: "explicit",
                score: 86,
                isPrimary: true
              },
              {
                rank: 2,
                url: "https://news.example.com/unsubscribe",
                hostname: "news.example.com",
                source: "explicit",
                score: 18,
                isPrimary: false
              }
            ]
          }
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (url.includes("/api/scans/links/jobs") && method === "POST") {
      const body = init?.body ? JSON.parse(init.body) : {};
      onUrlScanSubmit?.(body);

      return new Response(
        JSON.stringify({
          job: {
            id: "job_url_message_1",
            sourceType: "url",
            status: "queued",
            createdAt: "2026-03-16T18:08:06.410Z",
            startedAt: null,
            completedAt: null,
            originalName: Array.isArray(body?.urls) ? body.urls[0] : "https://secure-billing.example.com/login/reset",
            fileSize: 0,
            targetUrl: Array.isArray(body?.urls) ? body.urls[0] : "https://secure-billing.example.com/login/reset",
            reportId: null,
            errorMessage: null
          },
          jobs: Array.isArray(body?.urls)
            ? body.urls.map((targetUrl, index) => ({
                id: `job_url_message_${index + 1}`,
                sourceType: "url",
                status: "queued",
                createdAt: "2026-03-16T18:08:06.410Z",
                startedAt: null,
                completedAt: null,
                originalName: targetUrl,
                fileSize: 0,
                targetUrl,
                reportId: null,
                errorMessage: null
              }))
            : undefined,
          acceptedUrls: Array.isArray(body?.urls) ? body.urls.length : 1,
          quota: {
            allowed: true,
            limit: 40,
            used: Array.isArray(body?.urls) ? 8 : 7,
            remaining: Array.isArray(body?.urls) ? 32 : 33,
            windowStartedAt: "2026-03-15T19:18:06.304Z"
          },
          extracted: body?.message
            ? {
                url: "https://secure-billing.example.com/login/reset",
                candidateCount: 1,
                source: "explicit"
              }
            : null
        }),
        {
          status: 202,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (url.includes("/api/scans/reports/")) {
      if (url.includes("/workflow")) {
        return new Response(
          JSON.stringify({
            workflow: {
              id: "workflow_report_1",
              reportId: "report_1",
              ownerUserId: userId,
              caseStatus: "new",
              severity: "medium",
              assigneeLabel: "",
              clientLabel: "",
              recommendedAction: "",
              notesSummary: "",
              createdAt: "2026-03-16T18:08:06.410Z",
              updatedAt: "2026-03-16T18:08:06.410Z",
              lastCommentedAt: null
            },
            comments: [],
            shares: []
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      const reportId = url.split("/api/scans/reports/")[1]?.split("?")[0] || "";
      const detailedReport = reportDetailsById[reportId] || null;
      if (!detailedReport) {
        return new Response(
          JSON.stringify({
            error: {
              code: "SCAN_REPORT_NOT_FOUND",
              message: "Scan report not found."
            }
          }),
          {
            status: 404,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      return new Response(JSON.stringify({ report: detailedReport }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (url.includes("/api/scans/reports")) {
      return new Response(JSON.stringify({ reports }), {
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
      const requestUrl = relativeUrl.startsWith("/") ? new URL(`http://localhost${relativeUrl}`) : new URL(relativeUrl);
      const limit = Number(requestUrl.searchParams.get("limit") || 20);
      const offset = Number(requestUrl.searchParams.get("offset") || 0);
      const safeLimit = Math.max(1, Math.min(100, Number.isFinite(limit) ? limit : 20));
      const safeOffset = Math.max(0, Number.isFinite(offset) ? offset : 0);
      const pagedNotifications = notifications.slice(safeOffset, safeOffset + safeLimit);

      return new Response(
        JSON.stringify({
          notifications: pagedNotifications,
          unreadCount: notifications.filter((item) => !item.readAt).length,
          totalCount: notifications.length,
          limit: safeLimit,
          offset: safeOffset,
          hasMore: safeOffset + safeLimit < notifications.length
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
    expect(screen.getAllByRole("link", { name: /sign in/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("link", { name: /create account/i }).length).toBeGreaterThan(0);
  });

  it("renders indexable marketing routes as public pages", async () => {
    window.history.replaceState({}, "", "/features");

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

    expect(await screen.findByRole("heading", { name: /features built for practical file triage/i })).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /how it works/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("link", { name: /security/i }).length).toBeGreaterThan(0);
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

  it("blocks signup on submit when the final username check finds a duplicate", async () => {
    window.history.replaceState({}, "", "/signup");

    const registerSpy = vi.fn();
    const fetchMock = vi.fn(async (input, init = {}) => {
      const url = String(input);
      const method = String(init?.method || "GET").toUpperCase();

      if (url.endsWith("/api/public/status")) {
        return mockGuestStatus();
      }

      if (url.includes("/api/auth/username-availability")) {
        return new Response(
          JSON.stringify({
            available: false,
            suggestions: ["analyst_guard", "analyst_ops", "analyst_delta"]
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      if (url.endsWith("/api/auth/register") && method === "POST") {
        registerSpy();
        return new Response(JSON.stringify({}), {
          status: 201,
          headers: { "Content-Type": "application/json" }
        });
      }

      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    await userEvent.type(await screen.findByLabelText(/^username$/i), "analyst");
    await userEvent.type(screen.getByLabelText(/email address/i), "analyst@example.com");
    await userEvent.type(screen.getByLabelText(/^password$/i), "StrongPass!1234");
    await userEvent.type(screen.getByPlaceholderText(/confirm your password/i), "StrongPass!1234");
    await userEvent.click(screen.getByRole("button", { name: /^sign up$/i }));

    expect(await screen.findByText(/username is taken\. pick one of the suggestions\./i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /analyst_guard/i })).toBeInTheDocument();
    expect(registerSpy).not.toHaveBeenCalled();
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

  it("routes signup confirmation callbacks to sign in instead of reset password", async () => {
    window.history.replaceState({}, "", "/#type=signup&access_token=signup-token-abcdefghijklmnopqrstuvwxyz&email=person@example.com");

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

    expect(await screen.findByRole("heading", { name: /^sign in$/i })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /set a new password/i })).not.toBeInTheDocument();
    expect(screen.getByLabelText(/email address/i)).toHaveValue("person@example.com");
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

  it("submits pasted phishing-style messages through the URL scan intake", async () => {
    const restoreMatchMedia = setDesktopMatchMedia(true);
    window.history.replaceState({}, "", "/app/projects");

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

    let resolvedBody = null;
    let submittedBody = null;
    const fetchMock = createDashboardFetchMock({
      onUrlResolve: (body) => {
        resolvedBody = body;
      },
      onUrlScanSubmit: (body) => {
        submittedBody = body;
      }
    });

    vi.stubGlobal("fetch", fetchMock);

    try {
      render(<App />);

      const intakeField = await screen.findByLabelText(/suspicious link or pasted message/i);
      fireEvent.change(intakeField, {
        target: {
          value: "Please review immediately at hxxps[:]//secure-billing[.]example.com/login/reset"
        }
      });
      await userEvent.click(screen.getByRole("button", { name: /extract & queue scan/i }));

      expect(await screen.findByRole("dialog", { name: /choose suspicious links to scan/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /^scan all$/i })).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: /^scan all$/i }));

      await waitFor(() => {
        expect(resolvedBody).toEqual({
          message: "Please review immediately at hxxps[:]//secure-billing[.]example.com/login/reset"
        });
        expect(submittedBody).toEqual({
          urls: ["https://secure-billing.example.com/login/reset", "https://news.example.com/unsubscribe"]
        });
      });
    } finally {
      restoreMatchMedia();
    }
  });

  it("switches the chooser CTA from Scan All to Scan when some extracted links are deselected", async () => {
    const restoreMatchMedia = setDesktopMatchMedia(true);
    window.history.replaceState({}, "", "/app/projects");

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

    let submittedBody = null;
    const fetchMock = createDashboardFetchMock({
      onUrlScanSubmit: (body) => {
        submittedBody = body;
      }
    });

    vi.stubGlobal("fetch", fetchMock);

    try {
      render(<App />);

      const intakeField = await screen.findByLabelText(/suspicious link or pasted message/i);
      fireEvent.change(intakeField, {
        target: {
          value: "Review at hxxps[:]//secure-billing[.]example.com/login/reset or https://news.example.com/unsubscribe"
        }
      });
      await userEvent.click(screen.getByRole("button", { name: /extract & queue scan/i }));

      const dialog = await screen.findByRole("dialog", { name: /choose suspicious links to scan/i });
      const candidateRows = within(dialog).getAllByRole("checkbox");
      await userEvent.click(candidateRows[1]);

      expect(within(dialog).getByRole("button", { name: /^scan$/i })).toBeInTheDocument();

      await userEvent.click(within(dialog).getByRole("button", { name: /^scan$/i }));

      await waitFor(() => {
        expect(submittedBody).toEqual({
          url: "https://secure-billing.example.com/login/reset"
        });
      });
    } finally {
      restoreMatchMedia();
    }
  });

  it("refetches a detailed report when cached history restores only a summary payload", async () => {
    const restoreMatchMedia = setDesktopMatchMedia(true);
    const userId = "user_1";
    const dashboardCacheKey = `${SESSION_STORAGE_KEY}-dashboard-cache`;
    const reportSummary = {
      id: "report_1",
      sourceType: "file",
      createdAt: "2026-03-18T09:58:00.000Z",
      completedAt: "2026-03-18T10:00:00.000Z",
      verdict: "suspicious",
      riskScore: 72,
      fileName: "IMG_6121.heic",
      fileSize: 1235664,
      findingCount: 1,
      topFinding: "Malware family match",
      intel: null,
      iocCount: 1
    };
    const detailedReport = {
      id: "report_1",
      sourceType: "file",
      createdAt: "2026-03-18T09:58:00.000Z",
      completedAt: "2026-03-18T10:00:00.000Z",
      verdict: "suspicious",
      riskScore: 72,
      file: {
        originalName: "IMG_6121.heic",
        size: 1235664,
        type: "image/heic",
        hashes: {
          sha256: "abcd1234"
        }
      },
      findings: [
        {
          id: "finding_1",
          title: "Malware family match",
          severity: "high",
          description: "The uploaded file matches a known suspicious sample.",
          evidence: "sha256:abcd1234"
        }
      ],
      recommendations: ["Quarantine the file before opening it."],
      intel: null,
      iocs: {
        total: 1
      }
    };

    window.history.replaceState({}, "", "/app/history");

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

    localStorage.setItem(
      dashboardCacheKey,
      JSON.stringify({
        version: 1,
        userId,
        cachedAtMs: Date.now(),
        jobs: [],
        reports: [reportSummary],
        notifications: [],
        apiKeys: [],
        analytics: null,
        activeReport: reportSummary
      })
    );

    const fetchMock = createDashboardFetchMock({
      userId,
      reports: [reportSummary],
      reportDetailsById: {
        report_1: detailedReport
      }
    });

    vi.stubGlobal("fetch", fetchMock);

    try {
      render(<App />);

      expect(await screen.findByRole("heading", { name: /scan history/i })).toBeInTheDocument();
      expect(await screen.findByRole("heading", { name: /img_6121\.heic/i })).toBeInTheDocument();
      expect(await screen.findByText(/quarantine the file before opening it\./i)).toBeInTheDocument();

      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("/api/scans/reports/report_1"), expect.anything());
      });
    } finally {
      restoreMatchMedia();
    }
  });

  it("limits dropdown notifications to three and paginates older items in the see-all panel", async () => {
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

    const notifications = Array.from({ length: 10 }, (_value, index) => ({
      id: `notification_${index + 1}`,
      type: "report_ready",
      tone: "success",
      title: `Report ${index + 1} ready`,
      detail: `Notification detail ${String(index + 1).padStart(2, "0")}`,
      createdAt: `2026-03-${String(index + 1).padStart(2, "0")}T10:00:00.000Z`,
      readAt: null
    }));

    const fetchMock = createDashboardFetchMock({ notifications });
    vi.stubGlobal("fetch", fetchMock);

    try {
      render(<App />);

      expect(await screen.findByRole("heading", { name: /welcome back, analyst_ops/i })).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: /notifications/i }));

      expect(await screen.findByText(/notification detail 01/i)).toBeInTheDocument();
      expect(screen.getByText(/notification detail 02/i)).toBeInTheDocument();
      expect(screen.getByText(/notification detail 03/i)).toBeInTheDocument();
      expect(screen.queryByText(/notification detail 04/i)).not.toBeInTheDocument();

      await userEvent.click(screen.getByRole("button", { name: /see all notifications/i }));

      expect(await screen.findByRole("dialog", { name: /all notifications/i })).toBeInTheDocument();
      expect(await screen.findByText(/notification detail 08/i)).toBeInTheDocument();
      expect(screen.queryByText(/notification detail 09/i)).not.toBeInTheDocument();

      await userEvent.click(screen.getByRole("button", { name: /next/i }));
      expect(await screen.findByText(/notification detail 09/i)).toBeInTheDocument();
      expect(screen.getByText(/notification detail 10/i)).toBeInTheDocument();
      expect(screen.queryByText(/notification detail 01/i)).not.toBeInTheDocument();
    } finally {
      restoreMatchMedia();
    }
  });

  it("shows website-safety queued jobs inside the results list and removes the duplicate jobs section", async () => {
    const restoreMatchMedia = setDesktopMatchMedia(true);
    window.history.replaceState({}, "", "/app/website-safety");

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
      jobs: [
        {
          id: "job_web_1",
          sourceType: "website",
          status: "processing",
          createdAt: "2026-03-17T10:10:00.000Z",
          startedAt: "2026-03-17T10:10:04.000Z",
          completedAt: null,
          originalName: "https://pending.virovanta.test",
          fileSize: 0,
          targetUrl: "https://pending.virovanta.test",
          reportId: null,
          errorMessage: null
        }
      ],
      reports: []
    });
    vi.stubGlobal("fetch", fetchMock);

    try {
      render(<App />);

      expect(await screen.findByRole("heading", { name: /analyze web application safety posture/i })).toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: /website safety jobs/i })).not.toBeInTheDocument();
      expect(screen.getByRole("heading", { name: /website safety reports/i })).toBeInTheDocument();
      expect(screen.getByText(/https:\/\/pending\.virovanta\.test/i)).toBeInTheDocument();
      expect(screen.getByText(/^processing$/i)).toBeInTheDocument();
    } finally {
      restoreMatchMedia();
    }
  });

  it("creates API keys with the selected scope set from settings", async () => {
    const restoreMatchMedia = setDesktopMatchMedia(true);
    window.history.replaceState({}, "", "/app/settings");

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

    const fetchMock = vi.fn(async (input, init = {}) => {
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
            analytics: {
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
              timeSeries: [],
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

      if (url.includes("/api/auth/api-keys") && method === "GET") {
        return new Response(JSON.stringify({ keys: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.includes("/api/auth/api-keys") && method === "POST") {
        return new Response(
          JSON.stringify({
            apiKey: "svk_test.visible_once",
            metadata: {
              id: "key_1",
              name: "Scoped Integration",
              keyPrefix: "svk_test",
              scopes: ["jobs:read", "reports:read"],
              createdAt: "2026-03-15T11:00:00.000Z",
              lastUsedAt: null,
              revokedAt: null
            }
          }),
          {
            status: 201,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      if (url.includes("/api/auth/notifications")) {
        return new Response(
          JSON.stringify({
            notifications: [],
            unreadCount: 0
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

    vi.stubGlobal("fetch", fetchMock);

    try {
      render(<App />);

      expect(await screen.findByText(/automation access/i)).toBeInTheDocument();

      const keyNameInput = screen.getByLabelText(/key name/i);
      await userEvent.clear(keyNameInput);
      await userEvent.type(keyNameInput, "Scoped Integration");

      const jobsWriteOption = screen.getByRole("checkbox", { name: /jobs write/i });
      expect(jobsWriteOption).toBeChecked();
      await userEvent.click(jobsWriteOption);
      expect(jobsWriteOption).not.toBeChecked();

      await userEvent.click(screen.getByRole("button", { name: /create api key/i }));

      expect(await screen.findByText(/api key created successfully/i)).toBeInTheDocument();
      expect(screen.getByText(/copy and store this key now/i)).toBeInTheDocument();

      const postCall = fetchMock.mock.calls.find(([url, init]) => {
        return String(url).includes("/api/auth/api-keys") && String(init?.method || "GET").toUpperCase() === "POST";
      });

      expect(postCall).toBeTruthy();
      const requestBody = JSON.parse(String(postCall[1].body || "{}"));
      expect(requestBody.name).toBe("Scoped Integration");
      expect(requestBody.scopes).toContain("jobs:read");
      expect(requestBody.scopes).not.toContain("jobs:write");
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
