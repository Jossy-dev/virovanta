export function cn(...classes) {
  return classes.filter(Boolean).join(" ");
}

function createMonthBuckets(count = 6) {
  const today = new Date();
  const buckets = [];

  for (let index = count - 1; index >= 0; index -= 1) {
    buckets.push(new Date(today.getFullYear(), today.getMonth() - index, 1));
  }

  return buckets;
}

export function formatCompactNumber(value) {
  return new Intl.NumberFormat(undefined, {
    notation: "compact",
    maximumFractionDigits: 1
  }).format(Number(value) || 0);
}

export function formatPercent(value) {
  return `${Number(value || 0).toFixed(1)}%`;
}

export function createEmptyAnalytics() {
  return {
    generatedAt: "",
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
    timeSeries: createMonthBuckets(6).map((date) => ({
      month: new Intl.DateTimeFormat(undefined, { month: "short" }).format(date),
      reports: 0,
      flagged: 0,
      jobs: 0
    })),
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
  };
}

export function getInitials(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return "VV";
  }

  if (raw.includes("@")) {
    return raw
      .split("@")[0]
      .split(/[._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part.charAt(0).toUpperCase())
      .join("");
  }

  return raw
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part.charAt(0).toUpperCase())
    .join("");
}

export function filterCollection(items, query, keys) {
  const normalizedQuery = String(query || "").trim().toLowerCase();
  if (!normalizedQuery) {
    return items;
  }

  return items.filter((item) =>
    keys.some((key) => {
      const value = typeof key === "function" ? key(item) : item?.[key];
      return String(value || "").toLowerCase().includes(normalizedQuery);
    })
  );
}

export function paginate(items, page, pageSize) {
  const safePageSize = Math.max(1, Number(pageSize) || 1);
  const totalPages = Math.max(1, Math.ceil(items.length / safePageSize));
  const safePage = Math.min(Math.max(1, Number(page) || 1), totalPages);
  const startIndex = (safePage - 1) * safePageSize;

  return {
    page: safePage,
    totalPages,
    items: items.slice(startIndex, startIndex + safePageSize)
  };
}

export function buildAnalyticsData(snapshot) {
  const empty = createEmptyAnalytics();
  if (!snapshot || typeof snapshot !== "object") {
    return empty;
  }

  return {
    ...empty,
    ...snapshot,
    summary: {
      ...empty.summary,
      ...(snapshot.summary || {})
    },
    windows: {
      current: {
        ...empty.windows.current,
        ...(snapshot.windows?.current || {})
      },
      previous: {
        ...empty.windows.previous,
        ...(snapshot.windows?.previous || {})
      }
    },
    timeSeries: Array.isArray(snapshot.timeSeries) && snapshot.timeSeries.length > 0 ? snapshot.timeSeries : empty.timeSeries,
    postureBreakdown:
      Array.isArray(snapshot.postureBreakdown) && snapshot.postureBreakdown.length > 0
        ? snapshot.postureBreakdown
        : empty.postureBreakdown,
    queueBreakdown:
      Array.isArray(snapshot.queueBreakdown) && snapshot.queueBreakdown.length > 0 ? snapshot.queueBreakdown : empty.queueBreakdown,
    riskDistribution:
      Array.isArray(snapshot.riskDistribution) && snapshot.riskDistribution.length > 0
        ? snapshot.riskDistribution
        : empty.riskDistribution,
    fileTypeBreakdown:
      Array.isArray(snapshot.fileTypeBreakdown) && snapshot.fileTypeBreakdown.length > 0
        ? snapshot.fileTypeBreakdown
        : empty.fileTypeBreakdown,
    latestReport: snapshot.latestReport || null,
    highestRiskReport: snapshot.highestRiskReport || null
  };
}

export function buildActivityRows({ jobs, reports, session }) {
  const email = session?.user?.email || "workspace@virovanta.com";
  const activity = [
    ...(jobs || []).map((job) => ({
      id: `job-${job.id}`,
      user: email,
      action: `Queued ${job.originalName}`,
      status: job.status,
      date: job.createdAt
    })),
    ...(reports || []).map((report) => ({
      id: `report-${report.id}`,
      user: email,
      action: `Report completed for ${report.fileName}`,
      status: report.verdict,
      date: report.completedAt || report.createdAt
    }))
  ].sort((left, right) => new Date(right.date || 0).getTime() - new Date(left.date || 0).getTime());

  if (activity.length > 0) {
    return activity;
  }

  const now = Date.now();
  return [
    {
      id: "seed-1",
      user: email,
      action: "Created workspace baseline dashboard",
      status: "completed",
      date: new Date(now - 35 * 60 * 1000).toISOString()
    },
    {
      id: "seed-2",
      user: "ops@virovanta.com",
      action: "Reviewed onboarding traffic source mix",
      status: "active",
      date: new Date(now - 2 * 60 * 60 * 1000).toISOString()
    },
    {
      id: "seed-3",
      user: "intel@virovanta.com",
      action: "Published workspace trend snapshot",
      status: "completed",
      date: new Date(now - 5 * 60 * 60 * 1000).toISOString()
    }
  ];
}

export function buildWidgetCollections({ jobs, reports, apiKeys }) {
  const pendingJobs = (jobs || []).filter((job) => job.status === "queued" || job.status === "processing").length;
  const flaggedReports = (reports || []).filter((report) => report.verdict !== "clean").length;
  const newestReport = reports?.[0];

  return {
    tasks: [
      {
        id: "task-1",
        title: pendingJobs > 0 ? `${pendingJobs} queued jobs need review` : "No queued jobs waiting",
        detail: pendingJobs > 0 ? "Open the project queue and confirm priority order." : "Queue health is stable.",
        tone: pendingJobs > 0 ? "warning" : "success"
      },
      {
        id: "task-2",
        title: flaggedReports > 0 ? `${flaggedReports} flagged reports need triage` : "No flagged reports in the latest set",
        detail: flaggedReports > 0 ? "Review suspicious and malicious verdicts from the reports view." : "Threat posture is clear.",
        tone: flaggedReports > 0 ? "critical" : "success"
      },
      {
        id: "task-3",
        title: apiKeys.length > 0 ? "Audit active API keys this week" : "Create your first API key",
        detail: apiKeys.length > 0 ? "Verify integrations still need their current access." : "Automation can be enabled from settings.",
        tone: "neutral"
      }
    ],
    notifications: [
      {
        id: "note-1",
        title: newestReport ? `${newestReport.fileName} finished scanning` : "No reports have been generated yet",
        detail: newestReport ? "Latest analysis is available in reports." : "Upload files from the projects view to begin.",
        tone: newestReport ? "neutral" : "warning"
      },
      {
        id: "note-2",
        title: apiKeys.length > 0 ? `${apiKeys.length} active API key${apiKeys.length === 1 ? "" : "s"}` : "No API keys configured",
        detail: apiKeys.length > 0 ? "Automation endpoints remain enabled." : "Create keys when integrations are ready.",
        tone: "neutral"
      }
    ],
    events: [
      {
        id: "event-1",
        title: "Retention window updated",
        detail: "Reports now stay available for 30 days when runtime env is aligned.",
        tone: "success"
      },
      {
        id: "event-2",
        title: "Usage limits run on a rolling 24-hour window",
        detail: "Quota is now based on real scan timestamps instead of calendar resets.",
        tone: "neutral"
      }
    ]
  };
}

export function buildTeamRows({ session, jobs, reports }) {
  const userEmail = session?.user?.email || "analyst@virovanta.com";
  const storedUsername = String(session?.user?.username || session?.user?.name || "").trim();
  const fallbackUserName = userEmail.split("@")[0].replace(/[._-]+/g, " ");
  const riskyReports = (reports || []).filter((report) => report.verdict !== "clean").length;
  const queuePressure = (jobs || []).filter((job) => job.status !== "completed").length;

  return [
    {
      id: "team-1",
      name: storedUsername || fallbackUserName.replace(/\b\w/g, (char) => char.toUpperCase()),
      email: userEmail,
      role: session?.user?.role === "admin" ? "Workspace Admin" : "Security Analyst",
      status: "Active",
      lastSeen: "Just now"
    },
    {
      id: "team-2",
      name: "Signal Review",
      email: "signal@virovanta.com",
      role: "Threat Triage",
      status: riskyReports > 0 ? "Reviewing" : "Monitoring",
      lastSeen: `${Math.max(1, riskyReports)} alerts ago`
    },
    {
      id: "team-3",
      name: "Automation Queue",
      email: "queue@virovanta.com",
      role: "Workflow Runner",
      status: queuePressure > 0 ? "Busy" : "Idle",
      lastSeen: queuePressure > 0 ? "1 min ago" : "12 min ago"
    }
  ];
}
