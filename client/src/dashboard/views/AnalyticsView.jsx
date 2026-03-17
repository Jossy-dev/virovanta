import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { Activity, AlertTriangle, FileBarChart2, ShieldCheck } from "lucide-react";
import { MetricCard } from "../components/MetricCard";
import { ChartCard } from "../components/ChartCard";
import { WidgetCard } from "../components/WidgetCard";
import { formatCompactNumber, formatPercent } from "../dashboardUtils";

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) {
    return null;
  }

  return (
    <div className="dashboard-tooltip">
      {label ? <p className="mb-1 text-xs font-semibold text-slate-950 dark:text-white">{label}</p> : null}
      <div className="space-y-1">
        {payload.map((entry) => (
          <div key={entry.dataKey || entry.name} className="flex items-center justify-between gap-4">
            <span className="text-slate-500 dark:text-slate-400">{entry.name}</span>
            <span className="font-semibold text-slate-900 dark:text-white">{entry.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ChartEmptyState({ message }) {
  return (
    <div className="flex h-[280px] items-center justify-center rounded-3xl border border-dashed border-slate-200/90 bg-slate-50/80 px-6 text-center text-sm leading-7 text-slate-500 dark:border-slate-800/80 dark:bg-slate-950/40 dark:text-slate-400 sm:h-[320px]">
      {message}
    </div>
  );
}

function sumValues(items) {
  return (items || []).reduce((sum, item) => sum + (Number(item?.value) || 0), 0);
}

function buildDeltaMeta(currentValue, previousValue, { higherIsBetter = true } = {}) {
  const current = Number(currentValue) || 0;
  const previous = Number(previousValue) || 0;

  if (previous === 0 && current === 0) {
    return {
      delta: "0.0%",
      trend: "flat",
      tone: "neutral"
    };
  }

  if (previous === 0) {
    return {
      delta: "New",
      trend: current > 0 ? "up" : "flat",
      tone: current > 0 ? (higherIsBetter ? "positive" : "negative") : "neutral"
    };
  }

  const change = ((current - previous) / previous) * 100;
  if (Math.abs(change) < 0.05) {
    return {
      delta: "0.0%",
      trend: "flat",
      tone: "neutral"
    };
  }

  const increasing = change > 0;

  return {
    delta: `${increasing ? "+" : ""}${change.toFixed(1)}%`,
    trend: increasing ? "up" : "down",
    tone: increasing ? (higherIsBetter ? "positive" : "negative") : higherIsBetter ? "negative" : "positive"
  };
}

function formatRiskScore(value) {
  return `${Math.round(Number(value) || 0)}/100`;
}

function normalizeVerdictLabel(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();

  if (normalized === "clean" || normalized === "suspicious" || normalized === "malicious") {
    return normalized;
  }

  return "";
}

export function AnalyticsView({ analytics, formatDateTime, themePalette, onSelectPosture = () => {} }) {
  const comparisonWindowDays = Number(analytics?.comparisonWindowDays) || 30;
  const summary = analytics?.summary || {};
  const windows = analytics?.windows || {};
  const currentWindow = windows.current || {};
  const previousWindow = windows.previous || {};
  const postureTotal = sumValues(analytics?.postureBreakdown);
  const queueTotal = sumValues(analytics?.queueBreakdown);
  const activityTotal = (analytics?.timeSeries || []).reduce(
    (sum, bucket) => sum + (Number(bucket?.jobs) || 0) + (Number(bucket?.reports) || 0),
    0
  );
  const topFileTypes = Array.isArray(analytics?.fileTypeBreakdown) ? analytics.fileTypeBreakdown : [];
  const latestReport = analytics?.latestReport || null;
  const highestRiskReport = analytics?.highestRiskReport || null;

  const metrics = [
    {
      id: "reports-stored",
      title: "Reports stored",
      value: formatCompactNumber(summary.totalReports),
      description: "Completed reports retained in your history",
      ...buildDeltaMeta(currentWindow.reports, previousWindow.reports)
    },
    {
      id: "clean-rate",
      title: "Clean rate",
      value: formatPercent(summary.cleanRate),
      description: "Share of stored reports marked clean",
      ...buildDeltaMeta(currentWindow.cleanRate, previousWindow.cleanRate)
    },
    {
      id: "average-risk",
      title: "Average risk",
      value: formatRiskScore(summary.averageRiskScore),
      description: "Mean risk score across stored reports",
      ...buildDeltaMeta(currentWindow.averageRiskScore, previousWindow.averageRiskScore, { higherIsBetter: false })
    },
    {
      id: "failed-jobs",
      title: "Failed jobs",
      value: formatCompactNumber(summary.failedJobs),
      description: "Jobs that ended without a report",
      ...buildDeltaMeta(currentWindow.failedJobs, previousWindow.failedJobs, { higherIsBetter: false })
    }
  ];

  return (
    <div className="space-y-6">
      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={FileBarChart2} {...metrics[0]} />
        <MetricCard icon={ShieldCheck} {...metrics[1]} />
        <MetricCard icon={AlertTriangle} {...metrics[2]} />
        <MetricCard icon={Activity} {...metrics[3]} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.2fr_1fr]">
        <ChartCard
          title="Scan activity"
          subtitle="Jobs created and reports completed"
          action={<span className="dashboard-label">Last 6 months</span>}
        >
          {activityTotal === 0 ? (
            <ChartEmptyState message="No scan or report activity has been recorded yet." />
          ) : (
            <div className="h-[280px] sm:h-[320px]">
              <ResponsiveContainer width="100%" height="100%" minWidth={280} minHeight={280}>
                <LineChart data={analytics.timeSeries}>
                  <CartesianGrid stroke={themePalette.grid} vertical={false} />
                  <XAxis dataKey="month" stroke={themePalette.axis} tickLine={false} axisLine={false} fontSize={12} />
                  <YAxis stroke={themePalette.axis} tickLine={false} axisLine={false} fontSize={12} width={36} allowDecimals={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line
                    type="monotone"
                    dataKey="jobs"
                    name="Jobs"
                    stroke={themePalette.pie[0]}
                    strokeWidth={2.5}
                    dot={{ r: 3 }}
                    activeDot={{ r: 5 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="reports"
                    name="Reports"
                    stroke={themePalette.primary}
                    strokeWidth={2.5}
                    dot={{ r: 3 }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>

        <ChartCard
          title="Security posture"
          subtitle="Verdict distribution"
          action={<span className="dashboard-label">Click a bar to open matching reports</span>}
        >
          {postureTotal === 0 ? (
            <ChartEmptyState message="No completed reports are available yet, so there is no verdict distribution to plot." />
          ) : (
            <div className="h-[280px] sm:h-[320px]">
              <ResponsiveContainer width="100%" height="100%" minWidth={280} minHeight={280}>
                <BarChart data={analytics.postureBreakdown}>
                  <CartesianGrid stroke={themePalette.grid} vertical={false} />
                  <XAxis dataKey="label" stroke={themePalette.axis} tickLine={false} axisLine={false} fontSize={12} />
                  <YAxis stroke={themePalette.axis} tickLine={false} axisLine={false} fontSize={12} width={36} allowDecimals={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Bar dataKey="value" name="Reports" radius={[10, 10, 0, 0]}>
                    {analytics.postureBreakdown.map((entry, index) => (
                      <Cell
                        key={entry.label}
                        fill={themePalette.pie[index % themePalette.pie.length]}
                        cursor={Number(entry?.value) > 0 ? "pointer" : "default"}
                        onClick={() => {
                          const normalizedVerdict = normalizeVerdictLabel(entry?.label);
                          if (!normalizedVerdict || Number(entry?.value) <= 0) {
                            return;
                          }

                          onSelectPosture(normalizedVerdict);
                        }}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
        <ChartCard
          title="Queue outcomes"
          subtitle="Current stored job statuses"
          action={<span className="dashboard-label">Live state</span>}
        >
          {queueTotal === 0 ? (
            <ChartEmptyState message="No authenticated scan jobs have been recorded yet." />
          ) : (
            <div className="h-[280px] sm:h-[320px]">
              <ResponsiveContainer width="100%" height="100%" minWidth={280} minHeight={280}>
                <PieChart>
                  <Pie
                    data={analytics.queueBreakdown}
                    dataKey="value"
                    nameKey="label"
                    innerRadius={72}
                    outerRadius={110}
                    paddingAngle={4}
                    stroke="none"
                  >
                    {analytics.queueBreakdown.map((entry, index) => (
                      <Cell key={entry.label} fill={themePalette.pie[index % themePalette.pie.length]} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>

        <WidgetCard title="Observed patterns" subtitle={`Change compares the last ${comparisonWindowDays} days with the previous ${comparisonWindowDays} days`}>
          <div className="grid gap-4 lg:grid-cols-[1.05fr_0.95fr]">
            <div className="space-y-4">
              <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                <p className="dashboard-label">Latest completed report</p>
                <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">
                  {latestReport ? latestReport.fileName : "No completed reports yet"}
                </p>
                <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                  {latestReport
                    ? `${latestReport.verdict} verdict · ${formatRiskScore(latestReport.riskScore)} · ${formatDateTime(latestReport.completedAt)}`
                    : "Run an authenticated scan to start building report history."}
                </p>
              </div>

              <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                <p className="dashboard-label">Highest risk observed</p>
                <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">
                  {highestRiskReport ? highestRiskReport.fileName : "No high-risk file recorded yet"}
                </p>
                <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                  {highestRiskReport
                    ? `${formatRiskScore(highestRiskReport.riskScore)} · ${highestRiskReport.verdict} verdict`
                    : "Risk trends will appear here after reports are stored."}
                </p>
              </div>
            </div>

            <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Most scanned file types</p>
              {topFileTypes.length === 0 ? (
                <p className="mt-3 text-sm leading-7 text-slate-500 dark:text-slate-400">No file-type patterns are available yet.</p>
              ) : (
                <div className="mt-3 space-y-3">
                  {topFileTypes.map((entry) => (
                    <div key={entry.label} className="flex items-center justify-between gap-4 rounded-2xl bg-slate-50 px-3 py-3 dark:bg-slate-900/70">
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{entry.label}</span>
                      <span className="rounded-full bg-white px-2.5 py-1 text-xs font-semibold text-slate-700 shadow-sm ring-1 ring-slate-200 dark:bg-slate-950 dark:text-slate-200 dark:ring-slate-800">
                        {entry.value}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </WidgetCard>
      </section>
    </div>
  );
}
