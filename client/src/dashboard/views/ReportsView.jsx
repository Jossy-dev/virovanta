import { ArrowUpRight, Share2 } from "lucide-react";
import { WidgetCard } from "../components/WidgetCard";
import { filterCollection } from "../dashboardUtils";

export function ReportsView({
  reports,
  activeReport,
  searchQuery,
  onOpenReport,
  onCreateShare,
  shareState,
  shareError,
  isCreatingShare,
  shareCopied,
  onCopyShare,
  activeRiskMeta,
  formatDateTime,
  formatBytes,
  getDisplayFileType,
  formatVerdictLabel
}) {
  const filteredReports = filterCollection(reports, searchQuery, ["fileName", "verdict", "id"]);

  return (
    <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
      <aside className="dashboard-shell-surface p-4 sm:p-5">
        <div className="mb-4">
          <p className="dashboard-label">Reports</p>
          <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Scan history</h2>
        </div>
        <div className="dashboard-scrollbar max-h-[34vh] space-y-2 overflow-y-auto pr-1 sm:max-h-[48vh] xl:max-h-[68vh]">
          {filteredReports.length === 0 ? (
            <p className="text-sm text-slate-500 dark:text-slate-400">No reports available.</p>
          ) : (
            filteredReports.map((report) => (
              <button
                key={report.id}
                type="button"
                onClick={() => onOpenReport(report.id)}
                className={`w-full rounded-3xl border px-4 py-4 text-left transition ${
                  report.id === activeReport?.id
                    ? "border-viro-600 bg-viro-600 text-white dark:border-viro-500 dark:bg-viro-500 dark:text-white"
                    : "border-slate-200 bg-white hover:border-viro-200 hover:bg-viro-50 dark:border-slate-800 dark:bg-slate-950 dark:hover:border-viro-800 dark:hover:bg-viro-900/25"
                }`}
              >
                <p className="truncate text-sm font-semibold">{report.fileName}</p>
                <p
                  className={`mt-1 text-xs ${
                    report.id === activeReport?.id ? "text-white/70 dark:text-slate-500" : "text-slate-500 dark:text-slate-400"
                  }`}
                >
                  {formatDateTime(report.completedAt)}
                </p>
                <span
                  className={`mt-3 inline-flex rounded-full px-2.5 py-1 text-[11px] font-medium ${
                    report.id === activeReport?.id
                      ? "bg-white/10 text-white dark:bg-slate-100 dark:text-slate-900"
                      : "bg-slate-100 text-slate-600 dark:bg-slate-900 dark:text-slate-300"
                  }`}
                >
                  {report.verdict}
                </span>
              </button>
            ))
          )}
        </div>
      </aside>

      <div className="space-y-6">
        {!activeReport ? (
          <WidgetCard title="No report selected" subtitle="Choose a report from the left">
            <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">
              Select a completed report to inspect file metadata, findings, recommendations, and any shared link details.
            </p>
          </WidgetCard>
        ) : (
          <>
            <section className="dashboard-shell-surface p-4 sm:p-6">
              <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between">
                <div>
                  <p className="dashboard-label">Selected report</p>
                  <h2 className="mt-2 text-xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white sm:text-2xl">
                    {activeReport.file.originalName}
                  </h2>
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">{formatDateTime(activeReport.completedAt)}</p>
                </div>
                <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:flex-wrap">
                  <span
                    className={`inline-flex rounded-full px-3 py-2 text-sm font-medium ${
                      activeRiskMeta.tone === "risk-high"
                        ? "bg-rose-50 text-rose-700 dark:bg-rose-500/10 dark:text-rose-300"
                        : activeRiskMeta.tone === "risk-medium"
                          ? "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300"
                          : "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300"
                    }`}
                  >
                    {activeReport.riskScore}/100 {activeRiskMeta.label}
                  </span>
                  <button
                    type="button"
                    onClick={onCreateShare}
                    disabled={isCreatingShare}
                    className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 px-4 py-2.5 disabled:cursor-not-allowed disabled:opacity-45 sm:w-auto"
                  >
                    <Share2 size={16} />
                    {isCreatingShare ? "Generating..." : "Create share link"}
                  </button>
                </div>
              </div>

              <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">Detected type</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">{getDisplayFileType(activeReport.file)}</p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">File size</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">{formatBytes(activeReport.file.size)}</p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">Verdict</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">{formatVerdictLabel(activeReport.verdict)}</p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">SHA256</p>
                  <p className="mt-2 truncate font-mono text-xs text-slate-600 dark:text-slate-300">{activeReport.file.hashes.sha256}</p>
                </div>
              </div>
            </section>

            {shareState.url ? (
              <WidgetCard title="Share Link" subtitle="External access">
                <div className="space-y-3">
                  <code className="block overflow-x-auto rounded-2xl border border-slate-200/80 bg-slate-50 px-4 py-3 text-xs text-slate-700 dark:border-slate-800/80 dark:bg-slate-900 dark:text-slate-300">
                    {shareState.url}
                  </code>
                  <div className="flex flex-wrap gap-3">
                    <button
                      type="button"
                      onClick={onCopyShare}
                      className="dashboard-brand-outline w-full justify-center sm:w-auto"
                    >
                      {shareCopied ? "Copied" : "Copy link"}
                    </button>
                    <a
                      href={shareState.url}
                      target="_blank"
                      rel="noreferrer"
                      className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 sm:w-auto"
                    >
                      Open
                      <ArrowUpRight size={14} />
                    </a>
                  </div>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Expires {formatDateTime(shareState.expiresAt)}</p>
                </div>
              </WidgetCard>
            ) : null}

            {shareError ? <p className="text-sm text-rose-600 dark:text-rose-300">{shareError}</p> : null}

            <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
              <WidgetCard title="Findings" subtitle="What the scanner detected">
                {activeReport.findings.length === 0 ? (
                  <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">No notable indicators were detected in this file.</p>
                ) : (
                  <div className="space-y-3">
                    {activeReport.findings.map((finding) => (
                      <div key={`${finding.id}-${finding.title}`} className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-sm font-semibold text-slate-950 dark:text-white">{finding.title}</p>
                          <span className="rounded-full bg-slate-100 px-2.5 py-1 text-[11px] text-slate-600 dark:bg-slate-900 dark:text-slate-300">
                            {finding.severity}
                          </span>
                        </div>
                        <p className="mt-2 text-sm leading-7 text-slate-500 dark:text-slate-400">{finding.description}</p>
                        <p className="mt-2 font-mono text-xs text-slate-500 dark:text-slate-400">{finding.evidence}</p>
                      </div>
                    ))}
                  </div>
                )}
              </WidgetCard>

              <WidgetCard title="Recommendations" subtitle="Suggested next steps">
                <ul className="space-y-3">
                  {activeReport.recommendations.map((item) => (
                    <li key={item} className="rounded-2xl border border-slate-200/80 px-4 py-3 text-sm leading-7 text-slate-600 dark:border-slate-800/80 dark:text-slate-300">
                      {item}
                    </li>
                  ))}
                </ul>
              </WidgetCard>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
