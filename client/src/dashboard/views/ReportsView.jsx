import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, Share2, Trash2 } from "lucide-react";
import { WidgetCard } from "../components/WidgetCard";
import { filterCollection } from "../dashboardUtils";

const REPORTS_PAGE_SIZE = 12;

export function ReportsView({
  reports,
  activeReport,
  searchQuery,
  onOpenReport,
  onCreateShare,
  onDeleteReport,
  shareState,
  shareError,
  isCreatingShare,
  isDeletingReport,
  shareCopied,
  onCopyShare,
  activeRiskMeta,
  formatDateTime,
  formatBytes,
  getDisplayFileType,
  formatVerdictLabel
}) {
  const filteredReports = filterCollection(reports, searchQuery, ["fileName", "verdict", "id", "sourceType"]);
  const isLinkReport = activeReport?.sourceType === "url";
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [visibleReportCount, setVisibleReportCount] = useState(REPORTS_PAGE_SIZE);
  const visibleReports = useMemo(
    () => filteredReports.slice(0, visibleReportCount),
    [filteredReports, visibleReportCount]
  );
  const canLoadMoreReports = filteredReports.length > visibleReportCount;

  useEffect(() => {
    setConfirmDelete(false);
  }, [activeReport?.id]);

  useEffect(() => {
    setVisibleReportCount(REPORTS_PAGE_SIZE);
  }, [searchQuery]);

  useEffect(() => {
    const activeIndex = filteredReports.findIndex((report) => report.id === activeReport?.id);
    if (activeIndex >= 0 && activeIndex >= visibleReportCount) {
      const pagesRequired = Math.ceil((activeIndex + 1) / REPORTS_PAGE_SIZE);
      setVisibleReportCount(pagesRequired * REPORTS_PAGE_SIZE);
    }
  }, [activeReport?.id, filteredReports, visibleReportCount]);

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
            visibleReports.map((report) => {
              const isActive = report.id === activeReport?.id;

              return (
                <button
                  key={report.id}
                  type="button"
                  onClick={() => onOpenReport(report.id)}
                  className={`w-full cursor-pointer rounded-3xl border px-4 py-4 text-left transition ${
                    isActive
                      ? "border-viro-600 bg-viro-600 text-white dark:border-viro-500 dark:bg-viro-500 dark:text-white"
                      : "border-slate-200 bg-white hover:border-viro-200 hover:bg-viro-50 dark:border-slate-800 dark:bg-slate-950 dark:hover:border-viro-800 dark:hover:bg-viro-900/25"
                  }`}
                >
                  <p className={`truncate text-sm font-semibold ${isActive ? "text-white dark:text-white" : "text-slate-900 dark:text-slate-100"}`}>
                    {report.fileName}
                  </p>
                  <p className={`mt-1 text-xs ${isActive ? "text-white/80 dark:text-white/80" : "text-slate-500 dark:text-slate-300"}`}>
                    {formatDateTime(report.completedAt)}
                  </p>
                  <p className={`mt-1 text-xs ${isActive ? "text-white/80 dark:text-white/80" : "text-slate-500 dark:text-slate-300"}`}>
                    {report.sourceType === "url" ? "URL scan" : "File scan"}
                  </p>
                  <span
                    className={`mt-3 inline-flex rounded-full px-2.5 py-1 text-[11px] font-medium ${
                      isActive
                        ? "bg-white/20 text-white dark:bg-white/20 dark:text-white"
                        : "bg-slate-100 text-slate-600 dark:bg-slate-900 dark:text-slate-300"
                    }`}
                  >
                    {report.verdict}
                  </span>
                </button>
              );
            })
          )}
        </div>
        {canLoadMoreReports ? (
          <div className="mt-4">
            <button
              type="button"
              onClick={() => setVisibleReportCount((current) => current + REPORTS_PAGE_SIZE)}
              className="dashboard-brand-outline w-full justify-center"
            >
              Load more reports
            </button>
            <p className="mt-2 text-center text-xs text-slate-500 dark:text-slate-400">
              Showing {visibleReports.length} of {filteredReports.length}
            </p>
          </div>
        ) : null}
      </aside>

      <div className="space-y-6">
        {!activeReport ? (
          <WidgetCard title="No report selected" subtitle="Choose a report from the left">
            <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">
              Select a completed report to inspect file or URL metadata, findings, recommendations, and any shared link details.
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
                  <button
                    type="button"
                    onClick={() => {
                      if (!confirmDelete) {
                        setConfirmDelete(true);
                        return;
                      }

                      setConfirmDelete(false);
                      void onDeleteReport(activeReport.id);
                    }}
                    disabled={isDeletingReport}
                    className={`inline-flex w-full items-center justify-center gap-2 rounded-full border px-4 py-2.5 text-sm transition disabled:cursor-not-allowed disabled:opacity-45 sm:w-auto ${
                      confirmDelete
                        ? "border-rose-300 bg-rose-50 text-rose-700 hover:bg-rose-100 dark:border-rose-700 dark:bg-rose-900/30 dark:text-rose-200 dark:hover:bg-rose-900/45"
                        : "border-slate-300 bg-white text-slate-700 hover:border-rose-300 hover:text-rose-700 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200 dark:hover:border-rose-700 dark:hover:text-rose-200"
                    }`}
                  >
                    <Trash2 size={16} />
                    {isDeletingReport ? "Hiding..." : confirmDelete ? "Confirm hide report" : "Hide report"}
                  </button>
                </div>
              </div>

              {confirmDelete ? (
                <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50/60 px-4 py-3 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-200">
                  Report will be hidden from history immediately. Retention remains active for policy/audit expiry.
                </div>
              ) : null}

              <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isLinkReport ? "URL host" : "Detected type"}</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">
                    {isLinkReport ? activeReport?.url?.hostname || "Unknown host" : getDisplayFileType(activeReport.file)}
                  </p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isLinkReport ? "Fetched bytes" : "File size"}</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">{formatBytes(activeReport.file.size)}</p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">Verdict</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">{formatVerdictLabel(activeReport.verdict)}</p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isLinkReport ? "URL hash (SHA256)" : "SHA256"}</p>
                  <p className="mt-2 break-all font-mono text-xs text-slate-600 dark:text-slate-300">{activeReport.file.hashes.sha256}</p>
                </div>
              </div>

              {isLinkReport ? (
                <div className="mt-4 grid gap-4 sm:grid-cols-2">
                  <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                    <p className="dashboard-label">Final URL</p>
                    <p className="mt-2 break-all text-xs text-slate-700 dark:text-slate-300">{activeReport?.url?.final || activeReport.file.originalName}</p>
                  </div>
                  <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                    <p className="dashboard-label">Redirects</p>
                    <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">
                      {Array.isArray(activeReport?.url?.redirects) ? activeReport.url.redirects.length : 0}
                    </p>
                  </div>
                </div>
              ) : null}
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
                  <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">
                    No notable indicators were detected in this {isLinkReport ? "URL target" : "file"}.
                  </p>
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
                        <p className="mt-2 break-all font-mono text-xs text-slate-500 dark:text-slate-400">{finding.evidence}</p>
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

            {isLinkReport && activeReport?.technicalIndicators ? (
              <WidgetCard title="Technical Indicators" subtitle="Link analysis signals">
                <pre className="dashboard-scrollbar overflow-x-auto rounded-2xl border border-slate-200/80 bg-slate-50 p-3 text-xs text-slate-700 dark:border-slate-800/80 dark:bg-slate-900 dark:text-slate-300">
                  {JSON.stringify(activeReport.technicalIndicators, null, 2)}
                </pre>
              </WidgetCard>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}
