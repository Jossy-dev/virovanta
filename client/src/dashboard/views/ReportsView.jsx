import { useCallback, useEffect, useMemo, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { ArrowUpRight, Download, MessageSquareText, Share2, Trash2 } from "lucide-react";
import { WidgetCard } from "../components/WidgetCard";
import { filterCollection } from "../dashboardUtils";
import { createStaggerContainerVariants, createStaggerItemVariants } from "../../ui/motionSystem";

const REPORTS_PAGE_SIZE = 12;
const VERDICT_FILTER_VALUES = Object.freeze(["clean", "suspicious", "malicious"]);

function normalizeVerdictValue(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();

  if (VERDICT_FILTER_VALUES.includes(normalized)) {
    return normalized;
  }

  return "";
}

function SkeletonBar({ className = "" }) {
  return <span className={`block animate-pulse rounded bg-slate-200/85 dark:bg-slate-800/85 ${className}`} aria-hidden="true" />;
}

export function ReportsView({
  reports,
  activeReport,
  reportWorkflow,
  reportComments,
  reportShares,
  searchQuery,
  verdictFilter = "",
  onClearVerdictFilter = () => {},
  onOpenReport,
  onCreateShare,
  onRevokeShare = () => {},
  onDeleteReport,
  shareState,
  shareDraft,
  setShareDraft = () => {},
  shareError,
  isCreatingShare,
  isDeletingReport,
  isUpdatingReportWorkflow = false,
  isPostingReportComment = false,
  shareCopied,
  onCopyShare,
  onUpdateReportWorkflow = async () => {},
  onAddReportComment = async () => {},
  onDownloadReportPdf = async () => {},
  onDownloadReportExport = async () => {},
  activeRiskMeta,
  formatDateTime,
  formatBytes,
  getDisplayFileType,
  formatVerdictLabel
}) {
  const prefersReducedMotion = useReducedMotion();
  const normalizedVerdictFilter = normalizeVerdictValue(verdictFilter);
  const verdictFilteredReports = useMemo(() => {
    if (!normalizedVerdictFilter) {
      return reports;
    }

    return reports.filter((report) => normalizeVerdictValue(report?.verdict) === normalizedVerdictFilter);
  }, [reports, normalizedVerdictFilter]);
  const filteredReports = useMemo(
    () => filterCollection(verdictFilteredReports, searchQuery, ["fileName", "verdict", "id", "sourceType"]),
    [verdictFilteredReports, searchQuery]
  );
  const selectedReport = useMemo(() => {
    if (!activeReport || !activeReport.id) {
      return null;
    }

    return filteredReports.some((report) => report.id === activeReport.id) ? activeReport : null;
  }, [activeReport, filteredReports]);
  const [pendingSelectedReportId, setPendingSelectedReportId] = useState("");
  const selectedListReportId = pendingSelectedReportId || selectedReport?.id || "";
  const pendingReportSummary = useMemo(() => {
    if (!pendingSelectedReportId) {
      return null;
    }

    return filteredReports.find((report) => report.id === pendingSelectedReportId) || null;
  }, [filteredReports, pendingSelectedReportId]);
  const isReportDetailsLoading = Boolean(pendingSelectedReportId) && pendingSelectedReportId !== selectedReport?.id;
  const hasSelectedOrPendingReport = Boolean(selectedReport || pendingReportSummary);
  const selectedSourceType = pendingReportSummary?.sourceType || selectedReport?.sourceType || "file";
  const isWebTargetReport = selectedSourceType === "url" || selectedSourceType === "website";
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [commentDraft, setCommentDraft] = useState("");
  const [workflowDraft, setWorkflowDraft] = useState({
    caseStatus: "new",
    severity: "medium",
    assigneeLabel: "",
    clientLabel: "",
    recommendedAction: "",
    notesSummary: ""
  });
  const [visibleReportCount, setVisibleReportCount] = useState(REPORTS_PAGE_SIZE);
  const visibleReports = useMemo(
    () => filteredReports.slice(0, visibleReportCount),
    [filteredReports, visibleReportCount]
  );
  const reportListVariants = useMemo(
    () => createStaggerContainerVariants(prefersReducedMotion, { staggerChildren: 0.028, delayChildren: 0.01 }),
    [prefersReducedMotion]
  );
  const reportItemVariants = useMemo(
    () => createStaggerItemVariants(prefersReducedMotion, { y: 5, duration: 0.16 }),
    [prefersReducedMotion]
  );
  const canLoadMoreReports = filteredReports.length > visibleReportCount;
  const handleOpenReport = useCallback((reportId) => {
    if (!reportId || reportId === selectedListReportId) {
      return;
    }

    setPendingSelectedReportId(reportId);
    Promise.resolve(onOpenReport(reportId)).catch(() => {
      setPendingSelectedReportId((current) => (current === reportId ? "" : current));
    });
  }, [onOpenReport, selectedListReportId]);

  useEffect(() => {
    setConfirmDelete(false);
  }, [selectedReport?.id]);

  useEffect(() => {
    setCommentDraft("");
    setWorkflowDraft({
      caseStatus: reportWorkflow?.caseStatus || "new",
      severity: reportWorkflow?.severity || "medium",
      assigneeLabel: reportWorkflow?.assigneeLabel || "",
      clientLabel: reportWorkflow?.clientLabel || "",
      recommendedAction: reportWorkflow?.recommendedAction || "",
      notesSummary: reportWorkflow?.notesSummary || ""
    });
  }, [reportWorkflow?.reportId, reportWorkflow?.updatedAt]);

  useEffect(() => {
    if (!pendingSelectedReportId) {
      return;
    }

    if (selectedReport?.id === pendingSelectedReportId) {
      setPendingSelectedReportId("");
    }
  }, [pendingSelectedReportId, selectedReport?.id]);

  useEffect(() => {
    if (!pendingSelectedReportId) {
      return;
    }

    if (!filteredReports.some((report) => report.id === pendingSelectedReportId)) {
      setPendingSelectedReportId("");
    }
  }, [filteredReports, pendingSelectedReportId]);

  useEffect(() => {
    setVisibleReportCount(REPORTS_PAGE_SIZE);
  }, [searchQuery, normalizedVerdictFilter]);

  useEffect(() => {
    const activeIndex = filteredReports.findIndex((report) => report.id === selectedListReportId);
    if (activeIndex >= 0 && activeIndex >= visibleReportCount) {
      const pagesRequired = Math.ceil((activeIndex + 1) / REPORTS_PAGE_SIZE);
      setVisibleReportCount(pagesRequired * REPORTS_PAGE_SIZE);
    }
  }, [selectedListReportId, filteredReports, visibleReportCount]);

  useEffect(() => {
    if (!normalizedVerdictFilter || filteredReports.length === 0 || selectedListReportId) {
      return;
    }

    handleOpenReport(filteredReports[0].id);
  }, [filteredReports, normalizedVerdictFilter, selectedListReportId, handleOpenReport]);

  return (
    <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
      <aside className="dashboard-shell-surface p-4 sm:p-5">
        <div className="mb-4">
          <p className="dashboard-label">Reports</p>
          <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Scan history</h2>
          {normalizedVerdictFilter ? (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-viro-200 bg-viro-50 px-2.5 py-1 text-xs font-medium text-viro-700 dark:border-viro-800 dark:bg-viro-900/35 dark:text-viro-200">
                Filter: {formatVerdictLabel(normalizedVerdictFilter)}
              </span>
              <button
                type="button"
                onClick={onClearVerdictFilter}
                className="dashboard-brand-outline px-3 py-1.5 text-xs"
              >
                Clear filter
              </button>
            </div>
          ) : null}
        </div>
        <div className="dashboard-scrollbar max-h-[34vh] overflow-y-auto rounded-none border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-950 sm:max-h-[48vh] xl:max-h-[68vh]">
          {filteredReports.length === 0 ? (
            <p className="px-4 py-4 text-sm text-slate-500 dark:text-slate-400">
              {normalizedVerdictFilter
                ? `No ${formatVerdictLabel(normalizedVerdictFilter).toLowerCase()} reports available.`
                : "No reports available."}
            </p>
          ) : (
            <motion.div variants={reportListVariants} initial="hidden" animate="show">
              {visibleReports.map((report, index) => {
                const isActive = report.id === selectedListReportId;
                const isPendingActive = report.id === pendingSelectedReportId && pendingSelectedReportId !== selectedReport?.id;
                const isAlternateRow = index % 2 === 1;

                return (
                  <motion.button
                    key={report.id}
                    type="button"
                    variants={reportItemVariants}
                    layout="position"
                    onClick={() => handleOpenReport(report.id)}
                    className={`w-full cursor-pointer rounded-none border-b border-slate-200/80 px-4 py-4 text-left transition-colors duration-150 last:border-b-0 dark:border-slate-800/80 ${
                      isActive
                        ? "bg-viro-600 text-white dark:bg-viro-500 dark:text-white"
                        : isAlternateRow
                          ? "bg-slate-50/70 hover:bg-viro-50/70 dark:bg-slate-900/65 dark:hover:bg-viro-900/25"
                          : "bg-white hover:bg-slate-50 dark:bg-slate-950 dark:hover:bg-viro-900/20"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className={`truncate text-sm font-semibold ${isActive ? "text-white dark:text-white" : "text-slate-900 dark:text-slate-100"}`}>
                        {report.fileName}
                      </p>
                      {isPendingActive ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-[0.12em] text-white/80 dark:text-white/80">
                          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-white/90" />
                          Loading
                        </span>
                      ) : null}
                    </div>
                    <p className={`mt-1 text-xs ${isActive ? "text-white/80 dark:text-white/80" : "text-slate-500 dark:text-slate-300"}`}>
                      {formatDateTime(report.completedAt)}
                    </p>
                    <p className={`mt-1 text-xs ${isActive ? "text-white/80 dark:text-white/80" : "text-slate-500 dark:text-slate-300"}`}>
                      {report.sourceType === "url" ? "URL scan" : report.sourceType === "website" ? "Website safety" : "File scan"}
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
                  </motion.button>
                );
              })}
            </motion.div>
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
        {!hasSelectedOrPendingReport ? (
          <WidgetCard title="No report selected" subtitle="Choose a report from the left">
            <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">
              Select a completed report to inspect file or URL metadata, findings, recommendations, and any shared link details.
            </p>
          </WidgetCard>
        ) : isReportDetailsLoading ? (
          <>
            <section className="dashboard-shell-surface p-4 sm:p-6" aria-live="polite" aria-busy="true">
              <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between">
                <div>
                  <p className="dashboard-label">Selected report</p>
                  <h2 className="mt-2 text-xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white sm:text-2xl">
                    {pendingReportSummary?.fileName || "Loading report"}
                  </h2>
                  <p className="mt-2 inline-flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
                    <span className="h-2 w-2 animate-pulse rounded-full bg-viro-500 dark:bg-viro-400" />
                    Loading report details...
                  </p>
                </div>
                <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:flex-wrap">
                  <SkeletonBar className="h-10 w-40 rounded-full" />
                  <SkeletonBar className="h-10 w-40 rounded-full" />
                  <SkeletonBar className="h-10 w-40 rounded-full" />
                </div>
              </div>

              <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isWebTargetReport ? "URL host" : "Detected type"}</p>
                  <SkeletonBar className="mt-2 h-4 w-3/4" />
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isWebTargetReport ? "Fetched bytes" : "File size"}</p>
                  <SkeletonBar className="mt-2 h-4 w-2/3" />
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">Verdict</p>
                  <SkeletonBar className="mt-2 h-4 w-1/2" />
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isWebTargetReport ? "URL hash (SHA256)" : "SHA256"}</p>
                  <SkeletonBar className="mt-2 h-3 w-full" />
                </div>
              </div>

              {isWebTargetReport ? (
                <div className="mt-4 grid gap-4 sm:grid-cols-2">
                  <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                    <p className="dashboard-label">Final URL</p>
                    <SkeletonBar className="mt-2 h-3 w-full" />
                  </div>
                  <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                    <p className="dashboard-label">Redirects</p>
                    <SkeletonBar className="mt-2 h-4 w-1/4" />
                  </div>
                </div>
              ) : null}
            </section>

            <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
              <WidgetCard title="Findings" subtitle="What the scanner detected">
                <div className="space-y-3">
                  <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                    <SkeletonBar className="h-4 w-2/3" />
                    <SkeletonBar className="mt-3 h-3 w-full" />
                    <SkeletonBar className="mt-2 h-3 w-5/6" />
                  </div>
                  <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                    <SkeletonBar className="h-4 w-1/2" />
                    <SkeletonBar className="mt-3 h-3 w-full" />
                  </div>
                </div>
              </WidgetCard>

              <WidgetCard title="Recommendations" subtitle="Suggested next steps">
                <div className="space-y-3">
                  <SkeletonBar className="h-10 w-full rounded-2xl" />
                  <SkeletonBar className="h-10 w-full rounded-2xl" />
                  <SkeletonBar className="h-10 w-5/6 rounded-2xl" />
                </div>
              </WidgetCard>
            </div>
          </>
        ) : selectedReport ? (
          <>
            <section className="dashboard-shell-surface p-4 sm:p-6">
              <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between">
                <div>
                  <p className="dashboard-label">Selected report</p>
                  <h2 className="mt-2 text-xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white sm:text-2xl">
                    {selectedReport.file.originalName}
                  </h2>
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">{formatDateTime(selectedReport.completedAt)}</p>
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
                    {selectedReport.riskScore}/100 {activeRiskMeta.label}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      if (!confirmDelete) {
                        setConfirmDelete(true);
                        return;
                      }

                      setConfirmDelete(false);
                      void onDeleteReport(selectedReport.id);
                    }}
                    disabled={isDeletingReport}
                    className={`inline-flex w-full items-center justify-center gap-2 rounded-full border px-4 py-2.5 text-sm transition disabled:cursor-not-allowed disabled:opacity-45 sm:w-auto ${
                      confirmDelete
                        ? "border-rose-300 bg-rose-50 text-rose-700 hover:bg-rose-100 dark:border-rose-700 dark:bg-rose-900/30 dark:text-rose-200 dark:hover:bg-rose-900/45"
                        : "border-slate-300 bg-white text-slate-700 hover:border-rose-300 hover:text-rose-700 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200 dark:hover:border-rose-700 dark:hover:text-rose-200"
                    }`}
                  >
                    <Trash2 size={16} />
                    {isDeletingReport ? "Deleting..." : confirmDelete ? "Confirm delete report" : "Delete report"}
                  </button>
                </div>
              </div>

              {confirmDelete ? (
                <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50/60 px-4 py-3 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-200">
                  Report will be deleted from your workspace immediately.
                </div>
              ) : null}

              <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isWebTargetReport ? "URL host" : "Detected type"}</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">
                    {isWebTargetReport ? selectedReport?.url?.hostname || "Unknown host" : getDisplayFileType(selectedReport.file)}
                  </p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isWebTargetReport ? "Fetched bytes" : "File size"}</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">{formatBytes(selectedReport.file.size)}</p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">Verdict</p>
                  <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">{formatVerdictLabel(selectedReport.verdict)}</p>
                </div>
                <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="dashboard-label">{isWebTargetReport ? "URL hash (SHA256)" : "SHA256"}</p>
                  <p className="mt-2 break-all font-mono text-xs text-slate-600 dark:text-slate-300">{selectedReport.file.hashes.sha256}</p>
                </div>
              </div>

              {isWebTargetReport ? (
                <div className="mt-4 grid gap-4 sm:grid-cols-2">
                  <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                    <p className="dashboard-label">Final URL</p>
                    <p className="mt-2 break-all text-xs text-slate-700 dark:text-slate-300">{selectedReport?.url?.final || selectedReport.file.originalName}</p>
                  </div>
                  <div className="rounded-3xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                    <p className="dashboard-label">Redirects</p>
                    <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">
                      {Array.isArray(selectedReport?.url?.redirects) ? selectedReport.url.redirects.length : 0}
                    </p>
                  </div>
                </div>
              ) : null}
            </section>

            <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
              <WidgetCard title="Share control" subtitle="External report access">
                <div className="space-y-4">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                      <span>Share label</span>
                      <input
                        type="text"
                        value={shareDraft?.label || ""}
                        onChange={(event) => setShareDraft((current) => ({ ...current, label: event.target.value }))}
                        className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                        placeholder="Client-safe link"
                      />
                    </label>
                    <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                      <span>Duration</span>
                      <select
                        value={String(shareDraft?.ttlHours || 72)}
                        onChange={(event) => setShareDraft((current) => ({ ...current, ttlHours: Number(event.target.value) }))}
                        className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                      >
                        <option value="24">24 hours</option>
                        <option value="72">72 hours</option>
                        <option value="168">7 days</option>
                        <option value="336">14 days</option>
                      </select>
                    </label>
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <button
                      type="button"
                      onClick={() => onCreateShare(shareDraft)}
                      disabled={isCreatingShare}
                      className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 px-4 py-2.5 disabled:cursor-not-allowed disabled:opacity-45 sm:w-auto"
                    >
                      <Share2 size={16} />
                      {isCreatingShare ? "Generating..." : "Create share link"}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        void onDownloadReportPdf(selectedReport.id);
                      }}
                      className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 sm:w-auto"
                    >
                      <Download size={14} />
                      PDF
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        void onDownloadReportExport(selectedReport.id, "json");
                      }}
                      className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 sm:w-auto"
                    >
                      <Download size={14} />
                      JSON
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        void onDownloadReportExport(selectedReport.id, "csv");
                      }}
                      className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 sm:w-auto"
                    >
                      <Download size={14} />
                      CSV
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        void onDownloadReportExport(selectedReport.id, "stix");
                      }}
                      className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 sm:w-auto"
                    >
                      <Download size={14} />
                      STIX
                    </button>
                  </div>

                  {shareState.url ? (
                    <div className="rounded-2xl border border-slate-200/80 bg-slate-50/70 px-4 py-4 dark:border-slate-800/80 dark:bg-slate-900/50">
                      <code className="block overflow-x-auto text-xs text-slate-700 dark:text-slate-300">{shareState.url}</code>
                      <div className="mt-3 flex flex-wrap gap-3">
                        <button type="button" onClick={onCopyShare} className="dashboard-brand-outline w-full justify-center sm:w-auto">
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
                      <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">Expires {formatDateTime(shareState.expiresAt)}</p>
                    </div>
                  ) : null}

                  {reportShares?.length ? (
                    <div className="space-y-3">
                      <p className="dashboard-label">Recent share links</p>
                      {reportShares.map((share) => (
                        <div key={share.id} className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                            <div>
                              <p className="text-sm font-semibold text-slate-950 dark:text-white">{share.label || "Untitled share link"}</p>
                              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                                Created {formatDateTime(share.createdAt)}. Expires {formatDateTime(share.expiresAt)}.
                              </p>
                              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                                Accesses {share.accessCount || 0}{share.lastAccessedAt ? `, last opened ${formatDateTime(share.lastAccessedAt)}` : ""}
                              </p>
                            </div>
                            {share.revokedAt ? (
                              <span className="rounded-full border border-slate-300 px-2.5 py-1 text-xs text-slate-600 dark:border-slate-700 dark:text-slate-300">
                                Revoked
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => {
                                  void onRevokeShare(share.id);
                                }}
                                className="rounded-full border border-slate-200 px-3 py-1.5 text-xs text-slate-700 transition hover:border-rose-300 hover:text-rose-700 dark:border-slate-800 dark:text-slate-300 dark:hover:border-rose-700 dark:hover:text-rose-200"
                              >
                                Revoke
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              </WidgetCard>

              <WidgetCard title="Case workflow" subtitle="Analyst-ready triage state">
                <div className="grid gap-4">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                      <span>Status</span>
                      <select
                        value={workflowDraft.caseStatus}
                        onChange={(event) => setWorkflowDraft((current) => ({ ...current, caseStatus: event.target.value }))}
                        className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                      >
                        <option value="new">New</option>
                        <option value="triage">Triage</option>
                        <option value="investigating">Investigating</option>
                        <option value="closed">Closed</option>
                      </select>
                    </label>
                    <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                      <span>Severity</span>
                      <select
                        value={workflowDraft.severity}
                        onChange={(event) => setWorkflowDraft((current) => ({ ...current, severity: event.target.value }))}
                        className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                      </select>
                    </label>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                      <span>Assignee</span>
                      <input
                        type="text"
                        value={workflowDraft.assigneeLabel}
                        onChange={(event) => setWorkflowDraft((current) => ({ ...current, assigneeLabel: event.target.value }))}
                        className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                        placeholder="Analyst or queue owner"
                      />
                    </label>
                    <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                      <span>Client / queue label</span>
                      <input
                        type="text"
                        value={workflowDraft.clientLabel}
                        onChange={(event) => setWorkflowDraft((current) => ({ ...current, clientLabel: event.target.value }))}
                        className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                        placeholder="Finance escalation"
                      />
                    </label>
                  </div>

                  <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                    <span>Recommended action</span>
                    <input
                      type="text"
                      value={workflowDraft.recommendedAction}
                      onChange={(event) => setWorkflowDraft((current) => ({ ...current, recommendedAction: event.target.value }))}
                      className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                      placeholder="Block, escalate, or continue monitoring"
                    />
                  </label>

                  <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                    <span>Summary notes</span>
                    <textarea
                      value={workflowDraft.notesSummary}
                      onChange={(event) => setWorkflowDraft((current) => ({ ...current, notesSummary: event.target.value }))}
                      className="min-h-[116px] rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                      placeholder="Document why the verdict matters and what should happen next."
                    />
                  </label>

                  <button
                    type="button"
                    onClick={() => {
                      void onUpdateReportWorkflow(workflowDraft);
                    }}
                    disabled={isUpdatingReportWorkflow}
                    className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 sm:w-auto"
                  >
                    {isUpdatingReportWorkflow ? "Saving..." : "Save workflow"}
                  </button>
                </div>
              </WidgetCard>
            </div>

            {shareError ? <p className="text-sm text-rose-600 dark:text-rose-300">{shareError}</p> : null}

            <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
              <WidgetCard title="Findings" subtitle="What the scanner detected">
                {selectedReport.findings.length === 0 ? (
                  <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">
                    No notable indicators were detected in this {isWebTargetReport ? "URL target" : "file"}.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {selectedReport.findings.map((finding) => (
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
                  {selectedReport.recommendations.map((item) => (
                    <li key={item} className="rounded-2xl border border-slate-200/80 px-4 py-3 text-sm leading-7 text-slate-600 dark:border-slate-800/80 dark:text-slate-300">
                      {item}
                    </li>
                  ))}
                </ul>
              </WidgetCard>
            </div>

            {isWebTargetReport && selectedReport?.technicalIndicators ? (
              <WidgetCard title="Technical Indicators" subtitle="Link analysis signals">
                <pre className="dashboard-scrollbar overflow-x-auto rounded-2xl border border-slate-200/80 bg-slate-50 p-3 text-xs text-slate-700 dark:border-slate-800/80 dark:bg-slate-900 dark:text-slate-300">
                  {JSON.stringify(selectedReport.technicalIndicators, null, 2)}
                </pre>
              </WidgetCard>
            ) : null}

            <WidgetCard title="Analyst comments" subtitle="Case notes and customer-facing rationale">
              <div className="space-y-4">
                <div className="space-y-3">
                  {(reportComments || []).length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-slate-300/80 px-4 py-5 text-sm text-slate-500 dark:border-slate-800 dark:text-slate-400">
                      No comments yet. Use this thread for analyst notes, escalation context, or client-ready wording.
                    </div>
                  ) : (
                    reportComments.map((comment) => (
                      <div key={comment.id} className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                        <div className="flex items-center justify-between gap-3">
                          <div className="inline-flex items-center gap-2 text-sm font-semibold text-slate-950 dark:text-white">
                            <MessageSquareText size={15} className="text-slate-400" />
                            {comment.authorName}
                          </div>
                          <span className="text-xs text-slate-500 dark:text-slate-400">{formatDateTime(comment.createdAt)}</span>
                        </div>
                        <p className="mt-3 text-sm leading-7 text-slate-600 dark:text-slate-300">{comment.body}</p>
                      </div>
                    ))
                  )}
                </div>

                <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                    <span>Add comment</span>
                    <textarea
                      value={commentDraft}
                      onChange={(event) => setCommentDraft(event.target.value)}
                      className="min-h-[110px] rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                      placeholder="Explain why this report matters, what you verified, and what should happen next."
                    />
                  </label>
                  <div className="mt-3 flex flex-wrap gap-3">
                    <button
                      type="button"
                      onClick={async () => {
                        if (!commentDraft.trim()) {
                          return;
                        }
                        await onAddReportComment(commentDraft.trim());
                        setCommentDraft("");
                      }}
                      disabled={isPostingReportComment}
                      className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 sm:w-auto"
                    >
                      {isPostingReportComment ? "Posting..." : "Add comment"}
                    </button>
                  </div>
                </div>
              </div>
            </WidgetCard>
          </>
        ) : null}
      </div>
    </div>
  );
}
