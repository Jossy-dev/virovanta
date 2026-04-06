import { FileBarChart2, FolderPlus, ShieldAlert, UploadCloud } from "lucide-react";
import { ProjectsView } from "./ProjectsView";
import Button from "../../ui/Button";

export function DashboardOverview({
  userName,
  currentDateLabel,
  quotaText,
  selectedFiles,
  searchQuery,
  maxFilesPerBatch,
  maxUploadMb,
  isSubmittingScan,
  onSelectFiles,
  onSubmitScan,
  onResolveUrlScanTargets,
  onSubmitUrlScans,
  onClearSelectedFiles,
  jobs,
  reports,
  activeJob,
  analytics,
  workspaceSummary,
  onOpenReportWorkspace,
  formatDateTime,
  formatBytes,
  pluralize,
  onCreateProject,
  onOpenReports
}) {
  const queuedJobs = Number(analytics?.summary?.activeJobs) || jobs.filter((job) => job.status === "queued" || job.status === "processing").length;
  const completedReports = Number(analytics?.summary?.totalReports) || reports.length;
  const flaggedReports = Number(analytics?.summary?.flaggedReports) || reports.filter((report) => report.verdict !== "clean").length;
  const activeMonitors = Number(workspaceSummary?.usage?.monitorsActive) || 0;

  return (
    <div className="space-y-6">
      <section className="dashboard-shell-surface dashboard-grid-overlay overflow-hidden p-4 sm:p-6 lg:p-8">
        <div className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
          <div className="space-y-3">
            <p className="dashboard-label">Overview</p>
            <div>
              <h1 className="text-2xl font-semibold tracking-[-0.05em] text-slate-950 dark:text-white sm:text-3xl lg:text-[2.4rem]">
                Welcome back,  {userName}
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-7 text-slate-500 dark:text-slate-400">
                Upload files, monitor the queue, and review recent results from one place.
              </p>
            </div>
          </div>

          <div className="flex flex-col items-start gap-3 xl:items-end">
            <div className="flex flex-wrap gap-3">
              <span className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-500 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
                {currentDateLabel}
              </span>
              <span className="dashboard-brand-outline">
                {quotaText}
              </span>
            </div>
            <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:flex-wrap">
              <Button
                type="button"
                onClick={onCreateProject}
                variant="primary"
                size="lg"
                className="w-full sm:w-auto"
              >
                <FolderPlus size={16} />
                New scan
              </Button>
              <Button
                type="button"
                onClick={onOpenReports}
                variant="secondary"
                size="lg"
                className="w-full sm:w-auto"
              >
                <FileBarChart2 size={16} />
                View reports
              </Button>
            </div>
          </div>
        </div>

        <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <div className="dashboard-brand-stat rounded-3xl px-4 py-4">
            <div className="flex items-center gap-3">
              <span className="dashboard-brand-icon inline-flex h-10 w-10 items-center justify-center rounded-2xl border bg-white dark:bg-slate-950">
                <UploadCloud size={18} />
              </span>
              <div>
                <p className="dashboard-label">Queued jobs</p>
                <p className="mt-1 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{queuedJobs}</p>
              </div>
            </div>
          </div>
          <div className="dashboard-brand-stat rounded-3xl px-4 py-4">
            <div className="flex items-center gap-3">
              <span className="dashboard-brand-icon inline-flex h-10 w-10 items-center justify-center rounded-2xl border bg-white dark:bg-slate-950">
                <FolderPlus size={18} />
              </span>
              <div>
                <p className="dashboard-label">Completed reports</p>
                <p className="mt-1 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">
                  {completedReports}
                </p>
              </div>
            </div>
          </div>
          <div className="dashboard-brand-stat rounded-3xl px-4 py-4">
            <div className="flex items-center gap-3">
              <span className="dashboard-brand-icon inline-flex h-10 w-10 items-center justify-center rounded-2xl border bg-white dark:bg-slate-950">
                <ShieldAlert size={18} />
              </span>
              <div>
                <p className="dashboard-label">Flagged reports</p>
                <p className="mt-1 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{flaggedReports}</p>
              </div>
            </div>
          </div>
          <div className="dashboard-brand-stat rounded-3xl px-4 py-4">
            <div className="flex items-center gap-3">
              <span className="dashboard-brand-icon inline-flex h-10 w-10 items-center justify-center rounded-2xl border bg-white dark:bg-slate-950">
                <FileBarChart2 size={18} />
              </span>
              <div>
                <p className="dashboard-label">Active monitors</p>
                <p className="mt-1 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{activeMonitors}</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <ProjectsView
        selectedFiles={selectedFiles}
        searchQuery={searchQuery}
        maxFilesPerBatch={maxFilesPerBatch}
        maxUploadMb={maxUploadMb}
        quotaText={quotaText}
        isSubmittingScan={isSubmittingScan}
        onSelectFiles={onSelectFiles}
        onSubmitScan={onSubmitScan}
        onResolveUrlScanTargets={onResolveUrlScanTargets}
        onSubmitUrlScans={onSubmitUrlScans}
        onClearSelectedFiles={onClearSelectedFiles}
        jobs={jobs}
        activeJob={activeJob}
        onOpenReportWorkspace={onOpenReportWorkspace}
        formatDateTime={formatDateTime}
        formatBytes={formatBytes}
        pluralize={pluralize}
        showHeader={false}
        showQuotaBadge={false}
      />
    </div>
  );
}
