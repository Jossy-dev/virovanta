import { useEffect, useMemo, useRef } from "react";
import { ArrowRight, FolderOpen, UploadCloud } from "lucide-react";
import { DataTable } from "../components/DataTable";
import { WidgetCard } from "../components/WidgetCard";
import { filterCollection } from "../dashboardUtils";

export function ProjectsView({
  selectedFiles,
  searchQuery,
  maxFilesPerBatch,
  maxUploadMb,
  quotaText,
  isSubmittingScan,
  onSelectFiles,
  onSubmitScan,
  onClearSelectedFiles,
  jobs,
  activeJob,
  onOpenReportWorkspace,
  formatDateTime,
  formatBytes,
  pluralize,
  showHeader = true,
  showQuotaBadge = true
}) {
  const fileInputRef = useRef(null);

  useEffect(() => {
    if (selectedFiles.length === 0 && fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }, [selectedFiles]);

  const selectedUploadBytes = useMemo(
    () => selectedFiles.reduce((total, file) => total + (Number(file?.size) || 0), 0),
    [selectedFiles]
  );

  const filteredJobs = useMemo(
    () => filterCollection(jobs, searchQuery, ["originalName", "status", "id"]),
    [jobs, searchQuery]
  );

  const pendingJobs = jobs.filter((job) => job.status === "queued" || job.status === "processing").length;
  const completedJobs = jobs.filter((job) => job.status === "completed").length;
  const selectedFileNames = selectedFiles.map((file) => file?.name).filter(Boolean);

  const columns = [
    {
      key: "file",
      label: "File",
      render: (row) => (
        <div>
          <div className="font-medium text-slate-950 dark:text-white">{row.originalName}</div>
          <div className="text-xs text-slate-500 dark:text-slate-400">{row.id}</div>
        </div>
      )
    },
    {
      key: "status",
      label: "Status",
      render: (row) => (
        <span className="inline-flex rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">
          {row.status}
        </span>
      )
    },
    {
      key: "createdAt",
      label: "Queued",
      render: (row) => formatDateTime(row.createdAt)
    },
    {
      key: "report",
      label: "Report",
      render: (row) =>
        row.reportId ? (
          <button
            type="button"
            className="inline-flex items-center gap-1 text-sm font-medium text-viro-600 transition hover:text-viro-700 dark:text-emerald-300 dark:hover:text-emerald-200"
            onClick={() => onOpenReportWorkspace(row.reportId)}
          >
            Open
            <ArrowRight size={14} />
          </button>
        ) : (
          <span className="text-sm text-slate-400 dark:text-slate-500">{row.status === "failed" ? "Failed" : "Not ready"}</span>
        )
    }
  ];

  return (
    <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
      <div className="space-y-6">
        <section className="dashboard-shell-surface p-4 sm:p-6">
          {showHeader ? (
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="dashboard-label">Projects</p>
                <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Scan intake workspace</h2>
                <p className="mt-2 max-w-xl text-sm leading-7 text-slate-500 dark:text-slate-400">
                  Queue one or more files. Each upload is processed asynchronously and lands in reports when analysis is complete.
                </p>
              </div>
              {showQuotaBadge ? (
                <span className="rounded-full border border-slate-200 px-3 py-2 text-xs font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  {quotaText}
                </span>
              ) : null}
            </div>
          ) : null}

          <div
            className={`dashboard-grid-overlay rounded-3xl border border-dashed border-viro-200 bg-viro-50/45 p-4 sm:p-6 dark:border-viro-800 dark:bg-viro-900/20 ${
              showHeader ? "mt-6" : ""
            }`.trim()}
          >
            <label className="flex cursor-pointer flex-col gap-3">
              <div className="dashboard-brand-icon inline-flex h-12 w-12 items-center justify-center rounded-2xl border bg-white dark:bg-slate-950">
                <UploadCloud size={20} />
              </div>
              <div>
                <p className="text-base font-semibold text-slate-950 dark:text-white">
                  {selectedFiles.length > 0 ? `${pluralize("file", selectedFiles.length)} selected` : "Drop files or browse"}
                </p>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                  Up to {maxFilesPerBatch} files per batch, {maxUploadMb} MB per file.
                </p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                aria-label="Select scan files"
                className="hidden"
                onChange={(event) => onSelectFiles(event.target.files)}
              />
            </label>
          </div>

          {selectedFiles.length > 0 ? (
            <div className="mt-5 rounded-3xl border border-slate-200/80 bg-slate-50 p-4 dark:border-slate-800/80 dark:bg-slate-900/50">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-semibold text-slate-950 dark:text-white">{pluralize("file", selectedFiles.length)} ready</p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">{formatBytes(selectedUploadBytes)} total selected</p>
                </div>
                <button
                  type="button"
                  className="dashboard-brand-outline w-full px-3 py-2 sm:w-auto"
                  onClick={onClearSelectedFiles}
                >
                  Clear
                </button>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {selectedFileNames.map((name, index) => (
                  <span
                    key={`${name}-${index}`}
                    className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300"
                  >
                    {name}
                  </span>
                ))}
              </div>
            </div>
          ) : null}

          <div className="mt-5 flex flex-wrap gap-3">
            <button
              type="button"
              className="dashboard-brand-button w-full justify-center sm:w-auto"
              onClick={onSubmitScan}
              disabled={selectedFiles.length === 0 || isSubmittingScan}
            >
              <FolderOpen size={16} />
              {isSubmittingScan ? "Queueing..." : selectedFiles.length > 1 ? `Queue ${pluralize("job", selectedFiles.length)}` : "Queue Scan Job"}
            </button>
          </div>
        </section>

        <section className="space-y-4">
          <div>
            <p className="dashboard-label">Queue activity</p>
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Current jobs</h2>
          </div>
          <DataTable columns={columns} rows={filteredJobs} page={1} totalPages={1} onPageChange={() => {}} emptyMessage="No jobs have been queued yet." />
        </section>
      </div>

      <div className="space-y-4">
        <WidgetCard title="Live queue" subtitle="Current workspace health">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Pending</p>
              <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{pendingJobs}</p>
            </div>
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Completed</p>
              <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{completedJobs}</p>
            </div>
          </div>
        </WidgetCard>

        <WidgetCard title="Focused job" subtitle="Current attention target">
          {activeJob ? (
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="text-sm font-semibold text-slate-950 dark:text-white">{activeJob.originalName}</p>
              <p className="mt-2 inline-flex rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">
                {activeJob.status}
              </p>
              <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">{formatDateTime(activeJob.createdAt)}</p>
            </div>
          ) : (
            <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">No active jobs yet. New submissions will appear here.</p>
          )}
        </WidgetCard>
      </div>
    </div>
  );
}
