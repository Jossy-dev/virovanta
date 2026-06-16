import { cn } from "../dashboardUtils";

function clampProgress(value) {
  return Math.max(0, Math.min(100, Number(value) || 0));
}

function fallbackStage(status) {
  if (status === "completed") {
    return "Completed";
  }

  if (status === "failed") {
    return "Failed";
  }

  if (status === "cancelled") {
    return "Cancelled";
  }

  if (status === "cancelling") {
    return "Cancelling";
  }

  if (status === "processing") {
    return "Processing";
  }

  return "Queued";
}

function progressTone(status) {
  if (status === "completed") {
    return "bg-emerald-500";
  }

  if (status === "failed") {
    return "bg-rose-500";
  }

  if (status === "cancelled") {
    return "bg-slate-400 dark:bg-slate-500";
  }

  if (status === "cancelling") {
    return "bg-amber-500";
  }

  return "bg-viro-500";
}

export function JobProgressBar({ job, compact = false, className = "" }) {
  const status = String(job?.status || "queued").toLowerCase();
  const progressPercent = clampProgress(job?.progressPercent);
  const progressStage = String(job?.progressStage || "").trim() || fallbackStage(status);
  const progressDetail = String(job?.progressDetail || "").trim();

  return (
    <div className={cn("space-y-2", className)}>
      <div className="flex items-center justify-between gap-3 text-[11px] font-medium uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
        <span>{progressStage}</span>
        <span>{progressPercent}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-slate-200/90 dark:bg-slate-800">
        <div
          className={cn("h-full rounded-full transition-[width] duration-300 ease-out", progressTone(status))}
          style={{ width: `${progressPercent}%` }}
        />
      </div>
      {!compact && progressDetail ? <p className="text-xs leading-6 text-slate-500 dark:text-slate-400">{progressDetail}</p> : null}
    </div>
  );
}
