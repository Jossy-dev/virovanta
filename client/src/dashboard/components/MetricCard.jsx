import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";

export function MetricCard({ icon: Icon, title, value, delta, trend = "up", tone = "positive", description }) {
  const TrendIcon = trend === "down" ? ArrowDownRight : trend === "flat" ? Minus : ArrowUpRight;
  const badgeClassName =
    tone === "negative"
      ? "bg-rose-50 text-rose-700 ring-1 ring-rose-200 dark:bg-rose-500/10 dark:text-rose-300 dark:ring-rose-500/20"
      : tone === "neutral"
        ? "bg-slate-100 text-slate-600 ring-1 ring-slate-200 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-700"
        : "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/20";

  return (
    <article className="dashboard-subtle-panel group relative overflow-hidden p-4 transition duration-200 hover:-translate-y-0.5 hover:shadow-panel sm:p-5">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div className="rounded-2xl border border-slate-200/80 bg-slate-100 p-3 text-slate-700 dark:border-slate-800/80 dark:bg-slate-900 dark:text-slate-200">
          <Icon size={18} strokeWidth={2} />
        </div>
        <span
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium ${badgeClassName}`}
        >
          <TrendIcon size={14} strokeWidth={2} />
          {delta}
        </span>
      </div>

      <div className="space-y-2">
        <p className="dashboard-label">{title}</p>
        <div className="text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white sm:text-3xl">{value}</div>
        <p className="dashboard-muted-text">{description}</p>
      </div>
    </article>
  );
}
