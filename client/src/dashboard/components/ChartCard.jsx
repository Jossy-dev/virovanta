import { memo } from "react";

export const ChartCard = memo(function ChartCard({ title, subtitle, action, children, className = "" }) {
  return (
    <section className={`dashboard-subtle-panel p-4 sm:p-5 ${className}`.trim()}>
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-1">
          <p className="dashboard-label">{title}</p>
          <h3 className="text-lg font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">{subtitle}</h3>
        </div>
        {action}
      </div>
      {children}
    </section>
  );
});

ChartCard.displayName = "ChartCard";
