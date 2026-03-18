import { cn } from "../dashboard/dashboardUtils";

export function SkeletonBlock({ className = "" }) {
  return (
    <span
      aria-hidden="true"
      className={cn("block animate-pulse rounded-lg bg-slate-200/85 dark:bg-slate-800/85", className)}
    />
  );
}

export function SkeletonText({
  lines = 3,
  lineClassName = "h-3"
}) {
  return (
    <div className="grid gap-2" aria-hidden="true">
      {Array.from({ length: lines }, (_value, index) => (
        <SkeletonBlock
          key={index}
          className={cn(
            lineClassName,
            index === lines - 1 ? "w-3/5" : "w-full"
          )}
        />
      ))}
    </div>
  );
}
