import { PanelLeftClose, PanelLeftOpen, X } from "lucide-react";
import { cn } from "../dashboardUtils";

export function Sidebar({
  items,
  activePath,
  onSelect,
  logoSrc,
  appName,
  tagline,
  collapsed,
  isDesktop,
  mobileOpen,
  onToggleCollapse,
  onCloseMobile
}) {
  const mobileSidebarVisible = !isDesktop && mobileOpen;
  const sidebarWidth = isDesktop ? (collapsed ? 120 : 280) : undefined;

  return (
    <>
      <button
        type="button"
        aria-label="Close navigation"
        data-mobile-state={mobileSidebarVisible ? "open" : "closed"}
        className={cn(
          "fixed inset-0 z-40 bg-slate-950/50 backdrop-blur-sm transition lg:hidden",
          mobileSidebarVisible ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"
        )}
        onClick={onCloseMobile}
      />

      <aside
        aria-hidden={!isDesktop && !mobileOpen}
        data-mobile-state={mobileSidebarVisible ? "open" : "closed"}
        className={cn(
          "dashboard-shell-surface dashboard-mobile-sidebar fixed bottom-3 left-3 top-3 z-50 flex max-w-[calc(100vw-1.5rem)] flex-col overflow-y-auto px-4 py-5 shadow-2xl transition-[transform,opacity,width] duration-300 ease-[cubic-bezier(0.22,1,0.36,1)] lg:sticky lg:top-4 lg:z-0 lg:h-[calc(100vh-2rem)] lg:max-w-none lg:shadow-panel",
          mobileSidebarVisible
            ? "translate-x-0 opacity-100 pointer-events-auto"
            : "pointer-events-none -translate-x-[calc(100%+1.5rem)] opacity-0 lg:pointer-events-auto lg:translate-x-0 lg:opacity-100"
        )}
        style={sidebarWidth ? { width: `${sidebarWidth}px` } : undefined}
      >
        <div className={cn("flex gap-3", collapsed ? "flex-col items-center" : "items-center justify-between")}>
          <div className={cn("flex items-center gap-3", collapsed && "justify-center")}>
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-slate-200 bg-slate-100 dark:border-slate-800 dark:bg-slate-900">
              <img src={logoSrc} alt={appName} className="h-7 w-7 object-contain" />
            </div>
            {!collapsed ? (
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-slate-950 dark:text-white">{appName}</p>
                <p className="truncate text-xs text-slate-500 dark:text-slate-300">{tagline}</p>
              </div>
            ) : null}
          </div>

          <div className={cn("flex items-center gap-2", collapsed && "justify-center")}>
            <button
              type="button"
              className="dashboard-brand-control hidden cursor-pointer rounded-full border border-slate-200 bg-white p-2 text-slate-700 lg:inline-flex dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              onClick={onToggleCollapse}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
            </button>
            <button
              type="button"
              className="dashboard-brand-control inline-flex cursor-pointer rounded-full border border-slate-200 bg-white p-2 text-slate-700 lg:hidden dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              onClick={onCloseMobile}
              aria-label="Close sidebar"
              title="Close sidebar"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        <nav className="mt-8 flex-1 space-y-2" aria-label="Primary dashboard navigation">
          {items.map((item) => {
            const Icon = item.icon;
            const active = item.path === activePath;

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  onSelect(item.path);
                  onCloseMobile();
                }}
                aria-label={item.label}
                title={collapsed ? item.label : undefined}
                className={cn(
                  "group relative flex w-full cursor-pointer items-center gap-3 rounded-2xl px-3 py-3 text-left transition",
                  active
                    ? "bg-viro-600 text-white shadow-soft dark:bg-viro-500 dark:text-white"
                    : "bg-white/85 text-slate-700 hover:bg-viro-50 hover:text-viro-700 dark:bg-slate-900/70 dark:text-slate-100 dark:hover:bg-viro-900/35 dark:hover:text-emerald-200"
                )}
              >
                <span
                  className={cn(
                    "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border transition",
                    active
                      ? "border-white/15 bg-white/10"
                      : "border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-950"
                  )}
                >
                  <Icon size={18} strokeWidth={2} />
                </span>
                {!collapsed ? (
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-semibold">{item.label}</span>
                    <span className={cn("block truncate text-xs", active ? "text-white/80" : "text-slate-500 dark:text-slate-300")}>
                      {item.description}
                    </span>
                  </span>
                ) : null}
                {collapsed ? <span className="dashboard-floating-tooltip">{item.label}</span> : null}
              </button>
            );
          })}
        </nav>

        {!collapsed && isDesktop ? (
          <div className="dashboard-grid-panel min-h-[136px] px-4 py-4">
            <div className="flex h-full flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="h-2.5 w-2.5 rounded-full bg-viro-600 dark:bg-viro-400" />
                <span className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-viro-200 bg-white/85 dark:border-viro-800 dark:bg-slate-950/80">
                  <img src={logoSrc} alt="" className="h-5 w-5 object-contain opacity-80" aria-hidden="true" />
                </span>
              </div>
              <div className="space-y-2">
                <div className="h-2 w-20 rounded-full bg-viro-600/20 dark:bg-viro-400/25" />
                <div className="h-2 w-28 rounded-full bg-slate-200/90 dark:bg-slate-800/90" />
                <div className="h-2 w-16 rounded-full bg-slate-200/90 dark:bg-slate-800/90" />
              </div>
            </div>
          </div>
        ) : null}
      </aside>
    </>
  );
}
