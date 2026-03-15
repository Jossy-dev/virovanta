import { useMemo, useState } from "react";
import { Bell, ChevronDown, Menu, MoonStar, Search, SunMedium } from "lucide-react";
import { cn, getInitials } from "../dashboardUtils";

function getNotificationToneStyles(tone) {
  switch (tone) {
    case "success":
      return {
        dot: "bg-emerald-500",
        pill: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300"
      };
    case "warning":
      return {
        dot: "bg-amber-500",
        pill: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300"
      };
    case "danger":
      return {
        dot: "bg-rose-500",
        pill: "bg-rose-50 text-rose-700 dark:bg-rose-500/10 dark:text-rose-300"
      };
    default:
      return {
        dot: "bg-sky-500",
        pill: "bg-sky-50 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300"
      };
  }
}

export function Navbar({
  searchQuery,
  onSearchChange,
  onOpenMobileSidebar,
  theme,
  onToggleTheme,
  notifications,
  onNotificationsViewed,
  user,
  onLogout
}) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const initials = useMemo(() => getInitials(user?.username || user?.name || user?.email || "VV"), [user]);
  const displayName = useMemo(() => {
    const username = String(user?.username || user?.name || "").trim();
    return username || "Operator";
  }, [user]);
  const unreadCount = useMemo(() => notifications.filter((item) => !item.readAt).length, [notifications]);

  return (
    <header className="dashboard-shell-surface sticky top-3 z-30 mb-5 flex flex-wrap items-center gap-3 px-3 py-3 sm:top-4 sm:mb-6 sm:px-4 sm:py-4">
      <div className="flex items-center gap-2">
        <button
          type="button"
          className="dashboard-brand-control inline-flex rounded-2xl border border-slate-200 p-2 text-slate-600 lg:hidden dark:border-slate-800 dark:text-slate-300"
          aria-label="Open navigation"
          onClick={onOpenMobileSidebar}
        >
          <Menu size={18} />
        </button>
      </div>

      <label className="order-3 relative min-w-0 basis-full sm:order-none sm:flex-1">
        <Search
          size={16}
          className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500"
        />
        <input
          type="search"
          value={searchQuery}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder="Search scans, reports, jobs..."
          className="w-full rounded-2xl border border-slate-200 bg-slate-50 py-3 pl-11 pr-4 text-sm text-slate-700 transition placeholder:text-slate-400 focus:border-viro-300 focus:bg-white focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-viro-700 dark:focus:bg-slate-950"
        />
      </label>

      <div className="ml-auto flex shrink-0 items-center gap-2">
        <button
          type="button"
          className="dashboard-brand-control inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-slate-200 text-slate-600 dark:border-slate-800 dark:text-slate-300"
          aria-label="Toggle theme"
          onClick={onToggleTheme}
        >
          {theme === "dark" ? <SunMedium size={18} /> : <MoonStar size={18} />}
        </button>

        <div className="relative">
          <button
            type="button"
            className="dashboard-brand-control relative inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-slate-200 text-slate-600 dark:border-slate-800 dark:text-slate-300"
            aria-label="Notifications"
            onClick={() => {
              const next = !showNotifications;
              setShowNotifications(next);
              setShowUserMenu(false);
              if (next && unreadCount > 0) {
                onNotificationsViewed?.();
              }
            }}
          >
            <Bell size={18} />
            {unreadCount > 0 ? (
              <span className="absolute right-2 top-2 h-2.5 w-2.5 rounded-full bg-emerald-500" />
            ) : null}
          </button>

          {showNotifications ? (
            <div className="absolute right-0 mt-3 w-[min(22rem,calc(100vw-1.5rem))] rounded-3xl border border-slate-200 bg-white p-3 shadow-panel dark:border-slate-800 dark:bg-slate-950 sm:w-80">
              <div className="mb-2 flex items-center justify-between px-2 py-1">
                <div>
                  <p className="dashboard-label">Notifications</p>
                  <h3 className="text-sm font-semibold text-slate-950 dark:text-white">Workspace updates</h3>
                </div>
                <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                  {unreadCount > 0 ? `${unreadCount} unread` : "All caught up"}
                </span>
              </div>
              <div className="space-y-2">
                {notifications.length === 0 ? (
                  <div className="rounded-2xl border border-slate-200/70 px-3 py-4 dark:border-slate-800/70">
                    <p className="text-sm text-slate-500 dark:text-slate-400">No notifications yet.</p>
                  </div>
                ) : (
                  notifications.map((item) => {
                    const toneStyles = getNotificationToneStyles(item.tone);

                    return (
                      <div
                        key={item.id}
                        className={cn(
                          "rounded-2xl border border-slate-200/70 px-3 py-3 dark:border-slate-800/70",
                          !item.readAt && "bg-slate-50/90 dark:bg-slate-900/60"
                        )}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-3">
                            <span className={cn("mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full", toneStyles.dot)} />
                            <div>
                              <p className="text-sm font-medium text-slate-900 dark:text-white">{item.title}</p>
                              <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">{item.detail}</p>
                            </div>
                          </div>
                          <span className={cn("rounded-full px-2 py-1 text-[11px] font-medium capitalize", toneStyles.pill)}>
                            {item.type.replace(/_/g, " ")}
                          </span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          ) : null}
        </div>

        <div className="relative">
          <button
            type="button"
            className="dashboard-brand-control inline-flex items-center gap-3 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-left dark:border-slate-800 dark:bg-slate-900"
            onClick={() => {
              setShowUserMenu((current) => !current);
              setShowNotifications(false);
            }}
          >
            <span className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-viro-600 text-sm font-semibold text-white dark:bg-viro-500 dark:text-white">
              {initials}
            </span>
            <span className="hidden min-w-0 lg:block">
              <span className="block truncate text-sm font-semibold text-slate-950 dark:text-white">{displayName}</span>
              <span className="block max-w-[160px] truncate text-xs text-slate-500 dark:text-slate-400">{user?.email}</span>
            </span>
            <ChevronDown size={16} className="hidden text-slate-400 lg:block dark:text-slate-500" />
          </button>

          {showUserMenu ? (
            <div className="absolute right-0 mt-3 w-[min(18rem,calc(100vw-1.5rem))] rounded-3xl border border-slate-200 bg-white p-3 shadow-panel dark:border-slate-800 dark:bg-slate-950 sm:w-64">
              <div className="rounded-2xl border border-slate-200/70 px-3 py-3 dark:border-slate-800/70">
                <p className="text-sm font-semibold text-slate-950 dark:text-white">{displayName}</p>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{user?.email}</p>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{user?.role || "User"} account</p>
              </div>
              <div className="mt-2 space-y-1">
                <button
                  type="button"
                  className={cn(
                    "dashboard-brand-control flex w-full items-center rounded-2xl px-3 py-2 text-sm text-slate-600",
                    "dark:text-slate-300"
                  )}
                  onClick={onLogout}
                >
                  Log out
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}
