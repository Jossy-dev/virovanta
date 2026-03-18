import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { Bell, ChevronDown, ChevronLeft, ChevronRight, Menu, MoonStar, Search, SunMedium, X } from "lucide-react";
import { cn, getInitials } from "../dashboardUtils";
import Button from "../../ui/Button";
import Modal from "../../ui/Modal";
import { SkeletonBlock } from "../../ui/Skeleton";
import { createEnterMotion, createStaggerContainerVariants, createStaggerItemVariants } from "../../ui/motionSystem";

const NOTIFICATION_DROPDOWN_LIMIT = 3;
const NOTIFICATION_MODAL_PAGE_SIZE = 8;

function formatNotificationDate(value) {
  const timestamp = Date.parse(String(value || ""));
  if (!Number.isFinite(timestamp)) {
    return "";
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit"
  }).format(new Date(timestamp));
}

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

export const Navbar = memo(function Navbar({
  searchQuery,
  onSearchChange,
  onOpenMobileSidebar,
  theme,
  onToggleTheme,
  notifications,
  onNotificationsViewed,
  onFetchNotificationsPage,
  onSelectNotification,
  user,
  onLogout
}) {
  const prefersReducedMotion = useReducedMotion();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showNotificationsPanel, setShowNotificationsPanel] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [notificationPageOffset, setNotificationPageOffset] = useState(0);
  const [notificationPageItems, setNotificationPageItems] = useState([]);
  const [notificationTotalCount, setNotificationTotalCount] = useState(0);
  const [notificationUnreadCount, setNotificationUnreadCount] = useState(0);
  const [notificationPanelLoading, setNotificationPanelLoading] = useState(false);
  const [notificationPanelError, setNotificationPanelError] = useState("");
  const initials = useMemo(() => getInitials(user?.username || user?.name || user?.email || "VV"), [user]);
  const displayName = useMemo(() => {
    const username = String(user?.username || user?.name || "").trim();
    return username || "Operator";
  }, [user]);
  const unreadCount = useMemo(() => notifications.filter((item) => !item.readAt).length, [notifications]);
  const dropdownNotifications = useMemo(
    () => notifications.slice(0, NOTIFICATION_DROPDOWN_LIMIT),
    [notifications]
  );
  const pageStart = notificationTotalCount === 0 ? 0 : notificationPageOffset + 1;
  const pageEnd = Math.min(notificationPageOffset + notificationPageItems.length, notificationTotalCount);
  const hasPreviousPage = notificationPageOffset > 0;
  const hasNextPage = notificationPageOffset + NOTIFICATION_MODAL_PAGE_SIZE < notificationTotalCount;
  const dropdownPanelMotion = createEnterMotion(prefersReducedMotion, { duration: 0.2, y: 6 });
  const dropdownListVariants = useMemo(
    () => createStaggerContainerVariants(prefersReducedMotion, { staggerChildren: 0.04, delayChildren: 0.01 }),
    [prefersReducedMotion]
  );
  const dropdownItemVariants = useMemo(
    () => createStaggerItemVariants(prefersReducedMotion, { y: 6, duration: 0.18 }),
    [prefersReducedMotion]
  );

  useEffect(() => {
    setNotificationUnreadCount(unreadCount);
    if (!showNotificationsPanel) {
      setNotificationTotalCount(notifications.length);
    }
  }, [notifications.length, showNotificationsPanel, unreadCount]);

  const loadNotificationPage = useCallback(
    async (offset = 0) => {
      const safeOffset = Math.max(0, Number(offset) || 0);
      const fallbackUnreadCount = notifications.filter((item) => !item.readAt).length;

      if (!onFetchNotificationsPage) {
        setNotificationPageItems(notifications.slice(safeOffset, safeOffset + NOTIFICATION_MODAL_PAGE_SIZE));
        setNotificationPageOffset(safeOffset);
        setNotificationTotalCount(notifications.length);
        setNotificationUnreadCount(fallbackUnreadCount);
        setNotificationPanelError("");
        return;
      }

      setNotificationPanelLoading(true);
      setNotificationPanelError("");

      try {
        const payload = await onFetchNotificationsPage({
          limit: NOTIFICATION_MODAL_PAGE_SIZE,
          offset: safeOffset
        });

        const pageItems = Array.isArray(payload?.notifications) ? payload.notifications : [];
        const totalCount = Number.isFinite(Number(payload?.totalCount)) ? Number(payload.totalCount) : notifications.length;
        const unreadTotal = Number.isFinite(Number(payload?.unreadCount))
          ? Number(payload.unreadCount)
          : fallbackUnreadCount;

        setNotificationPageItems(pageItems);
        setNotificationPageOffset(safeOffset);
        setNotificationTotalCount(Math.max(0, totalCount));
        setNotificationUnreadCount(Math.max(0, unreadTotal));
      } catch (_error) {
        setNotificationPanelError("Could not load more notifications right now.");
      } finally {
        setNotificationPanelLoading(false);
      }
    },
    [notifications, onFetchNotificationsPage]
  );
  const handleNotificationSelect = useCallback(
    (notification) => {
      if (!notification) {
        return;
      }

      onSelectNotification?.(notification);
      setShowNotifications(false);
      setShowNotificationsPanel(false);
      setShowUserMenu(false);
    },
    [onSelectNotification]
  );

  return (
    <header className="dashboard-shell-surface sticky top-3 z-30 mb-5 flex flex-wrap items-center gap-3 px-3 py-3 sm:top-4 sm:mb-6 sm:px-4 sm:py-4">
      <div className="flex items-center gap-2">
        <button
          type="button"
          className="dashboard-brand-control inline-flex rounded-2xl border border-slate-200 bg-white p-2 text-slate-700 lg:hidden dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
          aria-label="Open navigation"
          onClick={onOpenMobileSidebar}
        >
          <Menu size={18} />
        </button>
      </div>

      <label className="order-3 relative min-w-0 basis-full sm:order-none sm:flex-1">
        <Search
          size={16}
          className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 dark:text-slate-300"
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
          className="dashboard-brand-control inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
          aria-label="Toggle theme"
          onClick={onToggleTheme}
        >
          {theme === "dark" ? <SunMedium size={18} /> : <MoonStar size={18} />}
        </button>

        <div className="relative">
          <button
            type="button"
            className="dashboard-brand-control relative inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
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
            <motion.div
              className="absolute right-0 mt-3 w-[min(22rem,calc(100vw-1.5rem))] rounded-3xl border border-slate-200 bg-white p-3 shadow-panel dark:border-slate-800 dark:bg-slate-950 sm:w-80"
              {...dropdownPanelMotion}
            >
              <div className="mb-2 flex items-center justify-between px-2 py-1">
                <div>
                  <p className="dashboard-label">Notifications</p>
                  <h3 className="text-sm font-semibold text-slate-950 dark:text-white">Workspace updates</h3>
                </div>
                <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                  {unreadCount > 0 ? `${unreadCount} unread` : "All caught up"}
                </span>
              </div>
              <motion.div className="space-y-2" variants={dropdownListVariants} initial="hidden" animate="show">
                {dropdownNotifications.length === 0 ? (
                  <div className="rounded-2xl border border-slate-200/70 px-3 py-4 dark:border-slate-800/70">
                    <p className="text-sm text-slate-500 dark:text-slate-400">No notifications yet.</p>
                  </div>
                ) : (
                  dropdownNotifications.map((item) => {
                    const toneStyles = getNotificationToneStyles(item.tone);
                    const isActionable = Boolean(item?.entityId) && typeof onSelectNotification === "function";

                    if (isActionable) {
                      return (
                        <motion.button
                          key={item.id}
                          type="button"
                          variants={dropdownItemVariants}
                          onClick={() => handleNotificationSelect(item)}
                          className={cn(
                            "w-full cursor-pointer rounded-2xl border border-slate-200/70 px-3 py-3 text-left transition hover:border-viro-300 hover:bg-viro-50/60 dark:border-slate-800/70 dark:hover:border-viro-700 dark:hover:bg-viro-900/25",
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
                        </motion.button>
                      );
                    }

                    return (
                      <motion.div
                        key={item.id}
                        variants={dropdownItemVariants}
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
                      </motion.div>
                    );
                  })
                )}
              </motion.div>
              <div className="mt-3 border-t border-slate-200 px-1 pt-2 dark:border-slate-800">
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-full text-viro-700 dark:text-viro-300"
                  onClick={() => {
                    setShowNotifications(false);
                    setShowUserMenu(false);
                    setShowNotificationsPanel(true);
                    void loadNotificationPage(0);
                  }}
                >
                  See all notifications
                </Button>
              </div>
            </motion.div>
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
              <span className="block max-w-[160px] truncate text-xs text-slate-500 dark:text-slate-300">{user?.email}</span>
            </span>
            <ChevronDown size={16} className="hidden text-slate-500 lg:block dark:text-slate-300" />
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
                    "dashboard-brand-control flex w-full items-center rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-medium text-slate-700 hover:text-slate-900",
                    "dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800 dark:hover:text-white"
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

      <Modal
        open={showNotificationsPanel}
        onClose={() => setShowNotificationsPanel(false)}
        ariaLabel="All notifications"
        maxWidthClassName="max-w-3xl"
      >
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div>
            <p className="dashboard-label">Notifications</p>
            <h3 className="text-base font-semibold text-slate-950 dark:text-white">All workspace updates</h3>
          </div>
          <div className="flex items-center gap-2">
            <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-500 dark:bg-slate-900 dark:text-slate-400">
              {notificationUnreadCount > 0 ? `${notificationUnreadCount} unread` : "All caught up"}
            </span>
            <Button
              variant="secondary"
              size="sm"
              className="h-9 w-9 rounded-xl p-0"
              aria-label="Close notifications panel"
              onClick={() => setShowNotificationsPanel(false)}
            >
              <X size={16} />
            </Button>
          </div>
        </div>

        <div className="min-h-[320px] flex-1 overflow-y-auto p-5">
          {notificationPanelLoading ? (
            <div className="space-y-3" role="status" aria-live="polite" aria-busy="true">
              {[0, 1, 2].map((item) => (
                <div
                  key={item}
                  className="rounded-2xl border border-slate-200/70 px-4 py-4 dark:border-slate-800/70"
                >
                  <SkeletonBlock className="h-3 w-40" />
                  <SkeletonBlock className="mt-3 h-2.5 w-11/12" />
                </div>
              ))}
            </div>
          ) : notificationPanelError ? (
            <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-4 text-sm text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-300">
              {notificationPanelError}
            </div>
          ) : notificationPageItems.length === 0 ? (
            <div className="rounded-2xl border border-slate-200/70 px-4 py-6 dark:border-slate-800/70">
              <p className="text-sm text-slate-500 dark:text-slate-400">No notifications yet.</p>
            </div>
          ) : (
            <motion.div className="space-y-2" variants={dropdownListVariants} initial="hidden" animate="show">
              {notificationPageItems.map((item) => {
                const toneStyles = getNotificationToneStyles(item.tone);
                const isActionable = Boolean(item?.entityId) && typeof onSelectNotification === "function";

                if (isActionable) {
                  return (
                    <motion.button
                      key={item.id}
                      type="button"
                      variants={dropdownItemVariants}
                      onClick={() => handleNotificationSelect(item)}
                      className={cn(
                        "w-full cursor-pointer rounded-2xl border border-slate-200/70 px-4 py-4 text-left transition-colors hover:border-viro-300 hover:bg-viro-50/60 dark:border-slate-800/70 dark:hover:border-viro-700 dark:hover:bg-viro-900/25",
                        !item.readAt && "bg-slate-50/90 dark:bg-slate-900/60"
                      )}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-start gap-3">
                          <span className={cn("mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full", toneStyles.dot)} />
                          <div>
                            <p className="text-sm font-medium text-slate-900 dark:text-white">{item.title}</p>
                            <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">{item.detail}</p>
                            <p className="mt-2 text-[11px] uppercase tracking-[0.08em] text-slate-400 dark:text-slate-500">
                              {formatNotificationDate(item.createdAt)}
                            </p>
                          </div>
                        </div>
                        <span className={cn("rounded-full px-2 py-1 text-[11px] font-medium capitalize", toneStyles.pill)}>
                          {item.type.replace(/_/g, " ")}
                        </span>
                      </div>
                    </motion.button>
                  );
                }

                return (
                  <motion.article
                    key={item.id}
                    variants={dropdownItemVariants}
                    className={cn(
                      "rounded-2xl border border-slate-200/70 px-4 py-4 transition-colors dark:border-slate-800/70",
                      !item.readAt && "bg-slate-50/90 dark:bg-slate-900/60"
                    )}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-3">
                        <span className={cn("mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full", toneStyles.dot)} />
                        <div>
                          <p className="text-sm font-medium text-slate-900 dark:text-white">{item.title}</p>
                          <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">{item.detail}</p>
                          <p className="mt-2 text-[11px] uppercase tracking-[0.08em] text-slate-400 dark:text-slate-500">
                            {formatNotificationDate(item.createdAt)}
                          </p>
                        </div>
                      </div>
                      <span className={cn("rounded-full px-2 py-1 text-[11px] font-medium capitalize", toneStyles.pill)}>
                        {item.type.replace(/_/g, " ")}
                      </span>
                    </div>
                  </motion.article>
                );
              })}
            </motion.div>
          )}
        </div>

        <div className="flex items-center justify-between border-t border-slate-200 px-5 py-4 dark:border-slate-800">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {notificationTotalCount > 0 ? `Showing ${pageStart}-${pageEnd} of ${notificationTotalCount}` : "No items"}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              className="px-3"
              disabled={!hasPreviousPage || notificationPanelLoading}
              onClick={() => {
                if (!hasPreviousPage) {
                  return;
                }
                void loadNotificationPage(Math.max(0, notificationPageOffset - NOTIFICATION_MODAL_PAGE_SIZE));
              }}
            >
              <ChevronLeft size={14} />
              Prev
            </Button>
            <Button
              variant="primary"
              size="sm"
              className="px-3"
              disabled={!hasNextPage || notificationPanelLoading}
              onClick={() => {
                if (!hasNextPage) {
                  return;
                }
                void loadNotificationPage(notificationPageOffset + NOTIFICATION_MODAL_PAGE_SIZE);
              }}
            >
              Next
              <ChevronRight size={14} />
            </Button>
          </div>
        </div>
      </Modal>
    </header>
  );
});

Navbar.displayName = "Navbar";
