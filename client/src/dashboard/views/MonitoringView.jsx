import { useMemo, useState } from "react";
import { Activity, Globe2, Link2, Play, Plus, Trash2 } from "lucide-react";
import Button from "../../ui/Button";
import { DataTable } from "../components/DataTable";
import { WidgetCard } from "../components/WidgetCard";

const DEFAULT_MONITOR_FORM = Object.freeze({
  name: "",
  targetType: "website",
  target: "",
  cadenceHours: 24,
  notes: ""
});

export function MonitoringView({
  monitors,
  workspaceSummary,
  isManagingMonitor,
  onCreateMonitor,
  onRunMonitor,
  onDeleteMonitor,
  formatDateTime
}) {
  const [form, setForm] = useState(DEFAULT_MONITOR_FORM);
  const [error, setError] = useState("");

  const activeMonitorCount = useMemo(
    () => monitors.filter((monitor) => !monitor.deletedAt && monitor.status !== "deleted").length,
    [monitors]
  );

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    try {
      await onCreateMonitor({
        ...form,
        cadenceHours: Number(form.cadenceHours) || 24
      });
      setForm(DEFAULT_MONITOR_FORM);
    } catch (submitError) {
      setError(submitError?.message || "Could not create monitor.");
    }
  }

  const columns = [
    {
      key: "name",
      label: "Monitor",
      render: (row) => (
        <div className="space-y-1">
          <p className="font-semibold text-slate-950 dark:text-white">{row.name}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400">{row.target}</p>
        </div>
      )
    },
    {
      key: "status",
      label: "State",
      render: (row) => (
        <span className="inline-flex rounded-full border border-slate-200 px-2.5 py-1 text-xs font-medium text-slate-700 dark:border-slate-800 dark:text-slate-300">
          {row.status}
        </span>
      )
    },
    {
      key: "cadence",
      label: "Cadence",
      render: (row) => `${row.cadenceHours}h`
    },
    {
      key: "lastVerdict",
      label: "Last verdict",
      render: (row) =>
        row.lastVerdict ? (
          <div className="space-y-1">
            <p className="text-sm font-semibold capitalize text-slate-950 dark:text-white">{row.lastVerdict}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">Risk {row.lastRiskScore ?? "n/a"}/100</p>
          </div>
        ) : (
          "Not run"
        )
    },
    {
      key: "changes",
      label: "Latest change",
      render: (row) => row.lastChangeSummary?.[0] || "No drift recorded yet"
    },
    {
      key: "nextCheckAt",
      label: "Next run",
      render: (row) => (row.nextCheckAt ? formatDateTime(row.nextCheckAt) : "Pending")
    },
    {
      key: "actions",
      label: "Actions",
      render: (row) => (
        <div className="flex flex-wrap justify-end gap-2 md:justify-start">
          <Button type="button" variant="ghost" size="sm" onClick={() => { void onRunMonitor(row.id); }}>
            <Play size={14} />
            Run now
          </Button>
          <Button type="button" variant="ghost" size="sm" className="text-rose-600 hover:text-rose-700" onClick={() => { void onDeleteMonitor(row.id); }}>
            <Trash2 size={14} />
            Delete
          </Button>
        </div>
      )
    }
  ];

  const monitorLimit = workspaceSummary?.entitlements?.limits?.monitors;

  return (
    <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
      <div className="space-y-6">
        <WidgetCard
          title="Continuous monitoring"
          subtitle="Track URLs and websites for change"
          action={<Activity size={18} className="text-slate-400 dark:text-slate-500" />}
        >
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Active monitors</p>
              <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{activeMonitorCount}</p>
            </div>
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Plan allowance</p>
              <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">
                {monitorLimit == null ? "Unlimited" : monitorLimit}
              </p>
            </div>
          </div>
          <p className="mt-4 text-sm leading-7 text-slate-500 dark:text-slate-400">
            Use monitors for recurring watch targets so ViroVanta can automatically requeue checks in the background and alert when verdicts, redirects, or website posture changes.
          </p>
        </WidgetCard>

        <WidgetCard title="Create monitor" subtitle="Add a watch target">
          <form className="space-y-4" onSubmit={handleSubmit}>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                <span>Name</span>
                <input
                  type="text"
                  value={form.name}
                  onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                  className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                  placeholder="Vendor login monitor"
                />
              </label>
              <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                <span>Type</span>
                <select
                  value={form.targetType}
                  onChange={(event) => setForm((current) => ({ ...current, targetType: event.target.value }))}
                  className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                >
                  <option value="website">Website posture</option>
                  <option value="url">URL destination</option>
                </select>
              </label>
            </div>
            <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
              <span>Target</span>
              <input
                type="text"
                value={form.target}
                onChange={(event) => setForm((current) => ({ ...current, target: event.target.value }))}
                className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                placeholder={form.targetType === "website" ? "https://vendor.example.com" : "https://secure.example.com/login"}
              />
            </label>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                <span>Cadence (hours)</span>
                <input
                  type="number"
                  min="1"
                  max="720"
                  value={form.cadenceHours}
                  onChange={(event) => setForm((current) => ({ ...current, cadenceHours: event.target.value }))}
                  className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                />
              </label>
              <label className="grid gap-2 text-sm text-slate-600 dark:text-slate-300">
                <span>Analyst note</span>
                <input
                  type="text"
                  value={form.notes}
                  onChange={(event) => setForm((current) => ({ ...current, notes: event.target.value }))}
                  className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-950 outline-none transition focus:border-viro-400 dark:border-slate-800 dark:bg-slate-950 dark:text-white"
                  placeholder="Watch for redirect drift"
                />
              </label>
            </div>
            {error ? <p className="text-sm text-rose-600 dark:text-rose-300">{error}</p> : null}
            <Button type="submit" variant="primary" disabled={isManagingMonitor}>
              <Plus size={16} />
              {isManagingMonitor ? "Creating..." : "Create monitor"}
            </Button>
          </form>
        </WidgetCard>
      </div>

      <WidgetCard title="Watchlist" subtitle="Queued change detection targets">
        {monitors.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-300/80 px-5 py-8 text-sm leading-7 text-slate-500 dark:border-slate-800 dark:text-slate-400">
            No monitors yet. Add recurring website or URL targets here so you can re-alert on changes instead of running one-off scans only.
          </div>
        ) : (
          <DataTable columns={columns} rows={monitors} />
        )}
        {monitors.length > 0 ? (
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <div className="flex items-center gap-2">
                <Globe2 size={16} className="text-slate-400" />
                <p className="text-sm font-semibold text-slate-950 dark:text-white">Website posture tracking</p>
              </div>
              <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Best for vendor portals, login pages, and public trust surfaces.</p>
            </div>
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <div className="flex items-center gap-2">
                <Link2 size={16} className="text-slate-400" />
                <p className="text-sm font-semibold text-slate-950 dark:text-white">URL destination tracking</p>
              </div>
              <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Best for phishing links or campaign URLs that need rechecks after takedowns and redirects.</p>
            </div>
          </div>
        ) : null}
      </WidgetCard>
    </div>
  );
}
