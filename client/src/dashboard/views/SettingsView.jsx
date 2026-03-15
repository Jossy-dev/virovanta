import { KeyRound, MonitorCog, Shield } from "lucide-react";
import { DataTable } from "../components/DataTable";
import { WidgetCard } from "../components/WidgetCard";

export function SettingsView({
  session,
  theme,
  onToggleTheme,
  newApiKeyName,
  setNewApiKeyName,
  onCreateApiKey,
  isCreatingKey,
  newApiKey,
  apiKeys,
  onRevokeApiKey
}) {
  const columns = [
    {
      key: "name",
      label: "Name",
      render: (row) => <span className="font-medium text-slate-950 dark:text-white">{row.name}</span>
    },
    { key: "keyPrefix", label: "Prefix" },
    {
      key: "status",
      label: "Status",
      render: (row) =>
        row.revokedAt ? (
          <span className="inline-flex rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">
            Revoked
          </span>
        ) : (
          <button
            type="button"
            onClick={() => onRevokeApiKey(row.id)}
            className="rounded-full border border-slate-200 px-3 py-1.5 text-xs text-slate-700 transition hover:border-slate-300 hover:bg-slate-100 dark:border-slate-800 dark:text-slate-200 dark:hover:border-slate-700 dark:hover:bg-slate-900"
          >
            Revoke
          </button>
        )
    }
  ];

  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_1.2fr]">
      <div className="space-y-4">
        <WidgetCard title="Account" subtitle="Signed-in identity">
          <div className="space-y-3">
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Email</p>
              <p className="mt-2 text-sm font-semibold text-slate-950 dark:text-white">{session.user?.email}</p>
            </div>
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Role</p>
              <p className="mt-2 text-sm font-semibold capitalize text-slate-950 dark:text-white">{session.user?.role}</p>
            </div>
          </div>
        </WidgetCard>

        <WidgetCard
          title="Appearance"
          subtitle="Dashboard theme"
          action={<MonitorCog size={18} className="text-slate-400 dark:text-slate-500" />}
        >
          <div className="flex items-center justify-between gap-4 rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
            <div>
              <p className="text-sm font-semibold text-slate-950 dark:text-white">{theme === "dark" ? "Dark mode" : "Light mode"}</p>
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Persisted locally for the signed-in dashboard.</p>
            </div>
            <button
              type="button"
              onClick={onToggleTheme}
              className="dashboard-brand-outline"
            >
              Toggle theme
            </button>
          </div>
        </WidgetCard>

        <WidgetCard title="Security" subtitle="Operational note" action={<Shield size={18} className="text-slate-400 dark:text-slate-500" />}>
          <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">
            API keys should remain scoped to active automations only. Revoke any key that is no longer tied to a live workflow.
          </p>
        </WidgetCard>
      </div>

      <div className="space-y-4">
        <WidgetCard title="API Keys" subtitle="Automation access" action={<KeyRound size={18} className="text-slate-400 dark:text-slate-500" />}>
          <div className="flex flex-col gap-3 lg:flex-row">
            <input
              value={newApiKeyName}
              onChange={(event) => setNewApiKeyName(event.target.value)}
              placeholder="Key name"
              className="flex-1 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700 transition placeholder:text-slate-400 focus:border-viro-300 focus:bg-white focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-viro-700 dark:focus:bg-slate-950"
            />
            <button
              type="button"
              onClick={onCreateApiKey}
              disabled={isCreatingKey}
              className="dashboard-brand-button w-full justify-center lg:w-auto"
            >
              {isCreatingKey ? "Creating..." : "Create API Key"}
            </button>
          </div>
          {newApiKey ? (
            <div className="mt-4 rounded-3xl border border-slate-200/80 bg-slate-50 px-4 py-4 dark:border-slate-800/80 dark:bg-slate-900/50">
              <p className="dashboard-label">Copy now</p>
              <code className="mt-3 block overflow-x-auto text-xs text-slate-700 dark:text-slate-300">{newApiKey}</code>
            </div>
          ) : null}
        </WidgetCard>

        <DataTable columns={columns} rows={apiKeys} page={1} totalPages={1} onPageChange={() => {}} emptyMessage="No API keys have been created yet." />
      </div>
    </div>
  );
}
