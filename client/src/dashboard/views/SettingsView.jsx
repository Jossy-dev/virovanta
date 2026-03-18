import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Copy, KeyRound, MonitorCog, Shield } from "lucide-react";
import { DataTable } from "../components/DataTable";
import { WidgetCard } from "../components/WidgetCard";

const API_SCOPE_OPTIONS = Object.freeze([
  {
    value: "jobs:read",
    label: "Jobs Read",
    description: "View queued, processing, and completed job states."
  },
  {
    value: "jobs:write",
    label: "Jobs Write",
    description: "Create new scan jobs by uploading files and submitting URL or website-safety targets."
  },
  {
    value: "reports:read",
    label: "Reports Read",
    description: "Access report details, IOC output, and integrity status."
  },
  {
    value: "reports:share",
    label: "Reports Share",
    description: "Generate share links for selected reports."
  },
  {
    value: "reports:delete",
    label: "Reports Delete",
    description: "Delete reports from the user workspace."
  },
  {
    value: "analytics:read",
    label: "Analytics Read",
    description: "Read usage, verdict, and posture analytics."
  }
]);

function sortApiKeyScopes(scopes = []) {
  const order = API_SCOPE_OPTIONS.map((option) => option.value);
  const normalized = Array.isArray(scopes)
    ? scopes
        .map((value) => String(value || "").trim().toLowerCase())
        .filter((value, index, source) => value && source.indexOf(value) === index)
    : [];

  return normalized.sort((left, right) => {
    const leftIndex = order.indexOf(left);
    const rightIndex = order.indexOf(right);
    const safeLeftIndex = leftIndex === -1 ? Number.POSITIVE_INFINITY : leftIndex;
    const safeRightIndex = rightIndex === -1 ? Number.POSITIVE_INFINITY : rightIndex;
    if (safeLeftIndex !== safeRightIndex) {
      return safeLeftIndex - safeRightIndex;
    }

    return left.localeCompare(right);
  });
}

function resolveScopeLabel(scope) {
  return API_SCOPE_OPTIONS.find((option) => option.value === scope)?.label || scope;
}

function formatScopeBadge(scope) {
  const [group = "", access = ""] = String(scope || "").split(":");
  return `${group} ${access}`.trim();
}

function formatDateCell(value) {
  if (!value) {
    return "Never";
  }

  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return "Unknown";
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric"
  }).format(new Date(timestamp));
}

export function SettingsView({
  session,
  theme,
  onToggleTheme,
  newApiKeyName,
  newApiKeyScopes,
  setNewApiKeyName,
  setNewApiKeyScopes,
  onCreateApiKey,
  isCreatingKey,
  newApiKey,
  apiKeys,
  onRevokeApiKey
}) {
  const [isCopying, setIsCopying] = useState(false);
  const [keyCopied, setKeyCopied] = useState(false);
  const canCopyApiKey = typeof navigator !== "undefined" && Boolean(navigator?.clipboard?.writeText);
  const selectedScopeSet = useMemo(() => new Set(sortApiKeyScopes(newApiKeyScopes)), [newApiKeyScopes]);
  const selectedScopeCount = selectedScopeSet.size;
  const canCreateKey = !isCreatingKey && String(newApiKeyName || "").trim().length >= 3 && selectedScopeCount > 0;

  useEffect(() => {
    setKeyCopied(false);
    setIsCopying(false);
  }, [newApiKey]);

  function toggleScope(scopeValue) {
    setNewApiKeyScopes((current) => {
      const normalized = sortApiKeyScopes(current);
      if (normalized.includes(scopeValue)) {
        return normalized.filter((scope) => scope !== scopeValue);
      }

      return sortApiKeyScopes([...normalized, scopeValue]);
    });
  }

  function selectAllScopes() {
    setNewApiKeyScopes(API_SCOPE_OPTIONS.map((option) => option.value));
  }

  function clearScopes() {
    setNewApiKeyScopes([]);
  }

  async function copyNewApiKey() {
    if (!newApiKey || !canCopyApiKey) {
      return;
    }

    setIsCopying(true);

    try {
      await navigator.clipboard.writeText(newApiKey);
      setKeyCopied(true);
    } finally {
      setIsCopying(false);
    }
  }

  function submitApiKeyCreation() {
    onCreateApiKey({
      name: String(newApiKeyName || "").trim(),
      scopes: sortApiKeyScopes(newApiKeyScopes)
    });
  }

  const columns = [
    {
      key: "name",
      label: "Key",
      render: (row) => (
        <div className="space-y-0.5">
          <span className="font-medium text-slate-950 dark:text-white">{row.name}</span>
          <p className="text-xs text-slate-500 dark:text-slate-400">{row.keyPrefix}</p>
        </div>
      )
    },
    {
      key: "scopes",
      label: "Scopes",
      className: "min-w-[220px]",
      render: (row) => {
        const scopes = sortApiKeyScopes(row.scopes);
        if (scopes.length === 0) {
          return <span className="text-xs text-slate-400 dark:text-slate-500">No scopes</span>;
        }

        return (
          <div className="flex flex-wrap justify-end gap-1.5 md:justify-start">
            {scopes.map((scope) => (
              <span
                key={`${row.id}-${scope}`}
                className="inline-flex rounded-full border border-viro-200 bg-viro-50 px-2 py-1 text-[11px] font-medium uppercase tracking-[0.08em] text-viro-700 dark:border-viro-800 dark:bg-viro-900/30 dark:text-viro-200"
                title={resolveScopeLabel(scope)}
              >
                {formatScopeBadge(scope)}
              </span>
            ))}
          </div>
        );
      }
    },
    {
      key: "createdAt",
      label: "Created",
      render: (row) => formatDateCell(row.createdAt)
    },
    {
      key: "lastUsedAt",
      label: "Last Used",
      render: (row) => formatDateCell(row.lastUsedAt)
    },
    {
      key: "status",
      label: "Status",
      render: (row) =>
        row.revokedAt ? (
          <span className="inline-flex rounded-full border border-slate-300 bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
            Revoked
          </span>
        ) : (
          <span className="inline-flex rounded-full border border-viro-200 bg-viro-50 px-2.5 py-1 text-xs font-medium text-viro-700 dark:border-viro-800 dark:bg-viro-900/30 dark:text-viro-200">
            Active
          </span>
        )
    },
    {
      key: "actions",
      label: "Action",
      render: (row) =>
        row.revokedAt ? (
          <span className="text-xs text-slate-400 dark:text-slate-500">Unavailable</span>
        ) : (
          <button
            type="button"
            onClick={() => onRevokeApiKey(row.id)}
            className="rounded-full border border-slate-200 px-3 py-1.5 text-xs text-slate-700 transition hover:border-red-200 hover:bg-red-50 hover:text-red-700 dark:border-slate-800 dark:text-slate-200 dark:hover:border-red-800 dark:hover:bg-red-950/30 dark:hover:text-red-200"
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
          <div className="space-y-3">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-200" htmlFor="api-key-name">
              Key name
            </label>
            <input
              id="api-key-name"
              value={newApiKeyName}
              onChange={(event) => setNewApiKeyName(event.target.value)}
              placeholder="Key name"
              autoComplete="off"
              className="flex-1 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700 transition placeholder:text-slate-400 focus:border-viro-300 focus:bg-white focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-viro-700 dark:focus:bg-slate-950"
            />
          </div>

          <div className="mt-4 rounded-3xl border border-slate-200/80 bg-slate-50/80 px-4 py-4 dark:border-slate-800/80 dark:bg-slate-900/50">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm font-semibold text-slate-900 dark:text-white">Scope permissions</p>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={selectAllScopes}
                  className="dashboard-brand-outline px-3 py-1.5 text-xs"
                >
                  Select all
                </button>
                <button
                  type="button"
                  onClick={clearScopes}
                  className="dashboard-brand-outline px-3 py-1.5 text-xs"
                >
                  Clear
                </button>
              </div>
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              {API_SCOPE_OPTIONS.map((scope) => {
                const active = selectedScopeSet.has(scope.value);
                return (
                  <label
                    key={scope.value}
                    className={`flex cursor-pointer items-start gap-3 rounded-2xl border px-3 py-3 text-left transition ${
                      active
                        ? "border-viro-300 bg-viro-50 text-viro-900 dark:border-viro-700 dark:bg-viro-900/30 dark:text-viro-100"
                        : "border-slate-200 bg-white text-slate-700 hover:border-viro-200 hover:bg-viro-50/70 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200 dark:hover:border-viro-800 dark:hover:bg-viro-950/25"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={active}
                      onChange={() => toggleScope(scope.value)}
                      className="mt-0.5 h-4 w-4 rounded border-slate-300 text-viro-600 focus:ring-viro-400 dark:border-slate-700 dark:bg-slate-900 dark:text-viro-400 dark:focus:ring-viro-700"
                    />
                    <span className="min-w-0">
                      <span className="block text-sm font-semibold">{scope.label}</span>
                      <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">{scope.description}</span>
                    </span>
                  </label>
                );
              })}
            </div>

            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {selectedScopeCount} scope{selectedScopeCount === 1 ? "" : "s"} selected
              </p>
              <button
                type="button"
                onClick={submitApiKeyCreation}
                disabled={!canCreateKey}
                className="dashboard-brand-button w-full justify-center disabled:cursor-not-allowed disabled:opacity-45 sm:w-auto"
              >
                {isCreatingKey ? "Creating..." : "Create API Key"}
              </button>
            </div>
          </div>

          {newApiKey ? (
            <div className="mt-4 rounded-3xl border border-viro-200 bg-viro-50/70 px-4 py-4 dark:border-viro-800 dark:bg-viro-900/25">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-start gap-2">
                  <CheckCircle2 size={18} className="mt-0.5 text-viro-600 dark:text-viro-300" />
                  <div>
                    <p className="text-sm font-semibold text-viro-900 dark:text-viro-100">API key created successfully</p>
                    <p className="mt-1 text-xs text-viro-700 dark:text-viro-200">Copy and store this key now. It is shown only once.</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={copyNewApiKey}
                  disabled={isCopying || !canCopyApiKey}
                  className="dashboard-brand-outline inline-flex items-center gap-2 px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-45"
                >
                  <Copy size={14} />
                  {keyCopied ? "Copied" : isCopying ? "Copying..." : "Copy key"}
                </button>
              </div>
              <code className="mt-3 block overflow-x-auto rounded-2xl border border-viro-200 bg-white/80 px-3 py-2 text-xs text-slate-700 dark:border-viro-900 dark:bg-slate-950/70 dark:text-slate-200">
                {newApiKey}
              </code>
            </div>
          ) : null}
        </WidgetCard>

        <DataTable columns={columns} rows={apiKeys} page={1} totalPages={1} onPageChange={() => {}} emptyMessage="No API keys have been created yet." />
      </div>
    </div>
  );
}
