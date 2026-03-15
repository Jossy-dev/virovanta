import { useMemo, useState } from "react";
import { UserPlus } from "lucide-react";
import { DataTable } from "../components/DataTable";
import { WidgetCard } from "../components/WidgetCard";

export function UsersView({ teamRows, quotaText, onInviteUser }) {
  const [inviteEmail, setInviteEmail] = useState("");
  const columns = useMemo(
    () => [
      {
        key: "name",
        label: "User",
        render: (row) => (
          <div>
            <div className="font-medium text-slate-950 dark:text-white">{row.name}</div>
            <div className="text-xs text-slate-500 dark:text-slate-400">{row.email}</div>
          </div>
        )
      },
      { key: "role", label: "Role" },
      {
        key: "status",
        label: "Status",
        render: (row) => (
          <span className="inline-flex rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">
            {row.status}
          </span>
        )
      },
      { key: "lastSeen", label: "Last Seen" }
    ],
    []
  );

  return (
    <div className="grid gap-6 xl:grid-cols-[1.35fr_0.9fr]">
      <section className="space-y-4">
        <div>
          <p className="dashboard-label">Users</p>
          <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Workspace access</h2>
        </div>
        <DataTable columns={columns} rows={teamRows} page={1} totalPages={1} onPageChange={() => {}} emptyMessage="No users found." />
      </section>

      <div className="space-y-4">
        <WidgetCard title="Invite User" subtitle="Prepare collaboration access">
          <div className="space-y-3">
            <input
              type="email"
              value={inviteEmail}
              onChange={(event) => setInviteEmail(event.target.value)}
              placeholder="name@company.com"
              className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700 transition placeholder:text-slate-400 focus:border-viro-300 focus:bg-white focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-viro-700 dark:focus:bg-slate-950"
            />
            <button
              type="button"
              onClick={() => {
                if (!inviteEmail.trim()) {
                  return;
                }

                onInviteUser(inviteEmail);
                setInviteEmail("");
              }}
              className="dashboard-brand-button px-4"
            >
              <UserPlus size={16} />
              Send invite
            </button>
          </div>
        </WidgetCard>

        <WidgetCard title="Usage" subtitle="Rolling quota snapshot">
          <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">
            {quotaText}. Quota now updates from the real last 24 hours of scan jobs instead of a calendar-day reset.
          </p>
        </WidgetCard>
      </div>
    </div>
  );
}
