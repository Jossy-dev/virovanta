import { ChevronLeft, ChevronRight } from "lucide-react";

export function DataTable({
  columns,
  rows,
  page,
  totalPages,
  onPageChange,
  emptyMessage = "No records available."
}) {
  return (
    <div className="dashboard-subtle-panel overflow-hidden">
      <div className="space-y-3 p-3 md:hidden">
        {rows.length === 0 ? (
          <div className="rounded-3xl border border-slate-200/70 px-4 py-8 text-center text-sm text-slate-500 dark:border-slate-800/70 dark:text-slate-400">
            {emptyMessage}
          </div>
        ) : (
          rows.map((row) => (
            <article key={row.id} className="rounded-3xl border border-slate-200/80 bg-white px-4 py-4 dark:border-slate-800/80 dark:bg-slate-950">
              <div className="space-y-3">
                {columns.map((column) => (
                  <div key={column.key} className="flex items-start justify-between gap-4">
                    <span className="dashboard-label pt-1">{column.label}</span>
                    <div className="min-w-0 flex-1 text-right text-sm text-slate-600 dark:text-slate-300">
                      {column.render ? column.render(row) : row[column.key]}
                    </div>
                  </div>
                ))}
              </div>
            </article>
          ))
        )}
      </div>

      <div className="dashboard-scrollbar hidden overflow-x-auto md:block">
        <table className="w-full min-w-[680px] border-collapse">
          <thead>
            <tr className="border-b border-slate-200/80 bg-slate-50/80 dark:border-slate-800/80 dark:bg-slate-900/60">
              {columns.map((column) => (
                <th
                  key={column.key}
                  className={`px-5 py-4 text-left text-[11px] font-medium uppercase tracking-[0.18em] text-slate-400 dark:text-slate-500 ${
                    column.headerClassName || ""
                  }`.trim()}
                >
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-5 py-10 text-center text-sm text-slate-500 dark:text-slate-400"
                >
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr
                  key={row.id}
                  className="border-b border-slate-200/70 transition-colors hover:bg-slate-50 dark:border-slate-800/70 dark:hover:bg-slate-900/50"
                >
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={`px-5 py-4 align-middle text-sm text-slate-600 dark:text-slate-300 ${column.className || ""}`.trim()}
                    >
                      {column.render ? column.render(row) : row[column.key]}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 ? (
        <div className="flex flex-col gap-3 border-t border-slate-200/80 px-4 py-4 dark:border-slate-800/80 sm:flex-row sm:items-center sm:justify-between sm:px-5">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Page {page} of {totalPages}
          </p>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="dashboard-brand-outline inline-flex items-center gap-1 px-3 py-2 text-slate-600 disabled:cursor-not-allowed disabled:opacity-45 dark:text-slate-300"
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1}
            >
              <ChevronLeft size={16} />
              Prev
            </button>
            <button
              type="button"
              className="dashboard-brand-outline inline-flex items-center gap-1 px-3 py-2 text-slate-600 disabled:cursor-not-allowed disabled:opacity-45 dark:text-slate-300"
              onClick={() => onPageChange(page + 1)}
              disabled={page >= totalPages}
            >
              Next
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
