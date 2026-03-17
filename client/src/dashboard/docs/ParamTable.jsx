export function ParamTable({ title, items }) {
  if (!Array.isArray(items) || items.length === 0) {
    return null;
  }

  return (
    <div className="rounded-3xl border border-slate-200/80 dark:border-slate-800/80">
      <div className="border-b border-slate-200/80 px-4 py-3 dark:border-slate-800/80">
        <h4 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h4>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[620px] border-collapse">
          <thead>
            <tr className="bg-slate-50/80 dark:bg-slate-900/50">
              <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500 dark:text-slate-300">
                Name
              </th>
              <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500 dark:text-slate-300">
                Type
              </th>
              <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500 dark:text-slate-300">
                Required
              </th>
              <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500 dark:text-slate-300">
                Description
              </th>
              <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500 dark:text-slate-300">
                Example
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={`${item.name}-${item.type}`} className="border-t border-slate-200/70 dark:border-slate-800/70">
                <td className="px-4 py-3 font-mono text-xs text-slate-800 dark:text-slate-200">{item.name}</td>
                <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300">{item.type}</td>
                <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300">{item.required ? "Yes" : "No"}</td>
                <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300">{item.description}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-400">{item.example || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
