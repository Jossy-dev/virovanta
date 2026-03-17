import { useMemo, useState } from "react";
import { CodeBlock } from "./CodeBlock";
import { ParamTable } from "./ParamTable";
import { ResponseViewer } from "./ResponseViewer";

const METHOD_STYLE = Object.freeze({
  GET: "bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-500/10 dark:text-sky-200 dark:border-sky-800",
  POST: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-200 dark:border-emerald-800",
  PUT: "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-500/10 dark:text-amber-200 dark:border-amber-800",
  DELETE: "bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-500/10 dark:text-rose-200 dark:border-rose-800"
});

const SAMPLE_TABS = Object.freeze([
  { id: "curl", label: "curl", language: "curl" },
  { id: "javascript", label: "JavaScript", language: "javascript" },
  { id: "python", label: "Python", language: "python" }
]);

export function EndpointCard({ endpoint }) {
  const [activeSample, setActiveSample] = useState("curl");
  const methodStyle = METHOD_STYLE[endpoint.method] || METHOD_STYLE.GET;
  const sampleLanguage = useMemo(
    () => SAMPLE_TABS.find((tab) => tab.id === activeSample)?.language || "curl",
    [activeSample]
  );

  return (
    <article className="space-y-4 rounded-3xl border border-slate-200/80 bg-white p-4 dark:border-slate-800/80 dark:bg-slate-950 sm:p-5">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${methodStyle}`}>{endpoint.method}</span>
        <code className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200">
          {endpoint.path}
        </code>
      </div>

      <div className="space-y-2">
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{endpoint.name}</h3>
        <p className="text-sm leading-7 text-slate-600 dark:text-slate-300">{endpoint.description}</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
          Auth required: {endpoint.authRequired ? "Yes" : "No"}
        </span>
        {endpoint.scopes.map((scope) => (
          <span
            key={`${endpoint.id}-${scope}`}
            className="rounded-full border border-viro-200 bg-viro-50 px-3 py-1 text-xs font-medium text-viro-700 dark:border-viro-800 dark:bg-viro-900/25 dark:text-viro-200"
          >
            {scope}
          </span>
        ))}
      </div>

      <ParamTable title="Path Parameters" items={endpoint.pathParams} />
      <ParamTable title="Query Parameters" items={endpoint.queryParams} />

      {endpoint.bodySchema ? (
        <ResponseViewer
          title="Body Schema"
          payload={endpoint.bodySchema}
        />
      ) : null}

      <div className="rounded-3xl border border-slate-200/80 dark:border-slate-800/80">
        <div className="border-b border-slate-200/80 px-4 py-3 dark:border-slate-800/80">
          <h4 className="text-sm font-semibold text-slate-900 dark:text-white">Status Codes</h4>
        </div>
        <ul className="space-y-0">
          {endpoint.statusCodes.map((entry) => (
            <li
              key={`${endpoint.id}-${entry.code}`}
              className="flex flex-wrap items-center gap-3 border-t border-slate-200/70 px-4 py-3 text-sm text-slate-700 first:border-t-0 dark:border-slate-800/70 dark:text-slate-300"
            >
              <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 font-mono text-xs dark:border-slate-700 dark:bg-slate-900">
                {entry.code}
              </span>
              <span>{entry.meaning}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <ResponseViewer title="Success Response" payload={endpoint.successExample} />
        <ResponseViewer title="Error Response" payload={endpoint.errorExample} />
      </div>

      <div className="space-y-3 rounded-3xl border border-slate-200/80 p-4 dark:border-slate-800/80">
        <div className="flex flex-wrap gap-2">
          {SAMPLE_TABS.map((tab) => (
            <button
              key={`${endpoint.id}-${tab.id}`}
              type="button"
              onClick={() => setActiveSample(tab.id)}
              className={`rounded-full px-3 py-1.5 text-xs font-medium transition ${
                activeSample === tab.id
                  ? "bg-viro-600 text-white dark:bg-viro-500"
                  : "bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <CodeBlock
          title={`${endpoint.name} (${activeSample})`}
          language={sampleLanguage}
          code={endpoint.codeSamples[activeSample]}
        />
      </div>
    </article>
  );
}
