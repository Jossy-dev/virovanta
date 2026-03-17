import { useMemo, useState } from "react";
import { Play, RefreshCcw } from "lucide-react";
import { API_BASE_URL } from "../../appConfig";
import { CodeBlock } from "./CodeBlock";

function safeJsonParse(value) {
  const source = String(value || "").trim();
  if (!source) {
    return { ok: true, data: null };
  }

  try {
    return {
      ok: true,
      data: JSON.parse(source)
    };
  } catch (error) {
    return {
      ok: false,
      error: error?.message || "Invalid JSON payload."
    };
  }
}

export function TryItPanel({ options }) {
  const [selectedId, setSelectedId] = useState(options[0]?.id || "");
  const selected = useMemo(
    () => options.find((option) => option.id === selectedId) || options[0] || null,
    [options, selectedId]
  );
  const [baseUrl, setBaseUrl] = useState(API_BASE_URL);
  const [apiKey, setApiKey] = useState("");
  const [requestPath, setRequestPath] = useState(selected?.path || "");
  const [requestBody, setRequestBody] = useState(selected?.defaultBody || "");
  const [isRunning, setIsRunning] = useState(false);
  const [responseState, setResponseState] = useState({
    status: null,
    payload: null,
    error: ""
  });

  function resetFromSelection(nextId) {
    const match = options.find((option) => option.id === nextId);
    setSelectedId(nextId);
    setRequestPath(match?.path || "");
    setRequestBody(match?.defaultBody || "");
    setResponseState({
      status: null,
      payload: null,
      error: ""
    });
  }

  async function executeRequest() {
    if (!selected) {
      return;
    }

    const trimmedBase = String(baseUrl || "").replace(/\/+$/, "");
    const trimmedPath = String(requestPath || "").trim();
    const hasAbsoluteUrl = /^https?:\/\//i.test(trimmedPath);
    const targetUrl = hasAbsoluteUrl ? trimmedPath : `${trimmedBase}${trimmedPath.startsWith("/") ? trimmedPath : `/${trimmedPath}`}`;

    const parsedBody = safeJsonParse(requestBody);
    if (!parsedBody.ok) {
      setResponseState({
        status: null,
        payload: null,
        error: parsedBody.error
      });
      return;
    }

    setIsRunning(true);
    setResponseState((current) => ({ ...current, error: "" }));

    try {
      const response = await fetch(targetUrl, {
        method: selected.method,
        headers: {
          Accept: "application/json",
          ...(apiKey ? { "x-api-key": apiKey } : {}),
          ...(selected.method !== "GET" && parsedBody.data != null ? { "Content-Type": "application/json" } : {})
        },
        ...(selected.method !== "GET" && parsedBody.data != null ? { body: JSON.stringify(parsedBody.data) } : {})
      });

      const text = await response.text();
      let parsedPayload;
      try {
        parsedPayload = text ? JSON.parse(text) : {};
      } catch {
        parsedPayload = { raw: text };
      }

      setResponseState({
        status: response.status,
        payload: parsedPayload,
        error: ""
      });
    } catch (error) {
      setResponseState({
        status: null,
        payload: null,
        error: error?.message || "Network error while executing request."
      });
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <section className="space-y-4 rounded-3xl border border-slate-200/80 bg-white p-4 dark:border-slate-800/80 dark:bg-slate-950 sm:p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Interactive Request Runner</h3>
        <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
          Browser-side test panel
        </span>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <label className="space-y-2 text-sm text-slate-700 dark:text-slate-300">
          <span className="font-medium">Request template</span>
          <select
            value={selected?.id || ""}
            onChange={(event) => resetFromSelection(event.target.value)}
            className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700 outline-none focus:border-viro-400 focus:bg-white dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-viro-600 dark:focus:bg-slate-950"
          >
            {options.map((option) => (
              <option key={option.id} value={option.id}>
                {option.method} {option.path} - {option.name}
              </option>
            ))}
          </select>
        </label>

        <label className="space-y-2 text-sm text-slate-700 dark:text-slate-300">
          <span className="font-medium">API Base URL</span>
          <input
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
            className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700 outline-none focus:border-viro-400 focus:bg-white dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-viro-600 dark:focus:bg-slate-950"
          />
        </label>

        <label className="space-y-2 text-sm text-slate-700 dark:text-slate-300">
          <span className="font-medium">API Key</span>
          <input
            type="password"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            placeholder="svk_xxxxx.yyyyy"
            className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700 outline-none focus:border-viro-400 focus:bg-white dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-viro-600 dark:focus:bg-slate-950"
          />
        </label>

        <label className="space-y-2 text-sm text-slate-700 dark:text-slate-300">
          <span className="font-medium">Path</span>
          <input
            value={requestPath}
            onChange={(event) => setRequestPath(event.target.value)}
            className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-sm text-slate-700 outline-none focus:border-viro-400 focus:bg-white dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-viro-600 dark:focus:bg-slate-950"
          />
        </label>
      </div>

      {selected?.method !== "GET" ? (
        <div className="space-y-2">
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300">JSON body</p>
          <textarea
            value={requestBody}
            onChange={(event) => setRequestBody(event.target.value)}
            rows={8}
            className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-sm text-slate-700 outline-none focus:border-viro-400 focus:bg-white dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-viro-600 dark:focus:bg-slate-950"
          />
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={executeRequest}
          disabled={isRunning}
          className="dashboard-brand-button inline-flex items-center gap-2 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Play size={14} />
          {isRunning ? "Running..." : "Send request"}
        </button>
        <button
          type="button"
          onClick={() => resetFromSelection(selected?.id || options[0]?.id || "")}
          className="dashboard-brand-outline inline-flex items-center gap-2"
        >
          <RefreshCcw size={14} />
          Reset
        </button>
        {responseState.status ? (
          <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200">
            HTTP {responseState.status}
          </span>
        ) : null}
      </div>

      {responseState.error ? (
        <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-200">
          {responseState.error}
        </div>
      ) : null}

      {responseState.payload ? (
        <CodeBlock title="Response" language="json" code={JSON.stringify(responseState.payload, null, 2)} compact />
      ) : (
        <p className="text-sm text-slate-500 dark:text-slate-400">Execute a request to view formatted JSON response output.</p>
      )}
    </section>
  );
}
