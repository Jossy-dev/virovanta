import { useEffect, useMemo, useState } from "react";
import { BookOpenText, KeyRound, LifeBuoy, Search, TerminalSquare, Workflow } from "lucide-react";
import { API_BASE_URL } from "../../appConfig";
import { EndpointCard } from "../docs/EndpointCard";
import { CodeBlock } from "../docs/CodeBlock";
import { ParamTable } from "../docs/ParamTable";
import { ResponseViewer } from "../docs/ResponseViewer";
import { TryItPanel } from "../docs/TryItPanel";
import {
  API_ENDPOINTS,
  DOCS_AUTH_TEXT,
  DOCS_ERROR_FORMAT,
  DOCS_JS_SDK_SAMPLE,
  DOCS_LANDING,
  DOCS_LANDING_SNIPPETS,
  DOCS_NAV_SECTIONS,
  DOCS_PYTHON_SDK_SAMPLE,
  DOCS_QUICKSTART_SAMPLES,
  DOCS_QUICKSTART_STEPS,
  DOCS_RATE_LIMIT_HEADERS,
  DOCS_RATE_LIMITS,
  DOCS_RETRY_GUIDANCE,
  DOCS_TRY_IT_OPTIONS,
  DOCS_WEBHOOK
} from "../docs/apiDocsConfig";

const SNIPPET_TABS = Object.freeze([
  { id: "curl", label: "curl", language: "curl" },
  { id: "javascript", label: "JavaScript", language: "javascript" },
  { id: "python", label: "Python", language: "python" }
]);

const REFERENCE_PLACEHOLDER = "<API_BASE_URL>";

function normalizeText(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function injectApiBaseUrl(snippet) {
  return String(snippet || "").replaceAll(REFERENCE_PLACEHOLDER, API_BASE_URL);
}

function renderSnippetTabs({ tabs, activeTab, onSelect }) {
  return (
    <div className="flex flex-wrap gap-2">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onSelect(tab.id)}
          className={`rounded-full px-3 py-1.5 text-xs font-medium transition ${
            activeTab === tab.id
              ? "bg-viro-600 text-white dark:bg-viro-500"
              : "bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

function buildEndpointIndexText(endpoint) {
  return [
    endpoint.name,
    endpoint.method,
    endpoint.path,
    endpoint.description,
    ...(Array.isArray(endpoint.scopes) ? endpoint.scopes : []),
    ...(Array.isArray(endpoint.pathParams) ? endpoint.pathParams.map((item) => item.name) : []),
    ...(Array.isArray(endpoint.queryParams) ? endpoint.queryParams.map((item) => item.name) : [])
  ]
    .join(" ")
    .toLowerCase();
}

function decorateEndpoint(endpoint) {
  const codeSamples = Object.fromEntries(
    Object.entries(endpoint.codeSamples || {}).map(([key, value]) => [key, injectApiBaseUrl(value)])
  );

  return {
    ...endpoint,
    codeSamples
  };
}

export function DocsView() {
  const [landingSample, setLandingSample] = useState("curl");
  const [quickstartSample, setQuickstartSample] = useState("curl");
  const [referenceQuery, setReferenceQuery] = useState("");
  const [activeSectionId, setActiveSectionId] = useState(DOCS_NAV_SECTIONS[0]?.id || "landing");

  const landingLanguage = useMemo(
    () => SNIPPET_TABS.find((tab) => tab.id === landingSample)?.language || "curl",
    [landingSample]
  );
  const quickstartLanguage = useMemo(
    () => SNIPPET_TABS.find((tab) => tab.id === quickstartSample)?.language || "curl",
    [quickstartSample]
  );

  const endpointCards = useMemo(() => API_ENDPOINTS.map(decorateEndpoint), []);
  const normalizedQuery = normalizeText(referenceQuery);
  const filteredEndpoints = useMemo(() => {
    if (!normalizedQuery) {
      return endpointCards;
    }

    return endpointCards.filter((endpoint) => buildEndpointIndexText(endpoint).includes(normalizedQuery));
  }, [endpointCards, normalizedQuery]);

  const tryItOptions = useMemo(
    () =>
      DOCS_TRY_IT_OPTIONS.map((option) => ({
        ...option,
        path: option.path
      })),
    []
  );

  const authExampleCurl = useMemo(
    () =>
      injectApiBaseUrl(`curl -X GET "<API_BASE_URL>/api/scans/jobs?limit=5" \\
  -H "x-api-key: <API_KEY>"`),
    []
  );

  useEffect(() => {
    if (typeof window === "undefined") {
      return undefined;
    }

    const validSectionIds = DOCS_NAV_SECTIONS.map((section) => section.id);
    const observedSections = validSectionIds
      .map((sectionId) => document.getElementById(sectionId))
      .filter(Boolean);

    if (observedSections.length === 0) {
      return undefined;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        const visibleEntries = entries
          .filter((entry) => entry.isIntersecting)
          .sort((left, right) => right.intersectionRatio - left.intersectionRatio);

        if (visibleEntries.length > 0) {
          setActiveSectionId(visibleEntries[0].target.id);
        }
      },
      {
        root: null,
        rootMargin: "-20% 0px -55% 0px",
        threshold: [0.1, 0.25, 0.5, 0.75]
      }
    );

    observedSections.forEach((section) => observer.observe(section));

    const syncFromHash = () => {
      const hashValue = window.location.hash.replace(/^#/, "");
      if (validSectionIds.includes(hashValue)) {
        setActiveSectionId(hashValue);
      }
    };

    syncFromHash();
    window.addEventListener("hashchange", syncFromHash);

    return () => {
      observer.disconnect();
      window.removeEventListener("hashchange", syncFromHash);
    };
  }, []);

  return (
    <div className="grid gap-6 xl:grid-cols-[250px_minmax(0,1fr)]">
      <aside className="dashboard-shell-surface h-fit p-4 sm:p-5 xl:sticky xl:top-24">
        <p className="dashboard-label">API docs</p>
        <h2 className="mt-2 text-lg font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Developer reference</h2>
        <p className="mt-2 text-sm leading-6 text-slate-500 dark:text-slate-400">
          Integration guide for secure API usage from your own backend services.
        </p>

        <nav className="mt-5 space-y-1" aria-label="Documentation sections">
          {DOCS_NAV_SECTIONS.map((section) => (
            <a
              key={section.id}
              href={`#${section.id}`}
              onClick={() => setActiveSectionId(section.id)}
              aria-current={activeSectionId === section.id ? "location" : undefined}
              className={`block rounded-xl px-3 py-2 text-sm transition ${
                activeSectionId === section.id
                  ? "border border-viro-300 bg-viro-100/90 font-semibold text-viro-800 shadow-sm dark:border-viro-700 dark:bg-viro-900/45 dark:text-viro-100"
                  : "text-slate-600 hover:bg-viro-50 hover:text-viro-700 dark:text-slate-300 dark:hover:bg-viro-900/30 dark:hover:text-viro-200"
              }`}
            >
              {section.label}
            </a>
          ))}
        </nav>
      </aside>

      <div className="min-w-0 space-y-6">
        <section id="landing" className="dashboard-shell-surface dashboard-grid-overlay space-y-5 p-5 sm:p-7">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="dashboard-label">Landing</p>
              <h2 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{DOCS_LANDING.title}</h2>
              <p className="mt-2 max-w-3xl text-sm leading-7 text-slate-600 dark:text-slate-300">{DOCS_LANDING.tagline}</p>
            </div>
            <a href={DOCS_LANDING.quickstartPath} className="dashboard-brand-button">
              <BookOpenText size={16} />
              Quickstart
            </a>
          </div>

          <p className="text-sm leading-7 text-slate-600 dark:text-slate-300">{DOCS_LANDING.value}</p>
          <div className="rounded-2xl border border-viro-200 bg-viro-50/70 px-4 py-3 text-sm text-viro-800 dark:border-viro-800 dark:bg-viro-900/25 dark:text-viro-100">
            <span className="font-semibold">Authentication:</span> {DOCS_LANDING.authSummary}
          </div>

          <div className="space-y-3">
            {renderSnippetTabs({
              tabs: SNIPPET_TABS.filter((tab) => tab.id !== "python"),
              activeTab: landingSample,
              onSelect: setLandingSample
            })}
            <CodeBlock
              title="First request"
              language={landingLanguage}
              code={injectApiBaseUrl(DOCS_LANDING_SNIPPETS[landingSample] || DOCS_LANDING_SNIPPETS.curl)}
            />
          </div>
        </section>

        <section id="quickstart" className="dashboard-shell-surface space-y-5 p-5 sm:p-7">
          <div>
            <p className="dashboard-label">Quickstart</p>
            <h2 className="mt-2 text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">
              Start scanning from your own app in 3 steps
            </h2>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            {DOCS_QUICKSTART_STEPS.map((step, index) => (
              <article key={step.title} className="rounded-2xl border border-slate-200/80 bg-slate-50/70 p-4 dark:border-slate-800/80 dark:bg-slate-900/60">
                <p className="dashboard-label">Step {index + 1}</p>
                <h3 className="mt-2 text-sm font-semibold text-slate-900 dark:text-white">{step.title}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">{step.detail}</p>
              </article>
            ))}
          </div>

          <div className="space-y-3">
            {renderSnippetTabs({
              tabs: SNIPPET_TABS,
              activeTab: quickstartSample,
              onSelect: setQuickstartSample
            })}
            <CodeBlock
              title="Quickstart sample"
              language={quickstartLanguage}
              code={injectApiBaseUrl(DOCS_QUICKSTART_SAMPLES[quickstartSample] || DOCS_QUICKSTART_SAMPLES.curl)}
            />
          </div>
        </section>

        <section id="authentication" className="dashboard-shell-surface space-y-5 p-5 sm:p-7">
          <div className="flex items-center gap-2">
            <KeyRound size={18} className="text-viro-600 dark:text-viro-300" />
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Authentication</h2>
          </div>

          <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
            <div className="space-y-3 rounded-2xl border border-slate-200/80 bg-slate-50/70 p-4 dark:border-slate-800/80 dark:bg-slate-900/50">
              <p className="text-sm font-semibold text-slate-900 dark:text-white">Header format</p>
              <code className="block rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200">
                {DOCS_AUTH_TEXT.headerFormat}
              </code>
              <p className="text-xs text-slate-500 dark:text-slate-400">Header name: {DOCS_AUTH_TEXT.headerName}</p>
            </div>

            <div className="rounded-2xl border border-slate-200/80 bg-slate-50/70 p-4 dark:border-slate-800/80 dark:bg-slate-900/50">
              <p className="text-sm font-semibold text-slate-900 dark:text-white">Security best practices</p>
              <ul className="mt-3 space-y-2 text-sm text-slate-600 dark:text-slate-300">
                {DOCS_AUTH_TEXT.notes.map((note) => (
                  <li key={note} className="leading-6">
                    {note}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <CodeBlock title="Authenticated request example" language="curl" code={authExampleCurl} />
        </section>

        <section id="api-reference" className="space-y-4">
          <div className="dashboard-shell-surface space-y-4 p-5 sm:p-7">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <TerminalSquare size={18} className="text-viro-600 dark:text-viro-300" />
                <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">API reference</h2>
              </div>
              <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
                {filteredEndpoints.length} endpoint{filteredEndpoints.length === 1 ? "" : "s"}
              </span>
            </div>

            <label className="relative block">
              <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 dark:text-slate-300" />
              <input
                type="search"
                value={referenceQuery}
                onChange={(event) => setReferenceQuery(event.target.value)}
                placeholder="Search endpoint by name, path, method, or scope..."
                className="w-full rounded-2xl border border-slate-200 bg-slate-50 py-3 pl-10 pr-4 text-sm text-slate-700 transition placeholder:text-slate-400 focus:border-viro-400 focus:bg-white focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-viro-700 dark:focus:bg-slate-950"
              />
            </label>
          </div>

          <div className="space-y-4">
            {filteredEndpoints.length > 0 ? (
              filteredEndpoints.map((endpoint) => <EndpointCard key={endpoint.id} endpoint={endpoint} />)
            ) : (
              <div className="dashboard-shell-surface p-6 text-sm text-slate-500 dark:text-slate-400">
                No endpoints matched your search.
              </div>
            )}
          </div>
        </section>

        <section id="errors" className="dashboard-shell-surface space-y-5 p-5 sm:p-7">
          <div className="flex items-center gap-2">
            <LifeBuoy size={18} className="text-viro-600 dark:text-viro-300" />
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Error handling</h2>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <ResponseViewer title="Raw API error format" payload={DOCS_ERROR_FORMAT.rawApiShape} />
            <ResponseViewer title="Normalized SDK error format" payload={DOCS_ERROR_FORMAT.normalizedSdkShape} />
          </div>

          <p className="text-sm leading-7 text-slate-600 dark:text-slate-300">
            Handle auth and validation errors immediately. Retry only transient failures (typically 429 and 5xx) with bounded exponential backoff.
          </p>
        </section>

        <section id="rate-limits" className="dashboard-shell-surface space-y-5 p-5 sm:p-7">
          <div>
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Rate limits</h2>
            <p className="mt-2 text-sm leading-7 text-slate-600 dark:text-slate-300">
              Limits protect API stability and abuse resistance. Configure clients to back off and retry safely.
            </p>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            {DOCS_RATE_LIMITS.map((limit) => (
              <article key={limit.name} className="rounded-2xl border border-slate-200/80 bg-slate-50/70 px-4 py-4 dark:border-slate-800/80 dark:bg-slate-900/60">
                <p className="dashboard-label">{limit.name}</p>
                <p className="mt-2 text-sm font-semibold text-slate-900 dark:text-white">{limit.value}</p>
              </article>
            ))}
          </div>

          <ParamTable
            title="Rate-limit headers"
            items={DOCS_RATE_LIMIT_HEADERS.map((header) => ({
              name: header.name,
              type: "string",
              required: true,
              description: header.description,
              example: "-"
            }))}
          />

          <div className="rounded-2xl border border-slate-200/80 bg-slate-50/70 px-4 py-4 dark:border-slate-800/80 dark:bg-slate-900/60">
            <p className="text-sm font-semibold text-slate-900 dark:text-white">Retry guidance</p>
            <ul className="mt-3 space-y-2 text-sm text-slate-600 dark:text-slate-300">
              {DOCS_RETRY_GUIDANCE.map((item) => (
                <li key={item} className="leading-6">
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section id="sdks" className="dashboard-shell-surface space-y-5 p-5 sm:p-7">
          <div className="flex items-center gap-2">
            <Workflow size={18} className="text-viro-600 dark:text-viro-300" />
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">SDKs and wrappers</h2>
          </div>

          <p className="text-sm leading-7 text-slate-600 dark:text-slate-300">
            Use these lightweight wrappers to standardize retries, headers, and error handling in your own services.
          </p>

          <div className="grid gap-4 xl:grid-cols-2">
            <CodeBlock title="JavaScript wrapper" language="javascript" code={injectApiBaseUrl(DOCS_JS_SDK_SAMPLE)} />
            <CodeBlock title="Python wrapper" language="python" code={injectApiBaseUrl(DOCS_PYTHON_SDK_SAMPLE)} />
          </div>
        </section>

        <section id="webhooks" className="dashboard-shell-surface space-y-5 p-5 sm:p-7">
          <div className="flex items-center gap-2">
            <LifeBuoy size={18} className="text-viro-600 dark:text-viro-300" />
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Webhooks</h2>
          </div>
          <p className="text-sm leading-7 text-slate-600 dark:text-slate-300">{DOCS_WEBHOOK.availability}</p>

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-2xl border border-slate-200/80 bg-slate-50/70 px-4 py-4 dark:border-slate-800/80 dark:bg-slate-900/60">
              <p className="text-sm font-semibold text-slate-900 dark:text-white">Signature verification</p>
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                Header: <code>{DOCS_WEBHOOK.signatureHeader}</code>
              </p>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">{DOCS_WEBHOOK.signatureScheme}</p>
            </div>
            <ResponseViewer title="Webhook event payload" payload={DOCS_WEBHOOK.eventExample} />
          </div>

          <CodeBlock title="Node.js verification sample" language="javascript" code={DOCS_WEBHOOK.verificationCode} />
        </section>

        <section id="try-it" className="dashboard-shell-surface space-y-5 p-5 sm:p-7">
          <div>
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Try it</h2>
            <p className="mt-2 text-sm leading-7 text-slate-600 dark:text-slate-300">
              Execute a live API request from the browser using your own key. For production usage, call the API from your backend service.
            </p>
          </div>
          <TryItPanel options={tryItOptions} />
        </section>
      </div>
    </div>
  );
}
