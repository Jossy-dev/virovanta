import { useEffect, useMemo, useRef, useState } from "react";
import Prism from "prismjs";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-javascript";
import "prismjs/components/prism-json";
import "prismjs/components/prism-python";
import { CheckCircle2, Copy } from "lucide-react";

const LANGUAGE_ALIASES = Object.freeze({
  curl: "bash",
  sh: "bash",
  shell: "bash",
  js: "javascript",
  jsx: "javascript",
  py: "python"
});

function resolvePrismLanguage(language) {
  const normalized = String(language || "bash").trim().toLowerCase();
  return LANGUAGE_ALIASES[normalized] || normalized;
}

export function CodeBlock({ code, language = "bash", title = "", compact = false }) {
  const [copied, setCopied] = useState(false);
  const prismLanguage = useMemo(() => resolvePrismLanguage(language), [language]);
  const codeRef = useRef(null);

  useEffect(() => {
    if (!codeRef.current) {
      return;
    }

    Prism.highlightElement(codeRef.current);
  }, [code, prismLanguage]);

  async function copyToClipboard() {
    if (!navigator?.clipboard?.writeText) {
      return;
    }

    try {
      await navigator.clipboard.writeText(String(code || ""));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="overflow-hidden rounded-3xl border border-slate-200/80 bg-white dark:border-slate-800/80 dark:bg-slate-950">
      <div className="flex items-center justify-between gap-2 border-b border-slate-200/80 px-4 py-3 dark:border-slate-800/80">
        <div className="min-w-0">
          {title ? <p className="truncate text-xs font-semibold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-300">{title}</p> : null}
          <p className="text-xs text-slate-500 dark:text-slate-400">{prismLanguage}</p>
        </div>
        <button
          type="button"
          className="dashboard-brand-outline inline-flex items-center gap-2 px-3 py-1.5 text-xs"
          onClick={copyToClipboard}
        >
          {copied ? <CheckCircle2 size={14} /> : <Copy size={14} />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className={`docs-code m-0 overflow-x-auto px-4 py-4 text-[12px] leading-6 ${compact ? "max-h-[240px]" : "max-h-[520px]"}`}>
        <code ref={codeRef} className={`language-${prismLanguage}`}>
          {String(code || "")}
        </code>
      </pre>
    </div>
  );
}
