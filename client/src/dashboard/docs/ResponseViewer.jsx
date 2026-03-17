import { CodeBlock } from "./CodeBlock";

export function ResponseViewer({ title, payload, compact = true }) {
  return <CodeBlock title={title} language="json" code={JSON.stringify(payload, null, 2)} compact={compact} />;
}
