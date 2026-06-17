ViroVanta YARA Rule Pack

This directory holds ViroVanta's first-party YARA rules for file scanning.
The pack is intentionally curated for lower-noise triage across the file types
the product already analyzes heavily: scripts, malicious documents, archives,
HTML credential harvest kits, and common loader behavior.

Design goals

- Favor rules we can explain clearly in reports.
- Keep licensing clean by shipping first-party rules only.
- Bias toward durable tradecraft signals, not one-off campaign strings.
- Avoid brittle "alert on any suspicious word" patterns that inflate false positives.

Metadata conventions

Every public rule includes:

- `author`: rule ownership.
- `category`: broad detection family.
- `severity`: `medium`, `high`, or `critical`.
- `confidence`: `medium`, `high`, or `very-high`.
- `scope`: intended scan scope, usually `file`.
- `rationale`: plain-English reason the pattern matters.

Current pack layout

- `scripts/`: PowerShell, JavaScript, Windows Script Host, and shortcut launchers.
- `documents/`: Office macro abuse, DDE execution, malicious PDF actions, and HTML credential harvest kits.
- `archives/`: Delivery patterns commonly used in phishing bundles.
- `binaries/`: Reflective loaders and shellcode-loader API clusters.
- `web/`: Redirector-heavy HTML payloads.
- `smoke-test.yar`: Minimal operator smoke test for local setup validation.

Operational notes

- Point `YARA_RULES_PATHS` at this directory and keep `YARA_RULES_RECURSIVE=true`.
- Run `npm run check:yara-pack --prefix server` to confirm the pack compiles and catches the bundled synthetic samples.
- Keep experimental or third-party rules outside this tree unless they have been reviewed for licensing, false-positive risk, and performance.

Important limitation

YARA is an evidence source, not the entire verdict. A match should strengthen the file report with explainable signals, but a clean YARA result should never be treated as proof that a sample is safe.
