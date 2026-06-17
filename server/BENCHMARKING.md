# File Scanner Benchmarking

ViroVanta now includes a synthetic file-scanner corpus and a repeatable benchmark harness for regression checks and local performance measurement.

## Commands

From the repo root:

```bash
npm run test:file-scanner
npm run bench:file-scanner
```

Useful benchmark options:

```bash
npm run bench:file-scanner --prefix server -- --iterations 5
npm run bench:file-scanner --prefix server -- --category archive
npm run bench:file-scanner --prefix server -- --filter powershell
npm run bench:file-scanner --prefix server -- --json --output ./benchmark-output.json
```

## What is included

- Shared synthetic corpus: `server/benchmarks/fileScannerCorpus.js`
- Broad regression coverage: `server/tests/fileScanner.corpusCoverage.test.js`
- Benchmark runner: `server/scripts/runFileScannerBenchmark.mjs`

The corpus intentionally covers:

- Clean plain-text files
- Weak-signal unknown cases
- PDF active content
- Office macro and external-reference cases
- JavaScript and PowerShell droppers
- LNK and HTML phishing-lure patterns
- Archive structure and nested payload paths
- LOLBin proxy execution patterns
- Defender tampering
- Browser credential-theft markers
- Email-based phishing indicators

## Why the corpus is synthetic

The repo does not bundle live malware. That is deliberate.

- It keeps the workspace safer for contributors and CI systems.
- It makes test runs deterministic and easy to review.
- It avoids turning the project into a malware distribution source.

This corpus is best understood as a regression and behavior-coverage suite, not proof of real-world detection efficacy.

## What this harness proves

- The scanner continues to recognize the behavior patterns ViroVanta explicitly supports.
- Verdict wording, finding IDs, and recommendation output stay stable enough for product workflows.
- Performance regressions become visible through repeatable latency measurements.

## What this harness does not prove

- That ViroVanta detects all real malware families
- That ClamAV or an external reputation feed will match every real-world sample
- That scanner accuracy on public malware corpora is unchanged over time
- That archive unpacking and emulation cover every attacker technique

For that, use this harness together with controlled external validation.

## Recommended external validation

Safe and official starting points:

- EICAR test files, including archive and double-archive variants, for basic anti-malware response checks
- AMTSO feature checks to verify protective controls and deployment behavior

Do not treat EICAR or AMTSO checks as complete efficacy benchmarks. They confirm that protective features respond, not that the product performs comprehensive malware classification.

## Practical benchmarking workflow

1. Run `npm run test:file-scanner` after scanner changes.
2. Run `npm run bench:file-scanner -- --iterations 5` to establish latency and expectation-check baselines.
3. Compare p50, p95, and max latency before and after the change.
4. Review any verdict, finding, or reason mismatches before merging.
5. If you later introduce YARA or richer static engines, add new synthetic cases before enabling the new rules in production.

## Determinism notes

The benchmark runner defaults to offline-friendly settings:

- `ENABLE_CLAMAV=false` unless already set
- External reputation credentials empty unless already set

That keeps default benchmark output stable across developer machines. If you explicitly enable ClamAV or an external reputation feed, results can legitimately differ based on local installation state or external reputation data.

## Primary-source guidance used for this setup

- EICAR explains that its test file is for validating anti-malware response without using real malware, and provides archive-depth variants.
- AMTSO feature checks are intended to verify that security controls are active and responding.
- YARA documentation reinforces the value of structured strings and conditions for malware-oriented matching logic.
- NIST SP 800-83 recommends regular scanning and layered malware prevention controls on hosts.
