import fs from "fs/promises";
import os from "os";
import path from "path";
import { performance } from "perf_hooks";

if (!("ENABLE_CLAMAV" in process.env)) {
  process.env.ENABLE_CLAMAV = "false";
}

if (!("VIRUSTOTAL_API_KEY" in process.env)) {
  process.env.VIRUSTOTAL_API_KEY = "";
}

const { FILE_SCANNER_CORPUS, materializeFileScannerCorpus } = await import("../benchmarks/fileScannerCorpus.js");
const { scanUploadedFile } = await import("../src/scanner/fileScanner.js");

function parseArgs(argv) {
  const parsed = {
    iterations: 1,
    json: false,
    category: "",
    filter: "",
    outputPath: ""
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--json") {
      parsed.json = true;
      continue;
    }

    if (arg === "--iterations") {
      parsed.iterations = Math.max(1, Number.parseInt(argv[index + 1], 10) || 1);
      index += 1;
      continue;
    }

    if (arg === "--category") {
      parsed.category = String(argv[index + 1] || "").trim().toLowerCase();
      index += 1;
      continue;
    }

    if (arg === "--filter") {
      parsed.filter = String(argv[index + 1] || "").trim().toLowerCase();
      index += 1;
      continue;
    }

    if (arg === "--output") {
      parsed.outputPath = String(argv[index + 1] || "").trim();
      index += 1;
    }
  }

  return parsed;
}

function percentile(sortedValues, fraction) {
  if (!Array.isArray(sortedValues) || sortedValues.length === 0) {
    return 0;
  }

  const index = Math.min(sortedValues.length - 1, Math.max(0, Math.ceil(sortedValues.length * fraction) - 1));
  return sortedValues[index];
}

function round(value, digits = 2) {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Number(value.toFixed(digits));
}

function matchesExpectation(result, entry) {
  const findingIds = result.findings.map((finding) => finding.id);
  const requiredFindingChecks = (entry.expectedFindingIds || []).map((findingId) => ({
    type: "all",
    target: [findingId],
    passed: findingIds.includes(findingId)
  }));
  const oneOfChecks = (entry.expectedFindingOneOf || []).map((group) => ({
    type: "oneOf",
    target: group,
    passed: group.some((findingId) => findingIds.includes(findingId))
  }));
  const reasonText = (Array.isArray(result.plainLanguageReasons) ? result.plainLanguageReasons : []).join(" ");
  const reasonChecks = (entry.expectedReasonIncludes || []).map((phrase) => ({
    type: "reason",
    target: [phrase],
    passed: reasonText.includes(phrase)
  }));

  return {
    verdictPassed: entry.expectedVerdicts.includes(result.verdict),
    findingChecks: [...requiredFindingChecks, ...oneOfChecks],
    reasonChecks
  };
}

function formatBenchmarkTable(rows) {
  const widths = [24, 12, 12, 12, 12];
  const pad = (value, length) => String(value).padEnd(length, " ");
  const header = [
    pad("Case", widths[0]),
    pad("Category", widths[1]),
    pad("Verdict", widths[2]),
    pad("Avg ms", widths[3]),
    pad("Expect", widths[4])
  ].join(" | ");
  const divider = widths.map((width) => "-".repeat(width)).join("-|-");

  return [header, divider]
    .concat(
      rows.map((row) =>
        [
          pad(row.id, widths[0]),
          pad(row.category, widths[1]),
          pad(row.verdict, widths[2]),
          pad(row.avgMs, widths[3]),
          pad(row.expectation, widths[4])
        ].join(" | ")
      )
    )
    .join("\n");
}

const options = parseArgs(process.argv.slice(2));
const selectedCorpus = FILE_SCANNER_CORPUS.filter((entry) => {
  const categoryMatch = !options.category || entry.category === options.category;
  const filterMatch =
    !options.filter ||
    entry.id.toLowerCase().includes(options.filter) ||
    entry.title.toLowerCase().includes(options.filter) ||
    entry.fileName.toLowerCase().includes(options.filter);

  return categoryMatch && filterMatch;
});

if (selectedCorpus.length === 0) {
  console.error("No corpus entries matched the current benchmark filter.");
  process.exitCode = 1;
} else {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-file-benchmark-"));

  try {
    const materializedCorpus = await materializeFileScannerCorpus(root, selectedCorpus);
    const results = [];

    for (const entry of materializedCorpus) {
      const scans = [];

      for (let iteration = 0; iteration < options.iterations; iteration += 1) {
        const startedAt = performance.now();
        const report = await scanUploadedFile({
          filePath: entry.filePath,
          originalName: entry.fileName,
          declaredMimeType: entry.declaredMimeType
        });
        const elapsedMs = performance.now() - startedAt;
        const expectation = matchesExpectation(report, entry);

        scans.push({
          iteration: iteration + 1,
          elapsedMs,
          verdict: report.verdict,
          findingCount: report.findings.length,
          riskScore: report.riskScore,
          expectation
        });
      }

      results.push({
        id: entry.id,
        title: entry.title,
        category: entry.category,
        fileName: entry.fileName,
        expectedVerdicts: entry.expectedVerdicts,
        expectedFindingIds: entry.expectedFindingIds || [],
        expectedFindingOneOf: entry.expectedFindingOneOf || [],
        scans
      });
    }

    const durations = results.flatMap((entry) => entry.scans.map((scan) => scan.elapsedMs)).sort((left, right) => left - right);
    const verdictChecks = results.flatMap((entry) => entry.scans.map((scan) => scan.expectation.verdictPassed));
    const findingChecks = results.flatMap((entry) => entry.scans.flatMap((scan) => scan.expectation.findingChecks.map((check) => check.passed)));
    const reasonChecks = results.flatMap((entry) => entry.scans.flatMap((scan) => scan.expectation.reasonChecks.map((check) => check.passed)));

    const byCategory = [...new Set(results.map((entry) => entry.category))].map((category) => {
      const categoryEntries = results.filter((entry) => entry.category === category);
      const categoryDurations = categoryEntries.flatMap((entry) => entry.scans.map((scan) => scan.elapsedMs));
      return {
        category,
        cases: categoryEntries.length,
        avgMs: round(categoryDurations.reduce((sum, value) => sum + value, 0) / categoryDurations.length),
        maxMs: round(Math.max(...categoryDurations))
      };
    });

    const caseRows = results.map((entry) => {
      const avgMs = entry.scans.reduce((sum, scan) => sum + scan.elapsedMs, 0) / entry.scans.length;
      const verdicts = [...new Set(entry.scans.map((scan) => scan.verdict))].join(", ");
      const allChecksPassed = entry.scans.every(
        (scan) =>
          scan.expectation.verdictPassed &&
          scan.expectation.findingChecks.every((check) => check.passed) &&
          scan.expectation.reasonChecks.every((check) => check.passed)
      );

      return {
        id: entry.id,
        category: entry.category,
        verdict: verdicts,
        avgMs: round(avgMs),
        expectation: allChecksPassed ? "pass" : "review"
      };
    });

    const summary = {
      generatedAt: new Date().toISOString(),
      iterations: options.iterations,
      offlineDefaults: {
        enableClamAv: process.env.ENABLE_CLAMAV,
        externalReputationConfigured: Boolean(process.env.VIRUSTOTAL_API_KEY)
      },
      corpus: {
        selectedCases: selectedCorpus.length,
        totalScans: durations.length
      },
      latency: {
        avgMs: round(durations.reduce((sum, value) => sum + value, 0) / durations.length),
        p50Ms: round(percentile(durations, 0.5)),
        p95Ms: round(percentile(durations, 0.95)),
        maxMs: round(Math.max(...durations))
      },
      expectationChecks: {
        verdictPassRate: round((verdictChecks.filter(Boolean).length / verdictChecks.length) * 100),
        findingPassRate: findingChecks.length === 0 ? 100 : round((findingChecks.filter(Boolean).length / findingChecks.length) * 100),
        reasonPassRate: reasonChecks.length === 0 ? 100 : round((reasonChecks.filter(Boolean).length / reasonChecks.length) * 100)
      },
      byCategory,
      cases: results.map((entry) => ({
        id: entry.id,
        category: entry.category,
        title: entry.title,
        fileName: entry.fileName,
        expectedVerdicts: entry.expectedVerdicts,
        scans: entry.scans.map((scan) => ({
          iteration: scan.iteration,
          elapsedMs: round(scan.elapsedMs),
          verdict: scan.verdict,
          findingCount: scan.findingCount,
          riskScore: scan.riskScore,
          verdictPassed: scan.expectation.verdictPassed,
          findingChecks: scan.expectation.findingChecks,
          reasonChecks: scan.expectation.reasonChecks
        }))
      }))
    };

    if (options.outputPath) {
      await fs.writeFile(path.resolve(options.outputPath), JSON.stringify(summary, null, 2));
    }

    if (options.json) {
      console.log(JSON.stringify(summary, null, 2));
    } else {
      console.log("ViroVanta file scanner benchmark");
      console.log(`Generated: ${summary.generatedAt}`);
      console.log(`Corpus cases: ${summary.corpus.selectedCases}`);
      console.log(`Iterations per case: ${summary.iterations}`);
      console.log(`Total scans: ${summary.corpus.totalScans}`);
      console.log(
        `Latency: avg ${summary.latency.avgMs} ms | p50 ${summary.latency.p50Ms} ms | p95 ${summary.latency.p95Ms} ms | max ${summary.latency.maxMs} ms`
      );
      console.log(
        `Expectation checks: verdict ${summary.expectationChecks.verdictPassRate}% | findings ${summary.expectationChecks.findingPassRate}% | reasons ${summary.expectationChecks.reasonPassRate}%`
      );
      console.log("");
      console.log(formatBenchmarkTable(caseRows));
      console.log("");
      console.log("Category summary");
      for (const row of byCategory) {
        console.log(`- ${row.category}: ${row.cases} case(s), avg ${row.avgMs} ms, max ${row.maxMs} ms`);
      }
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}
