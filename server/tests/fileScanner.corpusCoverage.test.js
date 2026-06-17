import fs from "fs/promises";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "vitest";
import { FILE_SCANNER_CORPUS, materializeFileScannerCorpus } from "../benchmarks/fileScannerCorpus.js";
import { scanUploadedFile } from "../src/scanner/fileScanner.js";

const tempRoots = [];

async function createCorpusRoot() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-file-corpus-test-"));
  tempRoots.push(root);
  return root;
}

afterEach(async () => {
  const roots = tempRoots.splice(0);
  await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe("file scanner synthetic corpus coverage", () => {
  it("meets verdict and finding expectations across the shared corpus", async () => {
    const root = await createCorpusRoot();
    const materializedCorpus = await materializeFileScannerCorpus(root);

    for (const entry of materializedCorpus) {
      const report = await scanUploadedFile({
        filePath: entry.filePath,
        originalName: entry.fileName,
        declaredMimeType: entry.declaredMimeType
      });

      const findingIds = report.findings.map((finding) => finding.id);
      const joinedReasons = (Array.isArray(report.plainLanguageReasons) ? report.plainLanguageReasons : []).join(" ");

      expect(
        entry.expectedVerdicts.includes(report.verdict),
        `${entry.id} expected verdict ${entry.expectedVerdicts.join(" or ")} but received ${report.verdict}`
      ).toBe(true);

      for (const findingId of entry.expectedFindingIds || []) {
        expect(
          findingIds.includes(findingId),
          `${entry.id} expected finding ${findingId} but findings were ${findingIds.join(", ")}`
        ).toBe(true);
      }

      for (const group of entry.expectedFindingOneOf || []) {
        expect(
          group.some((findingId) => findingIds.includes(findingId)),
          `${entry.id} expected one of ${group.join(", ")} but findings were ${findingIds.join(", ")}`
        ).toBe(true);
      }

      for (const phrase of entry.expectedReasonIncludes || []) {
        expect(
          joinedReasons.includes(phrase),
          `${entry.id} expected plain-language reason to include "${phrase}" but reasons were "${joinedReasons}"`
        ).toBe(true);
      }

      expect(Array.isArray(report.recommendations), `${entry.id} should return recommendations`).toBe(true);
      expect(report.recommendations.length, `${entry.id} should return at least one recommendation`).toBeGreaterThan(0);
      expect(typeof report.engines?.classification?.reason, `${entry.id} should return a classification reason`).toBe("string");
      expect(String(report.engines.classification.reason || "").trim().length, `${entry.id} classification reason should not be empty`).toBeGreaterThan(0);
    }
  });
});
