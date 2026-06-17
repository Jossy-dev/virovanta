import fs from "fs/promises";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "vitest";
import { scanUploadedFile } from "../src/scanner/fileScanner.js";

const tempRoots = [];

async function createTempFile(fileName, content) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-file-verdict-test-"));
  const filePath = path.join(root, fileName);
  tempRoots.push(root);
  await fs.writeFile(filePath, content);
  return filePath;
}

afterEach(async () => {
  const roots = tempRoots.splice(0);
  await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe("file scanner verdict confidence", () => {
  it("keeps obviously plain-text files clean", async () => {
    const filePath = await createTempFile(
      "notes.txt",
      Buffer.from("Quarterly notes\nEverything in this file is readable plain text.\n")
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "notes.txt",
      declaredMimeType: "text/plain"
    });

    expect(report.verdict).toBe("clean");
    expect(report.engines.classification.confidence).toBe("medium");
    expect(report.plainLanguageReasons[0]).toMatch(/no strong indicators were found/i);
    expect(report.recommendations.some((item) => /first-pass clean result/i.test(item))).toBe(true);
  });

  it("does not over-inflate a single generic high-risk extension into suspicious", async () => {
    const filePath = await createTempFile(
      "tool.exe",
      Buffer.from("This sample only has a risky extension and otherwise looks like plain readable text.\n")
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "tool.exe",
      declaredMimeType: "application/octet-stream"
    });

    expect(report.findings.some((finding) => finding.id === "high_risk_extension")).toBe(true);
    expect(report.verdict).toBe("unknown");
    expect(report.riskScore).toBeLessThan(40);
    expect(report.engines.riskScoring.strongSignalCount).toBe(0);
  });

  it("marks weak single-signal samples as unknown instead of clean", async () => {
    const filePath = await createTempFile(
      "invoice.docm",
      Buffer.from("This content is not enough to prove malware, but the container is macro-enabled.\n")
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "invoice.docm",
      declaredMimeType: "application/vnd.ms-word.document.macroEnabled.12"
    });

    expect(report.verdict).toBe("unknown");
    expect(report.findings.some((finding) => finding.id === "macro_enabled_document")).toBe(true);
    expect(report.engines.classification.reason).toMatch(/weak indicators/i);
    expect(report.recommendations[0]).toMatch(/inconclusive/i);
  });

  it("keeps a single strong masquerading signal suspicious instead of malicious", async () => {
    const filePath = await createTempFile(
      "invoice.pdf",
      Buffer.from("MZFakePortableExecutable")
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "invoice.pdf",
      declaredMimeType: "application/pdf"
    });

    expect(report.findings.some((finding) => finding.id === "type_mismatch")).toBe(true);
    expect(report.verdict).toBe("suspicious");
    expect(report.verdict).not.toBe("malicious");
  });
});
