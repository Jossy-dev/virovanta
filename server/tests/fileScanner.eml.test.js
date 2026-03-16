import fs from "fs/promises";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "vitest";
import { scanUploadedFile } from "../src/scanner/fileScanner.js";

const tempRoots = [];

async function createTempFile(fileName, content) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-eml-test-"));
  const filePath = path.join(root, fileName);
  tempRoots.push(root);
  await fs.writeFile(filePath, content, "utf8");
  return filePath;
}

afterEach(async () => {
  const roots = tempRoots.splice(0);
  await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe(".eml scanner", () => {
  it("parses sender/authentication signals and scans embedded URLs", async () => {
    const emlPayload = `From: Security Team <alerts@trusted.example>
Reply-To: attacker@evil.example
To: employee@example.com
Subject: Verify your account
Date: Tue, 16 Mar 2026 11:00:00 +0000
Message-ID: <message-1@example.com>
Authentication-Results: mx.example; spf=fail smtp.mailfrom=trusted.example; dkim=fail header.d=trusted.example; dmarc=fail header.from=trusted.example
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Please verify right now: http://127.0.0.1/login
`;

    const filePath = await createTempFile("suspicious.eml", emlPayload);
    const report = await scanUploadedFile({
      filePath,
      originalName: "suspicious.eml",
      declaredMimeType: "message/rfc822"
    });

    expect(report.engines.email.status).toBe("completed");
    expect(report.engines.email.sender.mismatch).toBe(true);
    expect(report.engines.email.authentication.spf.status).toBe("fail");
    expect(report.engines.email.authentication.dkim.status).toBe("fail");
    expect(report.engines.email.authentication.dmarc.status).toBe("fail");
    expect(report.engines.email.urlScans.totalExtracted).toBe(1);
    expect(report.engines.email.urlScans.scannedCount).toBe(1);
    expect(report.engines.email.urlScans.highRisk.malicious.length).toBe(1);
    expect(report.engines.email.urlScans.highRisk.malicious[0].url).toContain("127.0.0.1");
    expect(report.findings.some((finding) => finding.id === "email_reply_to_mismatch")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "email_spf_failed")).toBe(true);
    const maliciousLinkFinding = report.findings.find((finding) => finding.id === "email_embedded_links_malicious");
    expect(maliciousLinkFinding).toBeTruthy();
    expect(maliciousLinkFinding.evidence).toContain("127.0.0.1");
  });

  it("extracts and scans embedded email attachments", async () => {
    const attachmentPayload = Buffer.from("powershell -enc VABFAFMAVAA=").toString("base64");

    const emlPayload = `From: Payroll <payroll@example.com>
To: employee@example.com
Subject: Salary report
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY-1234"

--BOUNDARY-1234
Content-Type: text/plain; charset="UTF-8"

Please inspect the attached report.

--BOUNDARY-1234
Content-Type: application/octet-stream; name="report.ps1"
Content-Disposition: attachment; filename="report.ps1"
Content-Transfer-Encoding: base64

${attachmentPayload}
--BOUNDARY-1234--
`;

    const filePath = await createTempFile("attachment-test.eml", emlPayload);
    const report = await scanUploadedFile({
      filePath,
      originalName: "attachment-test.eml",
      declaredMimeType: "message/rfc822"
    });

    expect(report.engines.email.status).toBe("completed");
    expect(report.engines.email.attachments.total).toBe(1);
    expect(report.engines.email.attachments.scannedCount).toBe(1);
    expect(report.engines.email.attachments.items[0].status).toBe("completed");
    expect(["suspicious", "malicious"]).toContain(report.engines.email.attachments.items[0].verdict);
    expect(
      report.findings.some((finding) =>
        ["email_attachment_suspicious", "email_attachment_malicious"].includes(finding.id)
      )
    ).toBe(true);
  });
});
