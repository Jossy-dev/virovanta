import "dotenv/config";
import { config } from "../src/config.js";
import { collectSignatureEngineRuntimeStatus, resolveYaraRuleFiles } from "../src/scanner/signatureEngines.js";
import { describeClamAvDefinitions, printErrorLine, printStatusLine, printVerboseJson } from "./signatureEngineCli.js";

const runtime = await collectSignatureEngineRuntimeStatus(config);
const yaraSourceFiles = config.enableYara ? await resolveYaraRuleFiles(config) : [];

const payload = {
  checkedAt: new Date().toISOString(),
  runtime,
  yaraSourceFiles: yaraSourceFiles.slice(0, 50)
};

const { clamav, yara } = runtime;

if (clamav?.status === "ready") {
  printStatusLine("ClamAV worked", `${clamav.version || clamav.binary || "scanner"} is ready with ${describeClamAvDefinitions(clamav.definitions)}`);
} else if (clamav?.status === "disabled") {
  printStatusLine("ClamAV", "disabled by configuration");
} else {
  printErrorLine(`ClamAV issue: ${clamav?.detail || "ClamAV is not ready."}`);
}

if (yara?.status === "ready") {
  printStatusLine(
    "YARA worked",
    `${yara.version || yara.binary || "scanner"} is ready with ${Number(yara.sourceFileCount) || 0} rule file${
      Number(yara.sourceFileCount) === 1 ? "" : "s"
    }`
  );
} else if (yara?.status === "disabled") {
  printStatusLine("YARA", "disabled by configuration");
} else {
  printErrorLine(`YARA issue: ${yara?.detail || "YARA is not ready."}`);
}

printVerboseJson(payload);

if (runtime.status === "ok") {
  process.exit(0);
}

process.exit(1);
