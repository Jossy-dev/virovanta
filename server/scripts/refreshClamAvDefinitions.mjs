import "dotenv/config";
import { config } from "../src/config.js";
import { inspectClamAvDefinitions, updateClamAvDefinitions } from "../src/scanner/signatureEngines.js";
import { describeClamAvDefinitions, printErrorLine, printStatusLine, printVerboseJson } from "./signatureEngineCli.js";

const before = await inspectClamAvDefinitions(config);
const result = await updateClamAvDefinitions(config);
const after = await inspectClamAvDefinitions(config);

const payload = {
  ranAt: new Date().toISOString(),
  before,
  result,
  after
};

if (result.status === "disabled") {
  printStatusLine("ClamAV", "definition refresh skipped because ClamAV is disabled");
  printVerboseJson(payload);
  process.exit(0);
}

if (result.status === "updated") {
  printStatusLine("ClamAV worked", `definitions refresh completed, ${describeClamAvDefinitions(after)}`);
  printVerboseJson(payload);
  process.exit(0);
}

printErrorLine(`ClamAV refresh failed: ${result.detail || "FreshClam did not complete successfully."}`);
printVerboseJson(payload);
process.exit(1);
