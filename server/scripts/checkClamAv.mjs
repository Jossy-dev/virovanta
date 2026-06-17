import "dotenv/config";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { config } from "../src/config.js";
import { getClamAvRuntimeStatus, runClamAvScan } from "../src/scanner/signatureEngines.js";
import { describeClamAvDefinitions, printErrorLine, printStatusLine } from "./signatureEngineCli.js";

const tempFilePath = path.join(os.tmpdir(), `virovanta-clam-smoke-${Date.now()}.txt`);

try {
  const runtime = await getClamAvRuntimeStatus(config);

  if (runtime.status === "disabled") {
    printStatusLine("ClamAV", "disabled by configuration");
    process.exit(0);
  }

  if (!runtime.ready) {
    printErrorLine(`ClamAV check failed: ${runtime.detail || "ClamAV is not ready."}`);
    process.exit(1);
  }

  await fs.writeFile(tempFilePath, "ViroVanta ClamAV smoke test\n");
  const result = await runClamAvScan(tempFilePath, config);

  if (result.status === "clean") {
    printStatusLine(
      "ClamAV worked",
      `local scan completed successfully using ${result.version || runtime.version || runtime.binary || "clamscan"} with ${describeClamAvDefinitions(result.definitions || runtime.definitions)}`
    );
    process.exit(0);
  }

  if (result.status === "infected") {
    printErrorLine(`ClamAV check failed: smoke file was flagged by signature ${result.signature || "unknown"}.`);
    process.exit(1);
  }

  printErrorLine(`ClamAV check failed: ${result.detail || "ClamAV did not complete the smoke scan."}`);
  process.exit(1);
} finally {
  await fs.unlink(tempFilePath).catch(() => {});
}
