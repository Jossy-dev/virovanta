import fs from "fs/promises";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "vitest";
import {
  getClamAvRuntimeStatus,
  getYaraRuntimeStatus,
  inspectClamAvDefinitions,
  parseYaraCliOutput,
  runClamAvScan,
  runYaraScan
} from "../src/scanner/signatureEngines.js";

const tempRoots = [];

async function createTempRoot() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-signature-engines-test-"));
  tempRoots.push(root);
  return root;
}

async function writeExecutable(filePath, content) {
  await fs.writeFile(filePath, content, {
    mode: 0o755
  });
}

afterEach(async () => {
  const roots = tempRoots.splice(0);
  await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe("signature engine helpers", () => {
  it("parses YARA CLI output into distinct rule names", () => {
    const parsed = parseYaraCliOutput(`
      suspicious_rule /tmp/sample.bin
      suspicious_rule /tmp/sample.bin
      another.rule /tmp/sample.bin
    `);

    expect(parsed).toEqual(["suspicious_rule", "another.rule"]);
  });

  it("compiles and runs configured YARA rules through the external binaries", async () => {
    const root = await createTempRoot();
    const rulesDir = path.join(root, "rules");
    const samplePath = path.join(root, "sample.bin");
    const yaraBinary = path.join(root, "fake-yara.sh");
    const yaracBinary = path.join(root, "fake-yarac.sh");

    await fs.mkdir(rulesDir, {
      recursive: true
    });
    await fs.writeFile(path.join(rulesDir, "test.yar"), "rule fake_rule { condition: true }");
    await fs.writeFile(samplePath, "sample");
    await writeExecutable(
      yaracBinary,
      `#!/bin/sh
out=""
for arg in "$@"; do
  out="$arg"
done
printf 'compiled-rules' > "$out"
`
    );
    await writeExecutable(
      yaraBinary,
      `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "4.5.0"
  exit 0
fi
echo "test_fake_rule $@"
`
    );

    const runtimeConfig = {
      enableYara: true,
      yaraBinary,
      yaracBinary,
      yaraRulesPaths: rulesDir,
      yaraCompiledRulesPath: "",
      yaraRulesRecursive: true,
      yaraAutoCompile: true,
      yaraTimeoutMs: 10_000,
      yaraCompileTimeoutMs: 10_000,
      yaraMaxMatches: 10,
      yaraFastScan: true,
      yaraFailOnWarnings: false,
      yaraNoWarnings: false
    };

    const runtime = await getYaraRuntimeStatus(runtimeConfig);
    const result = await runYaraScan(samplePath, runtimeConfig);

    expect(runtime.status).toBe("ready");
    expect(runtime.sourceFileCount).toBe(1);
    expect(result.status).toBe("matched");
    expect(result.matchedRules).toContain("test_fake_rule");
    expect(result.compiledRulesPath).toBeTruthy();
  });

  it("reports current and stale ClamAV definition states and uses hardened scan settings", async () => {
    const root = await createTempRoot();
    const databaseDir = path.join(root, "clamav-db");
    const samplePath = path.join(root, "sample.bin");
    const clamscanBinary = path.join(root, "fake-clamscan.sh");

    await fs.mkdir(databaseDir, {
      recursive: true
    });
    const currentDb = path.join(databaseDir, "main.cvd");
    await fs.writeFile(currentDb, "db");
    await fs.writeFile(samplePath, "sample");
    await writeExecutable(
      clamscanBinary,
      `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "ClamAV 1.4.3"
  exit 0
fi
exit 0
`
    );

    const runtimeConfig = {
      enableClamAv: true,
      clamAvMode: "clamscan",
      clamScanBinary: clamscanBinary,
      clamdScanBinary: "clamdscan",
      clamAvScanTimeoutMs: 10_000,
      clamAvDatabaseDir: databaseDir,
      clamAvDefinitionMaxAgeHours: 72,
      clamAvOfficialDbOnly: false,
      clamAvMaxFileSizeMb: 20,
      clamAvMaxScanSizeMb: 40,
      clamAvMaxRecursion: 8
    };

    const currentDefinitions = await inspectClamAvDefinitions(runtimeConfig);
    const currentRuntime = await getClamAvRuntimeStatus(runtimeConfig);
    const cleanScan = await runClamAvScan(samplePath, runtimeConfig);

    expect(currentDefinitions.status).toBe("current");
    expect(currentRuntime.status).toBe("ready");
    expect(cleanScan.status).toBe("clean");
    expect(cleanScan.definitions?.status).toBe("current");

    const staleDate = new Date(Date.now() - 96 * 60 * 60 * 1000);
    await fs.utimes(currentDb, staleDate, staleDate);

    const staleDefinitions = await inspectClamAvDefinitions(runtimeConfig);
    const staleRuntime = await getClamAvRuntimeStatus(runtimeConfig);

    expect(staleDefinitions.status).toBe("stale");
    expect(staleRuntime.status).toBe("stale");
    expect(staleRuntime.definitions?.ageHours).toBeGreaterThan(72);
  });
});
