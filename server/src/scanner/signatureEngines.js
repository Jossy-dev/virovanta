import { spawn } from "child_process";
import crypto from "crypto";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { config } from "../config.js";

const DEFAULT_CLAMAV_DB_DIRS = Object.freeze([
  "/var/lib/clamav",
  "/opt/homebrew/var/lib/clamav",
  "/usr/local/var/lib/clamav"
]);

const CLAMAV_DB_EXTENSIONS = new Set([".cvd", ".cld", ".cud"]);
const YARA_RULE_EXTENSIONS = new Set([".yar", ".yara"]);

let yaraCompiledCache = {
  fingerprint: "",
  compiledRulesPath: "",
  sourceFiles: [],
  compiledAt: ""
};
const clamAvVersionCache = new Map();

function uniqueStrings(values) {
  return [...new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean))];
}

function splitConfiguredPaths(value) {
  return uniqueStrings(String(value || "").split(/[\n,]+/g));
}

export function sanitizeMatchedRuleName(value) {
  return String(value || "")
    .trim()
    .replace(/[^\w.:@/-]+/g, "_")
    .slice(0, 240);
}

export function parseYaraCliOutput(stdout) {
  const matches = [];
  const seen = new Set();

  for (const rawLine of String(stdout || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("warning:")) {
      continue;
    }

    const firstToken = line.split(/\s+/)[0];
    const ruleName = sanitizeMatchedRuleName(firstToken);
    if (!ruleName || seen.has(ruleName)) {
      continue;
    }

    seen.add(ruleName);
    matches.push(ruleName);
  }

  return matches;
}

function runCommand(command, args, timeoutMs = 90_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      const timeoutError = new Error("Command timed out");
      timeoutError.name = "AbortError";
      reject(timeoutError);
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timeout);
      resolve({ code, stdout, stderr });
    });
  });
}

async function pathExists(targetPath) {
  if (!targetPath) {
    return false;
  }

  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function gatherYaraRuleFilesFromPath(targetPath, recursive, files) {
  const stats = await fs.stat(targetPath);

  if (stats.isFile()) {
    if (YARA_RULE_EXTENSIONS.has(path.extname(targetPath).toLowerCase())) {
      files.push(path.resolve(targetPath));
    }
    return;
  }

  if (!stats.isDirectory()) {
    return;
  }

  const entries = await fs.readdir(targetPath, {
    withFileTypes: true
  });

  for (const entry of entries) {
    const fullPath = path.join(targetPath, entry.name);

    if (entry.isDirectory()) {
      if (recursive) {
        await gatherYaraRuleFilesFromPath(fullPath, recursive, files);
      }
      continue;
    }

    if (entry.isFile() && YARA_RULE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      files.push(path.resolve(fullPath));
    }
  }
}

export async function resolveYaraRuleFiles(runtimeConfig = config) {
  const configuredPaths = splitConfiguredPaths(runtimeConfig.yaraRulesPaths);
  const collected = [];

  for (const configuredPath of configuredPaths) {
    if (!(await pathExists(configuredPath))) {
      continue;
    }

    await gatherYaraRuleFilesFromPath(configuredPath, runtimeConfig.yaraRulesRecursive, collected);
  }

  return uniqueStrings(collected).sort((left, right) => left.localeCompare(right));
}

async function buildYaraRulesFingerprint(ruleFiles) {
  const digest = crypto.createHash("sha256");

  for (const filePath of ruleFiles) {
    const stats = await fs.stat(filePath);
    digest.update(filePath);
    digest.update(String(stats.size));
    digest.update(String(stats.mtimeMs));
  }

  return digest.digest("hex");
}

async function ensureCompiledYaraRules(runtimeConfig = config) {
  if (runtimeConfig.yaraCompiledRulesPath) {
    if (await pathExists(runtimeConfig.yaraCompiledRulesPath)) {
      return {
        status: "compiled",
        compiledRulesPath: runtimeConfig.yaraCompiledRulesPath,
        sourceFiles: [],
        compiledAt: null
      };
    }

    return {
      status: "misconfigured",
      reason: "compiled_rules_not_found",
      detail: "Configured YARA compiled rules file does not exist.",
      compiledRulesPath: runtimeConfig.yaraCompiledRulesPath,
      sourceFiles: []
    };
  }

  const sourceFiles = await resolveYaraRuleFiles(runtimeConfig);
  if (sourceFiles.length === 0) {
    return {
      status: "misconfigured",
      reason: "no_rule_files",
      detail: "No YARA rule files were found in the configured rule paths.",
      compiledRulesPath: "",
      sourceFiles: []
    };
  }

  if (!runtimeConfig.yaraAutoCompile) {
    return {
      status: "source",
      compiledRulesPath: "",
      sourceFiles,
      compiledAt: null
    };
  }

  const fingerprint = await buildYaraRulesFingerprint(sourceFiles);
  if (
    fingerprint === yaraCompiledCache.fingerprint &&
    yaraCompiledCache.compiledRulesPath &&
    (await pathExists(yaraCompiledCache.compiledRulesPath))
  ) {
    return {
      status: "compiled",
      compiledRulesPath: yaraCompiledCache.compiledRulesPath,
      sourceFiles,
      compiledAt: yaraCompiledCache.compiledAt
    };
  }

  const compiledRulesPath = path.join(os.tmpdir(), `virovanta-yara-${fingerprint}.compiled`);
  const compileArgs = [...sourceFiles, compiledRulesPath];

  try {
    const { code, stderr } = await runCommand(runtimeConfig.yaracBinary, compileArgs, runtimeConfig.yaraCompileTimeoutMs);
    if (code !== 0) {
      return {
        status: "error",
        reason: "compile_failed",
        detail: String(stderr || "YARA compilation failed.").trim(),
        compiledRulesPath,
        sourceFiles
      };
    }
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        status: "unavailable",
        reason: "yarac_not_found",
        detail: `Could not find \`${runtimeConfig.yaracBinary}\` in PATH.`,
        compiledRulesPath,
        sourceFiles
      };
    }

    if (error?.name === "AbortError") {
      return {
        status: "timeout",
        reason: "compile_timeout",
        detail: "YARA rule compilation timed out.",
        compiledRulesPath,
        sourceFiles
      };
    }

    return {
      status: "error",
      reason: "compile_failed",
      detail: error?.message || "YARA compilation failed unexpectedly.",
      compiledRulesPath,
      sourceFiles
    };
  }

  yaraCompiledCache = {
    fingerprint,
    compiledRulesPath,
    sourceFiles,
    compiledAt: new Date().toISOString()
  };

  return {
    status: "compiled",
    compiledRulesPath,
    sourceFiles,
    compiledAt: yaraCompiledCache.compiledAt
  };
}

export async function getYaraRuntimeStatus(runtimeConfig = config) {
  if (!runtimeConfig.enableYara) {
    return {
      status: "disabled",
      ready: true,
      binary: runtimeConfig.yaraBinary,
      detail: "YARA scanning disabled by configuration.",
      sourceFileCount: 0
    };
  }

  const rulePreparation = await ensureCompiledYaraRules(runtimeConfig);
  let version = "";

  try {
    const { code, stdout, stderr } = await runCommand(runtimeConfig.yaraBinary, ["--version"], 8_000);
    if (code === 0) {
      version = String(stdout || stderr || "").trim();
    }
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        status: "unavailable",
        ready: false,
        binary: runtimeConfig.yaraBinary,
        detail: `Could not find \`${runtimeConfig.yaraBinary}\` in PATH.`,
        sourceFileCount: rulePreparation.sourceFiles?.length || 0,
        compiledRulesPath: rulePreparation.compiledRulesPath || ""
      };
    }
  }

  if (["misconfigured", "error", "timeout", "unavailable"].includes(rulePreparation.status)) {
    return {
      status: rulePreparation.status,
      ready: false,
      binary: runtimeConfig.yaraBinary,
      version,
      detail: rulePreparation.detail || "YARA rules are not ready.",
      sourceFileCount: rulePreparation.sourceFiles?.length || 0,
      compiledRulesPath: rulePreparation.compiledRulesPath || ""
    };
  }

  return {
    status: "ready",
    ready: true,
    binary: runtimeConfig.yaraBinary,
    version,
    detail:
      rulePreparation.status === "compiled"
        ? "YARA rules are compiled and ready."
        : "YARA source rules are ready for direct scanning.",
    sourceFileCount: rulePreparation.sourceFiles?.length || 0,
    compiledRulesPath: rulePreparation.compiledRulesPath || "",
    compiledAt: rulePreparation.compiledAt || null
  };
}

export async function runYaraScan(filePath, runtimeConfig = config) {
  if (!runtimeConfig.enableYara) {
    return {
      status: "disabled",
      detail: "YARA scanning disabled by configuration.",
      matchedRules: [],
      ruleSourceCount: 0,
      compiledRulesPath: ""
    };
  }

  const rulePreparation = await ensureCompiledYaraRules(runtimeConfig);
  if (["misconfigured", "error", "timeout", "unavailable"].includes(rulePreparation.status)) {
    return {
      status: rulePreparation.status,
      detail: rulePreparation.detail || "YARA rules are not ready.",
      matchedRules: [],
      ruleSourceCount: rulePreparation.sourceFiles?.length || 0,
      compiledRulesPath: rulePreparation.compiledRulesPath || ""
    };
  }

  const args = [];
  if (runtimeConfig.yaraFastScan) {
    args.push("-f");
  }
  if (runtimeConfig.yaraNoWarnings) {
    args.push("-w");
  } else if (runtimeConfig.yaraFailOnWarnings) {
    args.push("--fail-on-warnings");
  }
  if (runtimeConfig.yaraMaxMatches > 0) {
    args.push("-l", String(runtimeConfig.yaraMaxMatches));
  }
  args.push("-a", String(Math.max(1, Math.ceil(runtimeConfig.yaraTimeoutMs / 1000))));

  if (rulePreparation.status === "compiled") {
    args.push("-C", rulePreparation.compiledRulesPath);
  } else {
    args.push(...rulePreparation.sourceFiles);
  }

  args.push(filePath);

  try {
    const { code, stdout, stderr } = await runCommand(runtimeConfig.yaraBinary, args, runtimeConfig.yaraTimeoutMs);
    if (code !== 0) {
      return {
        status: "error",
        detail: String(stderr || stdout || `YARA exited with code ${code}.`).trim(),
        matchedRules: [],
        ruleSourceCount: rulePreparation.sourceFiles?.length || 0,
        compiledRulesPath: rulePreparation.compiledRulesPath || ""
      };
    }

    const matchedRules = parseYaraCliOutput(stdout);
    return {
      status: matchedRules.length > 0 ? "matched" : "clean",
      detail:
        matchedRules.length > 0
          ? `YARA matched ${matchedRules.length} rule${matchedRules.length === 1 ? "" : "s"}.`
          : "YARA reported no rule matches.",
      matchedRules,
      ruleSourceCount: rulePreparation.sourceFiles?.length || 0,
      compiledRulesPath: rulePreparation.compiledRulesPath || "",
      compiledAt: rulePreparation.compiledAt || null
    };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        status: "unavailable",
        detail: `Could not find \`${runtimeConfig.yaraBinary}\` in PATH.`,
        matchedRules: [],
        ruleSourceCount: rulePreparation.sourceFiles?.length || 0,
        compiledRulesPath: rulePreparation.compiledRulesPath || ""
      };
    }

    if (error?.name === "AbortError") {
      return {
        status: "timeout",
        detail: "YARA scan timed out.",
        matchedRules: [],
        ruleSourceCount: rulePreparation.sourceFiles?.length || 0,
        compiledRulesPath: rulePreparation.compiledRulesPath || ""
      };
    }

    return {
      status: "error",
      detail: error?.message || "YARA scan failed unexpectedly.",
      matchedRules: [],
      ruleSourceCount: rulePreparation.sourceFiles?.length || 0,
      compiledRulesPath: rulePreparation.compiledRulesPath || ""
    };
  }
}

async function resolveClamAvDatabaseDir(runtimeConfig = config) {
  const explicit = String(runtimeConfig.clamAvDatabaseDir || "").trim();
  if (explicit) {
    return explicit;
  }

  for (const candidate of DEFAULT_CLAMAV_DB_DIRS) {
    if (await pathExists(candidate)) {
      return candidate;
    }
  }

  return "";
}

export async function inspectClamAvDefinitions(runtimeConfig = config) {
  const databaseDir = await resolveClamAvDatabaseDir(runtimeConfig);
  if (!databaseDir) {
    return {
      status: "missing",
      databaseDir: "",
      fileCount: 0,
      files: [],
      updatedAt: null,
      ageHours: null,
      detail: "ClamAV database directory was not found."
    };
  }

  let entries;
  try {
    entries = await fs.readdir(databaseDir, {
      withFileTypes: true
    });
  } catch (error) {
    return {
      status: "error",
      databaseDir,
      fileCount: 0,
      files: [],
      updatedAt: null,
      ageHours: null,
      detail: error?.message || "Could not read the ClamAV database directory."
    };
  }

  const files = entries
    .filter((entry) => entry.isFile() && CLAMAV_DB_EXTENSIONS.has(path.extname(entry.name).toLowerCase()))
    .map((entry) => entry.name)
    .sort((left, right) => left.localeCompare(right));

  if (files.length === 0) {
    return {
      status: "missing",
      databaseDir,
      fileCount: 0,
      files: [],
      updatedAt: null,
      ageHours: null,
      detail: "No ClamAV definition databases were found in the configured directory."
    };
  }

  const stats = await Promise.all(
    files.map(async (fileName) => ({
      fileName,
      stats: await fs.stat(path.join(databaseDir, fileName))
    }))
  );

  const newest = stats.reduce((latest, current) => {
    if (!latest || current.stats.mtimeMs > latest.stats.mtimeMs) {
      return current;
    }
    return latest;
  }, null);

  const updatedAt = newest ? newest.stats.mtime.toISOString() : null;
  const ageHours = updatedAt ? Number(((Date.now() - Date.parse(updatedAt)) / (60 * 60 * 1000)).toFixed(1)) : null;
  const status =
    ageHours == null
      ? "missing"
      : ageHours > runtimeConfig.clamAvDefinitionMaxAgeHours
        ? "stale"
        : "current";

  return {
    status,
    databaseDir,
    fileCount: files.length,
    files: files.slice(0, 12),
    updatedAt,
    ageHours,
    newestFile: newest?.fileName || null,
    detail:
      status === "current"
        ? "ClamAV definition databases look current."
        : "ClamAV definition databases are present but stale."
  };
}

async function getClamAvVersion(binary) {
  if (clamAvVersionCache.has(binary)) {
    return clamAvVersionCache.get(binary);
  }

  try {
    const { code, stdout, stderr } = await runCommand(binary, ["--version"], 8_000);
    if (code !== 0) {
      return "";
    }
    const version = String(stdout || stderr || "").trim();
    clamAvVersionCache.set(binary, version);
    return version;
  } catch {
    return "";
  }
}

export async function getClamAvRuntimeStatus(runtimeConfig = config) {
  const binary =
    runtimeConfig.clamAvMode === "clamdscan" ? runtimeConfig.clamdScanBinary : runtimeConfig.clamScanBinary;

  if (!runtimeConfig.enableClamAv) {
    return {
      status: "disabled",
      ready: true,
      mode: runtimeConfig.clamAvMode,
      binary,
      detail: "ClamAV scanning disabled by configuration."
    };
  }

  const definitions = await inspectClamAvDefinitions(runtimeConfig);

  try {
    const { code, stdout, stderr } = await runCommand(binary, ["--version"], 8_000);
    if (code !== 0) {
      return {
        status: "error",
        ready: false,
        mode: runtimeConfig.clamAvMode,
        binary,
        version: String(stdout || stderr || "").trim(),
        definitions,
        detail: `ClamAV binary exited with code ${code} during version check.`
      };
    }

    const version = String(stdout || stderr || "").trim();
    return {
      status: definitions.status === "missing" ? "degraded" : definitions.status === "stale" ? "stale" : "ready",
      ready: definitions.status !== "missing",
      mode: runtimeConfig.clamAvMode,
      binary,
      version,
      definitions,
      detail:
        definitions.status === "current"
          ? "ClamAV scanner and definitions are ready."
          : definitions.detail
    };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        status: "unavailable",
        ready: false,
        mode: runtimeConfig.clamAvMode,
        binary,
        definitions,
        detail: `Could not find \`${binary}\` in PATH.`
      };
    }

    return {
      status: "error",
      ready: false,
      mode: runtimeConfig.clamAvMode,
      binary,
      definitions,
      detail: error?.message || "ClamAV runtime inspection failed."
    };
  }
}

export async function runClamAvScan(filePath, runtimeConfig = config) {
  if (!runtimeConfig.enableClamAv) {
    return {
      status: "disabled",
      detail: "ClamAV scanning disabled by configuration."
    };
  }

  const binary =
    runtimeConfig.clamAvMode === "clamdscan" ? runtimeConfig.clamdScanBinary : runtimeConfig.clamScanBinary;
  const definitions = await inspectClamAvDefinitions(runtimeConfig);
  const args = ["--no-summary"];

  if (runtimeConfig.clamAvMode === "clamscan") {
    if (runtimeConfig.clamAvOfficialDbOnly) {
      args.push("--official-db-only=yes");
    }
    if (runtimeConfig.clamAvDatabaseDir) {
      args.push(`--database=${runtimeConfig.clamAvDatabaseDir}`);
    }
    args.push(`--max-filesize=${runtimeConfig.clamAvMaxFileSizeMb}M`);
    args.push(`--max-scansize=${runtimeConfig.clamAvMaxScanSizeMb}M`);
    args.push(`--max-recursion=${runtimeConfig.clamAvMaxRecursion}`);
  }

  args.push(filePath);

  try {
    const { code, stdout, stderr } = await runCommand(binary, args, runtimeConfig.clamAvScanTimeoutMs);
    const output = `${stdout}\n${stderr}`.trim();
    const infectedMatch = output.match(/:\s(.+)\sFOUND$/m);
    const version = await getClamAvVersion(binary);

    if (infectedMatch) {
      return {
        status: "infected",
        signature: infectedMatch[1],
        detail: "ClamAV detected known malware signature.",
        mode: runtimeConfig.clamAvMode,
        version,
        definitions
      };
    }

    if (code === 0) {
      return {
        status: "clean",
        detail: "ClamAV reported no known signatures.",
        mode: runtimeConfig.clamAvMode,
        version,
        definitions
      };
    }

    return {
      status: "error",
      detail: output || `ClamAV exited with code ${code}.`,
      mode: runtimeConfig.clamAvMode,
      version,
      definitions
    };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        status: "unavailable",
        detail: `Could not find \`${binary}\` in PATH.`,
        mode: runtimeConfig.clamAvMode,
        definitions
      };
    }

    if (error?.name === "AbortError") {
      return {
        status: "timeout",
        detail: "ClamAV scan timed out.",
        mode: runtimeConfig.clamAvMode,
        definitions
      };
    }

    return {
      status: "error",
      detail: error?.message || "Unexpected ClamAV failure.",
      mode: runtimeConfig.clamAvMode,
      definitions
    };
  }
}

export async function updateClamAvDefinitions(runtimeConfig = config) {
  if (!runtimeConfig.enableClamAv) {
    return {
      status: "disabled",
      detail: "ClamAV scanning disabled by configuration."
    };
  }

  const args = [];
  if (runtimeConfig.freshClamConfigPath) {
    args.push(`--config-file=${runtimeConfig.freshClamConfigPath}`);
  }

  try {
    const { code, stdout, stderr } = await runCommand(
      runtimeConfig.freshClamBinary,
      args,
      runtimeConfig.freshClamTimeoutMs
    );

    if (code !== 0) {
      return {
        status: "error",
        detail: String(stderr || stdout || `FreshClam exited with code ${code}.`).trim()
      };
    }

    return {
      status: "updated",
      detail: String(stdout || stderr || "FreshClam completed successfully.").trim()
    };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        status: "unavailable",
        detail: `Could not find \`${runtimeConfig.freshClamBinary}\` in PATH.`
      };
    }

    if (error?.name === "AbortError") {
      return {
        status: "timeout",
        detail: "FreshClam update timed out."
      };
    }

    return {
      status: "error",
      detail: error?.message || "FreshClam update failed unexpectedly."
    };
  }
}

export async function collectSignatureEngineRuntimeStatus(runtimeConfig = config) {
  const [clamav, yara] = await Promise.all([
    getClamAvRuntimeStatus(runtimeConfig),
    getYaraRuntimeStatus(runtimeConfig)
  ]);

  const alerts = [];
  if (!clamav.ready && clamav.status !== "disabled") {
    alerts.push({
      component: "clamav",
      severity: "warning",
      message: clamav.detail || "ClamAV is not fully ready.",
      code: clamav.status || "clamav_unready",
      occurredAt: new Date().toISOString()
    });
  } else if (clamav.status === "stale") {
    alerts.push({
      component: "clamav",
      severity: "warning",
      message: clamav.detail || "ClamAV definitions are stale.",
      code: "clamav_stale_definitions",
      occurredAt: new Date().toISOString()
    });
  }

  if (!yara.ready && yara.status !== "disabled") {
    alerts.push({
      component: "yara",
      severity: "warning",
      message: yara.detail || "YARA is not fully ready.",
      code: yara.status || "yara_unready",
      occurredAt: new Date().toISOString()
    });
  }

  return {
    status: alerts.length > 0 ? "degraded" : "ok",
    ready: true,
    clamav,
    yara,
    alerts
  };
}
