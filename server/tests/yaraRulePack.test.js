import fs from "fs/promises";
import path from "path";
import { describe, expect, it } from "vitest";
import { resolveYaraRuleFiles } from "../src/scanner/signatureEngines.js";

const packRoot = path.resolve(process.cwd(), "yara-rules");

function parseRuleBlocks(content) {
  const matches = [...content.matchAll(/((?:private\s+)?rule\s+([A-Za-z0-9_]+)\s*\n\{[\s\S]*?^})/gm)];
  return matches.map((match) => ({
    block: match[1],
    name: match[2],
    isPrivate: /^\s*private\s+rule\b/m.test(match[1])
  }));
}

describe("ViroVanta YARA rule pack", () => {
  it("loads the nested first-party rule pack", async () => {
    const ruleFiles = await resolveYaraRuleFiles({
      yaraRulesPaths: packRoot,
      yaraRulesRecursive: true
    });

    expect(ruleFiles.length).toBeGreaterThanOrEqual(7);
    expect(ruleFiles.some((filePath) => filePath.includes(`${path.sep}scripts${path.sep}`))).toBe(true);
    expect(ruleFiles.some((filePath) => filePath.includes(`${path.sep}documents${path.sep}`))).toBe(true);
    expect(ruleFiles.some((filePath) => filePath.includes(`${path.sep}archives${path.sep}`))).toBe(true);
    expect(ruleFiles.some((filePath) => filePath.includes(`${path.sep}binaries${path.sep}`))).toBe(true);
    expect(ruleFiles.some((filePath) => filePath.includes(`${path.sep}web${path.sep}`))).toBe(true);
  });

  it("keeps public rules namespaced, documented, and unique", async () => {
    const ruleFiles = await resolveYaraRuleFiles({
      yaraRulesPaths: packRoot,
      yaraRulesRecursive: true
    });

    const seen = new Set();
    let publicRuleCount = 0;

    for (const filePath of ruleFiles) {
      const content = await fs.readFile(filePath, "utf8");
      const rules = parseRuleBlocks(content);
      expect(rules.length).toBeGreaterThan(0);

      for (const rule of rules) {
        expect(rule.name.startsWith("vv_")).toBe(true);
        expect(seen.has(rule.name)).toBe(false);
        seen.add(rule.name);

        if (rule.isPrivate) {
          continue;
        }

        publicRuleCount += 1;
        expect(rule.block).toMatch(/^\s*author\s*=\s*"/m);
        expect(rule.block).toMatch(/^\s*category\s*=\s*"/m);
        expect(rule.block).toMatch(/^\s*severity\s*=\s*"/m);
        expect(rule.block).toMatch(/^\s*confidence\s*=\s*"/m);
        expect(rule.block).toMatch(/^\s*scope\s*=\s*"/m);
        expect(rule.block).toMatch(/^\s*rationale\s*=\s*"/m);
      }
    }

    expect(publicRuleCount).toBeGreaterThanOrEqual(12);
  });
});
