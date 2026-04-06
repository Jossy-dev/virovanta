import { describe, expect, it } from "vitest";
import {
  extractUrlCandidatesFromMessage,
  extractUrlScanTargetFromMessage,
  resolveUrlScanCandidates,
  resolveUrlScanTarget
} from "../src/utils/urlExtraction.js";

describe("URL extraction", () => {
  it("extracts a phishing-style obfuscated link from a pasted message", () => {
    const result = extractUrlScanTargetFromMessage(`
      Your Microsoft 365 password expires today.
      Review here: hxxps[:]//login-review[.]example.com/verify?session=abc123
    `);

    expect(result.url).toBe("https://login-review.example.com/verify?session=abc123");
    expect(result.candidateCount).toBe(1);
    expect(result.source).toBe("explicit");
  });

  it("prefers the more suspicious candidate when a message contains multiple links", () => {
    const candidates = extractUrlCandidatesFromMessage(`
      Safe footer: https://updates.example.org/unsubscribe
      Please sign in immediately at https://secure-billing.example.com/login/reset
    `);

    expect(candidates[0].normalizedUrl).toBe("https://secure-billing.example.com/login/reset");
    expect(candidates[1].normalizedUrl).toBe("https://updates.example.org/unsubscribe");
  });

  it("resolves bare domains without storing the full pasted message", () => {
    const result = resolveUrlScanTarget({
      message: "The suspicious portal says to visit portal-security.example.net/reset right away."
    });

    expect(result.url).toBe("https://portal-security.example.net/reset");
    expect(result.inputMode).toBe("message");
    expect(result.extracted).toBe(true);
  });

  it("returns ranked preview candidates for multi-link messages", () => {
    const result = resolveUrlScanCandidates({
      message: `
        Ignore footer: https://updates.example.org/unsubscribe
        Review immediately at https://secure-billing.example.com/login/reset
      `
    });

    expect(result.primaryUrl).toBe("https://secure-billing.example.com/login/reset");
    expect(result.candidateCount).toBe(2);
    expect(result.candidates).toEqual([
      expect.objectContaining({
        rank: 1,
        url: "https://secure-billing.example.com/login/reset",
        isPrimary: true
      }),
      expect.objectContaining({
        rank: 2,
        url: "https://updates.example.org/unsubscribe",
        isPrimary: false
      })
    ]);
  });

  it("rejects pasted messages that do not contain a scannable web link", () => {
    expect(() =>
      extractUrlScanTargetFromMessage("This email only says call the help desk and never includes a web address.")
    ).toThrow("No HTTP or HTTPS link could be extracted");
  });
});
