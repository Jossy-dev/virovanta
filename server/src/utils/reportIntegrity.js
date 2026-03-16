import crypto from "crypto";

const REPORT_SIGNATURE_ALGORITHM = "HMAC-SHA256";

function sortJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }

  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((accumulator, key) => {
        accumulator[key] = sortJsonValue(value[key]);
        return accumulator;
      }, {});
  }

  return value;
}

function canonicalizeReportPayload(report) {
  const clonedReport = structuredClone(report || {});
  if (clonedReport && typeof clonedReport === "object") {
    delete clonedReport.signature;
  }

  return JSON.stringify(sortJsonValue(clonedReport));
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hmacSha256Hex(secret, value) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

function timingSafeHexEqual(left, right) {
  const leftHex = String(left || "");
  const rightHex = String(right || "");
  if (leftHex.length !== rightHex.length || leftHex.length % 2 !== 0) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(Buffer.from(leftHex, "hex"), Buffer.from(rightHex, "hex"));
  } catch {
    return false;
  }
}

function normalizeSigningSecret(secret) {
  const normalized = String(secret || "").trim();
  if (!normalized) {
    throw new Error("Report integrity secret is required.");
  }

  return normalized;
}

export function signReport(report, { secret, keyId = "default" } = {}) {
  const signingSecret = normalizeSigningSecret(secret);
  const canonicalPayload = canonicalizeReportPayload(report);
  const payloadHash = sha256Hex(canonicalPayload);

  return {
    ...report,
    signature: {
      algorithm: REPORT_SIGNATURE_ALGORITHM,
      keyId: String(keyId || "default"),
      payloadHash,
      signedAt: new Date().toISOString(),
      value: hmacSha256Hex(signingSecret, canonicalPayload)
    }
  };
}

export function verifySignedReport(report, { secret } = {}) {
  const signature = report?.signature;

  if (!signature || typeof signature !== "object") {
    return {
      valid: false,
      reason: "missing_signature"
    };
  }

  if (signature.algorithm !== REPORT_SIGNATURE_ALGORITHM) {
    return {
      valid: false,
      reason: "unsupported_algorithm",
      algorithm: signature.algorithm || null
    };
  }

  const verificationSecret = String(secret || "").trim();
  if (!verificationSecret) {
    return {
      valid: false,
      reason: "missing_verification_secret"
    };
  }

  const canonicalPayload = canonicalizeReportPayload(report);
  const calculatedPayloadHash = sha256Hex(canonicalPayload);

  if (!timingSafeHexEqual(signature.payloadHash, calculatedPayloadHash)) {
    return {
      valid: false,
      reason: "payload_hash_mismatch",
      keyId: signature.keyId || null,
      signedAt: signature.signedAt || null,
      payloadHash: signature.payloadHash || null,
      calculatedPayloadHash
    };
  }

  const expectedSignature = hmacSha256Hex(verificationSecret, canonicalPayload);
  if (!timingSafeHexEqual(signature.value, expectedSignature)) {
    return {
      valid: false,
      reason: "signature_mismatch",
      keyId: signature.keyId || null,
      signedAt: signature.signedAt || null,
      payloadHash: signature.payloadHash || null,
      calculatedPayloadHash
    };
  }

  return {
    valid: true,
    reason: null,
    algorithm: signature.algorithm,
    keyId: signature.keyId || null,
    signedAt: signature.signedAt || null,
    payloadHash: signature.payloadHash,
    calculatedPayloadHash
  };
}
