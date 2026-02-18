import jwt from "jsonwebtoken";
import { HttpError } from "./httpError.js";

const SHARE_TOKEN_ALGORITHM = "HS256";
const SHARE_ISSUER = "virovanta";
const SHARE_AUDIENCE = "virovanta-shared-report";

export function createReportShareToken({ reportId, ownerUserId, config }) {
  const ttlMinutes = config.reportShareTokenTtlMinutes;
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();

  const token = jwt.sign(
    {
      rid: reportId,
      oid: ownerUserId
    },
    config.reportShareTokenSecret,
    {
      algorithm: SHARE_TOKEN_ALGORITHM,
      expiresIn: `${ttlMinutes}m`,
      issuer: SHARE_ISSUER,
      audience: SHARE_AUDIENCE
    }
  );

  return {
    token,
    expiresAt
  };
}

export function verifyReportShareToken(token, config) {
  try {
    const payload = jwt.verify(token, config.reportShareTokenSecret, {
      algorithms: [SHARE_TOKEN_ALGORITHM],
      issuer: SHARE_ISSUER,
      audience: SHARE_AUDIENCE
    });

    if (!payload?.rid || !payload?.oid) {
      throw new HttpError(401, "Invalid shared report link.", {
        code: "SHARED_REPORT_TOKEN_INVALID"
      });
    }

    return {
      reportId: payload.rid,
      ownerUserId: payload.oid
    };
  } catch (error) {
    if (error instanceof HttpError) {
      throw error;
    }

    throw new HttpError(401, "Invalid or expired shared report link.", {
      code: "SHARED_REPORT_TOKEN_INVALID"
    });
  }
}
