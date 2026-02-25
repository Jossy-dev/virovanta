import jwt from "jsonwebtoken";
import { HttpError } from "./httpError.js";

const SHARE_TOKEN_ALGORITHM = "HS256";

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
      issuer: config.reportShareTokenIssuer,
      audience: config.reportShareTokenAudience
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
      issuer: config.reportShareTokenIssuer,
      audience: config.reportShareTokenAudience
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
