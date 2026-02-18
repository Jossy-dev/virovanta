import { HttpError, isHttpError } from "../utils/httpError.js";

export function notFoundHandler(_req, _res, next) {
  next(new HttpError(404, "API route not found.", { code: "ROUTE_NOT_FOUND" }));
}

export function errorHandler(logger, config) {
  return function handleError(error, req, res, _next) {
    if (error?.name === "MulterError" && error.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        error: {
          code: "UPLOAD_TOO_LARGE",
          message: `File too large. Maximum allowed is ${(config.maxUploadBytes / (1024 * 1024)).toFixed(0)} MB.`
        },
        requestId: req.requestId
      });
    }

    const normalized = isHttpError(error)
      ? error
      : new HttpError(500, "Unexpected server error.", {
          code: "INTERNAL_ERROR"
        });

    if (!isHttpError(error)) {
      logger.error({ err: error, requestId: req.requestId }, "Unhandled API error");
    }

    return res.status(normalized.statusCode).json({
      error: {
        code: normalized.code,
        message: normalized.message,
        details: normalized.details || null
      },
      requestId: req.requestId
    });
  };
}
