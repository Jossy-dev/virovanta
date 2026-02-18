export class HttpError extends Error {
  constructor(statusCode, message, { code = "HTTP_ERROR", details = null } = {}) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export function isHttpError(error) {
  return error instanceof HttpError;
}
