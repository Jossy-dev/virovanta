import { HttpError } from "./httpError.js";

export function validateSchema(schema, payload) {
  const parsed = schema.safeParse(payload);

  if (parsed.success) {
    return parsed.data;
  }

  const details = parsed.error.issues.map((issue) => ({
    path: issue.path.join("."),
    message: issue.message
  }));

  throw new HttpError(400, "Invalid request payload.", {
    code: "VALIDATION_ERROR",
    details
  });
}
