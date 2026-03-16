const API_KEY_SCOPE_LIST = [
  "jobs:read",
  "jobs:write",
  "reports:read",
  "reports:share",
  "analytics:read"
];

const API_KEY_SCOPE_SET = new Set(API_KEY_SCOPE_LIST);

export const API_KEY_SCOPES = Object.freeze({
  JOBS_READ: "jobs:read",
  JOBS_WRITE: "jobs:write",
  REPORTS_READ: "reports:read",
  REPORTS_SHARE: "reports:share",
  ANALYTICS_READ: "analytics:read"
});

export const API_KEY_SCOPE_VALUES = Object.freeze([...API_KEY_SCOPE_LIST]);

export function normalizeApiKeyScopes(input, { fallbackToAll = true } = {}) {
  const source = Array.isArray(input) ? input : [];
  const normalized = [];

  for (const value of source) {
    const scope = String(value || "").trim().toLowerCase();
    if (!scope || !API_KEY_SCOPE_SET.has(scope) || normalized.includes(scope)) {
      continue;
    }

    normalized.push(scope);
  }

  if (normalized.length > 0) {
    return normalized;
  }

  return fallbackToAll ? [...API_KEY_SCOPE_VALUES] : [];
}

export function hasRequiredApiKeyScopes(grantedScopes, requiredScopes) {
  const granted = new Set(normalizeApiKeyScopes(grantedScopes, { fallbackToAll: true }));
  const required = normalizeApiKeyScopes(requiredScopes, { fallbackToAll: false });

  if (required.length === 0) {
    return true;
  }

  return required.every((scope) => granted.has(scope));
}
