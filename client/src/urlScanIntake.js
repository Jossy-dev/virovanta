const DIRECT_URL_PATTERN =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{2,5})?(?:[/?#].*)?$/i;

export function looksLikeDirectUrlScanInput(input) {
  const trimmed = String(input || "").trim();
  if (!trimmed || /\s/.test(trimmed)) {
    return false;
  }

  return /^(?:https?:\/\/|www\.)/i.test(trimmed) || DIRECT_URL_PATTERN.test(trimmed);
}

export function buildUrlScanIntakeBody(input) {
  const trimmed = String(input || "").trim();

  return looksLikeDirectUrlScanInput(trimmed) ? { url: trimmed } : { message: trimmed };
}
