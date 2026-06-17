export function formatDefinitionAge(ageHours) {
  if (!Number.isFinite(ageHours) || ageHours < 0) {
    return "unknown age";
  }

  if (ageHours < 1) {
    return "updated less than 1 hour ago";
  }

  const rounded = Math.round(ageHours * 10) / 10;
  const wholeHours = Math.round(rounded);
  if (Math.abs(rounded - wholeHours) < 0.05) {
    return `updated ${wholeHours} hour${wholeHours === 1 ? "" : "s"} ago`;
  }

  return `updated ${rounded} hours ago`;
}

export function describeClamAvDefinitions(definitions) {
  if (!definitions) {
    return "definitions status unavailable";
  }

  if (definitions.status === "missing") {
    return "definitions missing";
  }

  const suffix = formatDefinitionAge(definitions.ageHours);
  if (definitions.status === "stale") {
    return `definitions stale, ${suffix}`;
  }

  if (definitions.status === "current") {
    return `definitions current, ${suffix}`;
  }

  return definitions.detail || "definitions present";
}

export function printStatusLine(label, message) {
  process.stdout.write(`${label}: ${message}\n`);
}

export function printErrorLine(message) {
  process.stderr.write(`${message}\n`);
}

export function printVerboseJson(payload) {
  if (process.env.SIGNATURE_ENGINES_VERBOSE !== "true") {
    return;
  }

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}
