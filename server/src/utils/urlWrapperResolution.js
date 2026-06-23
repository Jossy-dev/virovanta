const GENERIC_WRAPPER_PARAM_KEYS = Object.freeze(["u", "url", "target", "dest", "destination", "redirect", "redir", "continue", "to", "q", "next", "r"]);

const KNOWN_REDIRECT_WRAPPER_PROFILES = Object.freeze([
  {
    id: "facebook_linkshim",
    label: "Facebook link shim",
    matchesHost: (hostname) => hostname === "l.facebook.com" || hostname === "lm.facebook.com" || hostname === "www.facebook.com",
    matchesPath: (pathname) => pathname === "/l.php" || pathname === "/flx/warn/",
    targetParamKeys: ["u"]
  },
  {
    id: "facebook_login_forwarder",
    label: "Facebook login forwarder",
    matchesHost: (hostname) => hostname === "www.facebook.com" || hostname === "facebook.com" || hostname === "m.facebook.com",
    matchesPath: (pathname) => pathname === "/login/" || pathname === "/login" || pathname.startsWith("/login/device-based/"),
    targetParamKeys: ["next"]
  },
  {
    id: "instagram_linkshim",
    label: "Instagram link shim",
    matchesHost: (hostname) => hostname === "l.instagram.com",
    targetParamKeys: ["u"]
  },
  {
    id: "messenger_linkshim",
    label: "Messenger link shim",
    matchesHost: (hostname) => hostname === "l.messenger.com",
    targetParamKeys: ["u"]
  },
  {
    id: "microsoft_safelinks",
    label: "Microsoft Safe Links",
    matchesHost: (hostname) => hostname === "safelinks.protection.outlook.com" || hostname.endsWith(".safelinks.protection.outlook.com"),
    targetParamKeys: ["url"]
  },
  {
    id: "proofpoint_urldefense",
    label: "Proofpoint URL Defense",
    matchesHost: (hostname) => hostname === "urldefense.com" || hostname.endsWith(".urldefense.com"),
    targetParamKeys: ["u"]
  },
  {
    id: "google_redirect",
    label: "Google redirector",
    matchesHost: (hostname) => hostname === "google.com" || hostname === "www.google.com" || hostname.endsWith(".google.com"),
    targetParamKeys: ["url", "q", "continue"]
  }
]);

function safeDecodeUriComponent(value, maxPasses = 2) {
  let current = String(value || "");
  for (let pass = 0; pass < maxPasses; pass += 1) {
    if (!current.includes("%")) {
      break;
    }

    try {
      const decoded = decodeURIComponent(current);
      if (!decoded || decoded === current) {
        break;
      }
      current = decoded;
    } catch {
      break;
    }
  }
  return current;
}

function normalizeHttpUrlString(value) {
  if (!value) {
    return null;
  }

  try {
    const parsed = new URL(String(value || "").trim());
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return null;
    }
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

function extractHttpUrlCandidate(value) {
  const candidates = [];
  const raw = String(value || "").trim();
  const decoded = safeDecodeUriComponent(raw, 3);

  if (raw) {
    candidates.push(raw);
  }
  if (decoded && decoded !== raw) {
    candidates.push(decoded);
  }

  for (const candidate of candidates) {
    const normalized = normalizeHttpUrlString(candidate);
    if (normalized) {
      return normalized;
    }

    const embeddedMatch = candidate.match(/https?:\/\/[^\s"'<>]+/i);
    if (embeddedMatch?.[0]) {
      const embedded = normalizeHttpUrlString(embeddedMatch[0]);
      if (embedded) {
        return embedded;
      }
    }
  }

  return null;
}

function registrableLikeDomain(hostname) {
  const labels = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "")
    .split(".")
    .filter(Boolean);

  if (labels.length <= 2) {
    return labels.join(".");
  }

  return labels.slice(-2).join(".");
}

function getDomainFamily(hostname) {
  const normalized = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");

  if (!normalized) {
    return "";
  }

  if (normalized === "t.co" || normalized === "x.com" || normalized.endsWith(".x.com") || normalized === "twitter.com" || normalized.endsWith(".twitter.com")) {
    return "x";
  }

  if (normalized === "facebook.com" || normalized.endsWith(".facebook.com") || normalized === "messenger.com" || normalized.endsWith(".messenger.com")) {
    return "facebook";
  }

  if (normalized === "instagram.com" || normalized.endsWith(".instagram.com")) {
    return "instagram";
  }

  if (normalized === "google.com" || normalized.endsWith(".google.com")) {
    return "google";
  }

  if (normalized === "microsoft.com" || normalized.endsWith(".microsoft.com") || normalized.endsWith(".protection.outlook.com")) {
    return "microsoft";
  }

  return registrableLikeDomain(normalized);
}

function getRedirectWrapperProfile(hostname, pathname = "/") {
  const normalizedHost = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");
  const normalizedPath = String(pathname || "/").trim() || "/";

  return (
    KNOWN_REDIRECT_WRAPPER_PROFILES.find((profile) => {
      if (!profile.matchesHost(normalizedHost)) {
        return false;
      }

      if (typeof profile.matchesPath === "function") {
        return profile.matchesPath(normalizedPath);
      }

      return true;
    }) || null
  );
}

export function resolveWrapperChain(startUrl) {
  const normalizedStartUrl = normalizeHttpUrlString(startUrl) || String(startUrl || "").trim();
  const visited = new Set([normalizedStartUrl]);
  const chain = [];
  const wrapperHosts = [];
  let currentUrl = normalizedStartUrl;

  for (let depth = 0; depth < 6; depth += 1) {
    const decodedCurrentUrl = safeDecodeUriComponent(currentUrl, 1);
    const normalizedDecodedCurrentUrl = normalizeHttpUrlString(decodedCurrentUrl);
    if (normalizedDecodedCurrentUrl && normalizedDecodedCurrentUrl !== currentUrl && !visited.has(normalizedDecodedCurrentUrl)) {
      chain.push({
        kind: "percent_decode",
        label: "Percent-decoded URL",
        from: currentUrl,
        to: normalizedDecodedCurrentUrl
      });
      currentUrl = normalizedDecodedCurrentUrl;
      visited.add(currentUrl);
      continue;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(currentUrl);
    } catch {
      break;
    }

    const wrapperProfile = getRedirectWrapperProfile(parsedUrl.hostname, parsedUrl.pathname);
    if (!wrapperProfile) {
      break;
    }

    if (!wrapperHosts.includes(parsedUrl.hostname)) {
      wrapperHosts.push(parsedUrl.hostname);
    }

    const candidateKeys = [
      ...wrapperProfile.targetParamKeys,
      ...GENERIC_WRAPPER_PARAM_KEYS.filter((key) => !wrapperProfile.targetParamKeys.includes(key))
    ];

    let advanced = false;
    for (const key of candidateKeys) {
      const values = parsedUrl.searchParams.getAll(key);
      for (const value of values) {
        const candidateUrl = extractHttpUrlCandidate(value);
        if (!candidateUrl || candidateUrl === currentUrl || visited.has(candidateUrl)) {
          continue;
        }

        chain.push({
          kind: "wrapper_param",
          label: `${wrapperProfile.label} extracted target`,
          wrapperId: wrapperProfile.id,
          wrapperLabel: wrapperProfile.label,
          host: parsedUrl.hostname,
          paramKey: key,
          from: currentUrl,
          to: candidateUrl
        });
        currentUrl = candidateUrl;
        visited.add(currentUrl);
        advanced = true;
        break;
      }

      if (advanced) {
        break;
      }
    }

    if (!advanced) {
      break;
    }
  }

  return {
    status: chain.length > 0 ? "resolved" : "none",
    chain,
    wrapperHosts,
    extractedTargetUrl: currentUrl !== normalizedStartUrl ? currentUrl : null,
    analysisStartUrl: currentUrl
  };
}

export function buildNavigationChain({ submittedUrl, wrapperChain, redirects }) {
  const chain = [
    {
      kind: "submitted",
      label: "Submitted URL",
      from: null,
      to: submittedUrl
    }
  ];

  for (const step of wrapperChain || []) {
    chain.push({
      kind: step.kind,
      label: step.label,
      from: step.from || null,
      to: step.to || null,
      host: step.host || null,
      paramKey: step.paramKey || null,
      wrapperLabel: step.wrapperLabel || null,
      statusCode: step.statusCode || null
    });
  }

  for (const hop of redirects || []) {
    chain.push({
      kind: "http_redirect",
      label: "HTTP redirect",
      from: hop.from || null,
      to: hop.to || null,
      statusCode: hop.statusCode || null
    });
  }

  return chain;
}

export { getDomainFamily };
