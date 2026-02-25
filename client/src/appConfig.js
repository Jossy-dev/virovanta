function envString(name, fallback = "") {
  const value = import.meta.env?.[name];
  if (typeof value !== "string") {
    return fallback;
  }

  const normalized = value.trim();
  return normalized || fallback;
}

function normalizeSlug(value, fallback = "app") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return normalized || fallback;
}

function trimTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

const defaultAppName = envString("VITE_APP_NAME", "ViroVanta");
const defaultAppSlug = normalizeSlug(envString("VITE_APP_SLUG", defaultAppName), "virovanta");
const apiEnvironment = envString("VITE_API_ENV", envString("VITE_APP_ENV", "local")).toLowerCase();
const localApiBaseUrl = envString("VITE_API_BASE_URL_LOCAL", "http://localhost:3001");
const productionApiBaseUrl = envString("VITE_API_BASE_URL_PROD", "https://virovanta.onrender.com");
const directApiBaseUrl = envString("VITE_API_BASE_URL", "");

export const APP_NAME = defaultAppName;
export const APP_SLUG = defaultAppSlug;
export const APP_TAGLINE = envString("VITE_APP_TAGLINE", "Smart file malware and anomaly scanning");
export const SESSION_STORAGE_KEY = envString("VITE_SESSION_STORAGE_KEY", `${defaultAppSlug}-session`);
export const LOGO_ALT_TEXT = `${APP_NAME} logo`;

export const BRAND_MARKS = Object.freeze({
  darkSurface: envString("VITE_BRAND_MARK_DARK_PATH", "/brand/virovanta-mark-dark-bg.png"),
  lightSurface: envString("VITE_BRAND_MARK_LIGHT_PATH", "/brand/virovanta-mark-light-bg.png")
});

export const HERO_BG_DEFAULT = envString("VITE_HERO_BG_DEFAULT", "classic");
export const HERO_BG_VARIANTS = Object.freeze({
  classic: {
    videoSrc: envString("VITE_HERO_CLASSIC_VIDEO_PATH", "/media/virovanta-hero-loop-smooth.mp4"),
    posterSrc: envString("VITE_HERO_CLASSIC_POSTER_PATH", "/media/virovanta-hero-poster-smooth.jpg")
  },
  cinematic: {
    videoSrc: envString("VITE_HERO_CINEMATIC_VIDEO_PATH", "/media/virovanta-hero-loop-cinematic.mp4"),
    posterSrc: envString("VITE_HERO_CINEMATIC_POSTER_PATH", "/media/virovanta-hero-poster-cinematic.jpg")
  }
});

const selectedApiBaseUrl = directApiBaseUrl || (apiEnvironment === "prod" ? productionApiBaseUrl : localApiBaseUrl);
export const API_BASE_URL = trimTrailingSlash(selectedApiBaseUrl);

export function buildApiUrl(path) {
  if (!path) {
    return API_BASE_URL;
  }

  if (/^https?:\/\//i.test(path)) {
    return path;
  }

  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}
