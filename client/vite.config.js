import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const devPort = Number.parseInt(env.VITE_DEV_SERVER_PORT || "", 10);
  const proxyTarget = (env.VITE_DEV_API_PROXY_TARGET || env.VITE_API_BASE_URL_LOCAL || "http://localhost:3001").trim();
  const safeResponseHeaders = {
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin"
  };

  return {
    plugins: [react()],
    server: {
      port: Number.isFinite(devPort) ? devPort : 5173,
      headers: safeResponseHeaders,
      proxy: {
        "/api": proxyTarget
      }
    },
    preview: {
      headers: safeResponseHeaders
    },
    test: {
      environment: "jsdom",
      setupFiles: "./src/test/setup.js",
      globals: true
    }
  };
});
