import express from "express";
import path from "path";

const SPA_NAVIGATION_ROUTE = /^\/(?!api(?:\/|$))(?!.*\.[^/]+$).+/;

export function registerProductionClientRoutes(app, clientDistPath) {
  const indexFilePath = path.join(clientDistPath, "index.html");

  app.use(express.static(clientDistPath));

  app.get("/", (_req, res) => {
    res.sendFile(indexFilePath);
  });

  app.get("/index.html", (_req, res) => {
    res.sendFile(indexFilePath);
  });

  // Dashboard and marketing refreshes should return the SPA shell so React Router can resolve them client-side.
  app.get(SPA_NAVIGATION_ROUTE, (_req, res) => {
    res.sendFile(indexFilePath);
  });
}
