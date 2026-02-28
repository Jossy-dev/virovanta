import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createApp } from "./src/app/createApp.js";

async function start() {
  const { app, config, logger } = await createApp();

  if (process.env.NODE_ENV === "production") {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const clientDistPath = path.resolve(__dirname, "../client/dist");
    const indexFilePath = path.join(clientDistPath, "index.html");
    const notFoundFilePath = path.join(clientDistPath, "404.html");

    app.use(express.static(clientDistPath));

    app.get("/", (_req, res) => {
      res.sendFile(indexFilePath);
    });

    app.get("/index.html", (_req, res) => {
      res.sendFile(indexFilePath);
    });

    app.get(/^\/(?!api).+/, (_req, res) => {
      res.status(404).sendFile(notFoundFilePath);
    });
  }

  app.listen(config.port, () => {
    logger.info({ port: config.port, service: config.serviceName }, `${config.apiTitle} listening on port ${config.port}`);
  });
}

start().catch((error) => {
  console.error("Failed to start service", error);
  process.exit(1);
});
