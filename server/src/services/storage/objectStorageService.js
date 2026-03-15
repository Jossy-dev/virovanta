import crypto from "crypto";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { pipeline } from "stream/promises";
import { DeleteObjectCommand, GetObjectCommand, S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";

function sanitizeSegment(value, fallback = "unknown") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);

  return normalized || fallback;
}

function sanitizeFileName(fileName) {
  const baseName = path.basename(String(fileName || "uploaded-file"));
  const extension = path.extname(baseName);
  const stem = baseName.slice(0, baseName.length - extension.length);
  const safeStem = sanitizeSegment(stem, "uploaded-file").slice(0, 120);
  const safeExtension = extension.replace(/[^.a-z0-9]+/gi, "").slice(0, 12);
  return `${safeStem}${safeExtension}`;
}

function normalizeBasePrefix(prefix) {
  const value = String(prefix || "")
    .trim()
    .replace(/^\/+|\/+$/g, "");

  return value;
}

export class ObjectStorageService {
  constructor({ config, logger }) {
    this.config = config;
    this.logger = logger;
    this.enabled = config.objectStorageProvider === "s3";
    this.basePrefix = normalizeBasePrefix(config.objectStoragePrefix);

    if (!this.enabled) {
      this.client = null;
      return;
    }

    this.client = new S3Client({
      region: config.objectStorageRegion,
      endpoint: config.objectStorageEndpoint || undefined,
      forcePathStyle: config.objectStorageForcePathStyle,
      credentials: {
        accessKeyId: config.objectStorageAccessKeyId,
        secretAccessKey: config.objectStorageSecretAccessKey
      }
    });
  }

  #withPrefix(key) {
    const normalizedKey = String(key || "").replace(/^\/+/, "");
    if (!this.basePrefix) {
      return normalizedKey;
    }
    return `${this.basePrefix}/${normalizedKey}`;
  }

  async uploadFileFromPath({ localPath, key, contentType = "application/octet-stream", metadata = {} }) {
    if (!this.enabled) {
      return null;
    }

    const stream = fs.createReadStream(localPath);
    const objectKey = this.#withPrefix(key);

    const upload = new Upload({
      client: this.client,
      params: {
        Bucket: this.config.objectStorageBucket,
        Key: objectKey,
        Body: stream,
        ContentType: contentType,
        Metadata: metadata
      }
    });

    const result = await upload.done();

    return {
      provider: this.config.objectStorageProvider,
      bucket: this.config.objectStorageBucket,
      key: objectKey,
      contentType,
      etag: result.ETag || null,
      location: result.Location || null
    };
  }

  async uploadJson({ key, payload, metadata = {} }) {
    if (!this.enabled) {
      return null;
    }

    const objectKey = this.#withPrefix(key);
    const body = JSON.stringify(payload);

    const result = await this.client.send(
      new PutObjectCommand({
        Bucket: this.config.objectStorageBucket,
        Key: objectKey,
        Body: body,
        ContentType: "application/json; charset=utf-8",
        Metadata: metadata
      })
    );

    return {
      provider: this.config.objectStorageProvider,
      bucket: this.config.objectStorageBucket,
      key: objectKey,
      contentType: "application/json; charset=utf-8",
      etag: result.ETag || null
    };
  }

  async downloadFileToPath({ key, localPath }) {
    if (!this.enabled) {
      throw new Error("Object storage is disabled.");
    }

    const normalizedKey = String(key || "").replace(/^\/+/, "");
    const objectKey =
      this.basePrefix && normalizedKey.startsWith(`${this.basePrefix}/`)
        ? normalizedKey
        : this.#withPrefix(normalizedKey);
    await fsPromises.mkdir(path.dirname(localPath), { recursive: true });

    const response = await this.client.send(
      new GetObjectCommand({
        Bucket: this.config.objectStorageBucket,
        Key: objectKey
      })
    );

    if (!response?.Body) {
      throw new Error("Object storage response did not include a body stream.");
    }

    await pipeline(response.Body, fs.createWriteStream(localPath));

    return {
      provider: this.config.objectStorageProvider,
      bucket: this.config.objectStorageBucket,
      key: objectKey
    };
  }

  async deleteObject({ key }) {
    if (!this.enabled) {
      return;
    }

    const normalizedKey = String(key || "").replace(/^\/+/, "");
    const objectKey =
      this.basePrefix && normalizedKey.startsWith(`${this.basePrefix}/`)
        ? normalizedKey
        : this.#withPrefix(normalizedKey);

    await this.client.send(
      new DeleteObjectCommand({
        Bucket: this.config.objectStorageBucket,
        Key: objectKey
      })
    );
  }

  buildQueueUploadKey({ userId, jobId, originalName }) {
    return this.buildUploadKey({ userId, jobId, originalName });
  }

  buildUploadKey({ userId, jobId, originalName }) {
    const safeUserId = sanitizeSegment(userId, "anonymous");
    const safeJobId = sanitizeSegment(jobId, crypto.randomUUID());
    const fileName = sanitizeFileName(originalName);

    return `uploads/${safeUserId}/${safeJobId}/${fileName}`;
  }

  buildReportKey({ userId, reportId }) {
    const safeUserId = sanitizeSegment(userId, "anonymous");
    const safeReportId = sanitizeSegment(reportId, crypto.randomUUID());
    return `reports/${safeUserId}/${safeReportId}.json`;
  }
}
