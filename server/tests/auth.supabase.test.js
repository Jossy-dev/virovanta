import fs from "fs/promises";
import os from "os";
import path from "path";
import jwt from "jsonwebtoken";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app/createApp.js";

const tempRoots = [];

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

async function setupSupabaseApp({ supabaseJwtSecret = "supabase-test-secret" } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-supabase-test-"));
  const uploadDir = path.join(root, "uploads");
  const dataFilePath = path.join(root, "store.json");
  tempRoots.push(root);

  const supabaseJwtIssuer = "https://example.supabase.co/auth/v1";
  const supabaseJwtAudience = "authenticated";

  const { app } = await createApp({
    dataFilePath,
    configOverrides: {
      uploadDir,
      dataFilePath,
      authProvider: "supabase",
      supabaseUrl: "https://example.supabase.co",
      supabaseAnonKey: "sb_publishable_test_key",
      supabaseJwtSecret,
      supabaseJwtIssuer,
      supabaseJwtAudience,
      supabaseJwtAlgorithm: "HS256",
      supabaseJwksUrl: "https://example.supabase.co/auth/v1/.well-known/jwks.json",
      requestsPerWindow: 5000,
      requestWindowMinutes: 15,
      enableClamAv: false,
      logLevel: "silent"
    }
  });

  return {
    app,
    supabaseJwtSecret,
    supabaseJwtIssuer,
    supabaseJwtAudience
  };
}

afterEach(async () => {
  vi.restoreAllMocks();

  const roots = tempRoots.splice(0);
  await Promise.all(
    roots.map(async (dir) => {
      await fs.rm(dir, { recursive: true, force: true });
    })
  );
});

describe("Supabase auth mode", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async (url, options = {}) => {
      const normalizedUrl = String(url);

      if (normalizedUrl.endsWith("/auth/v1/token?grant_type=password")) {
        return jsonResponse({
          access_token: jwt.sign(
            {
              sub: "supa_usr_1",
              email: "supa@example.com",
              user_metadata: { name: "Supa User" }
            },
            "supabase-test-secret",
            {
              algorithm: "HS256",
              issuer: "https://example.supabase.co/auth/v1",
              audience: "authenticated",
              expiresIn: "15m"
            }
          ),
          refresh_token: "refresh-token-1-abcdefghijklmnopqrstuvwxyz",
          expires_in: 3600,
          user: {
            id: "supa_usr_1",
            email: "supa@example.com",
            user_metadata: { name: "Supa User" }
          }
        });
      }

      if (normalizedUrl.endsWith("/auth/v1/token?grant_type=refresh_token")) {
        return jsonResponse({
          access_token: jwt.sign(
            {
              sub: "supa_usr_1",
              email: "supa@example.com",
              user_metadata: { name: "Supa User" }
            },
            "supabase-test-secret",
            {
              algorithm: "HS256",
              issuer: "https://example.supabase.co/auth/v1",
              audience: "authenticated",
              expiresIn: "15m"
            }
          ),
          refresh_token: "refresh-token-2-abcdefghijklmnopqrstuvwxyz",
          expires_in: 3600,
          user: {
            id: "supa_usr_1",
            email: "supa@example.com",
            user_metadata: { name: "Supa User" }
          }
        });
      }

      if (normalizedUrl.endsWith("/auth/v1/recover")) {
        return jsonResponse({});
      }

      if (normalizedUrl.endsWith("/auth/v1/.well-known/jwks.json")) {
        return jsonResponse({ keys: [] });
      }

      if (normalizedUrl.endsWith("/auth/v1/user") && String(options.method || "GET").toUpperCase() === "PUT") {
        return jsonResponse({
          user: {
            id: "supa_usr_1",
            email: "supa@example.com",
            user_metadata: { name: "Supa User" }
          }
        });
      }

      if (normalizedUrl.endsWith("/auth/v1/user")) {
        return jsonResponse({
          id: "supa_usr_3",
          email: "introspect@example.com",
          user_metadata: { name: "Introspected User" }
        });
      }

      if (normalizedUrl.endsWith("/auth/v1/logout")) {
        return new Response(null, { status: 204 });
      }

      if (normalizedUrl.endsWith("/auth/v1/signup")) {
        const body = JSON.parse(String(options.body || "{}"));
        if (body.email === "confirm@example.com") {
          return jsonResponse({
            user: {
              id: "supa_usr_pending",
              email: body.email,
              user_metadata: { name: body?.data?.name || "Pending User" },
              identities: [
                {
                  identity_id: "pending_identity_1",
                  provider: "email"
                }
              ]
            }
          });
        }

        if (body.email === "taken@example.com") {
          return jsonResponse({
            user: {
              id: "supa_usr_taken",
              email: body.email,
              user_metadata: { name: body?.data?.name || "Taken User" },
              identities: []
            }
          });
        }

        if (body.email === "taken-root@example.com") {
          return jsonResponse({
            id: "supa_usr_taken_root",
            email: body.email,
            user_metadata: { name: body?.data?.name || "Taken Root User" },
            identities: []
          });
        }

        return jsonResponse({
          access_token: jwt.sign(
            {
              sub: "supa_usr_2",
              email: body.email,
              user_metadata: { name: body?.data?.name || "New User" }
            },
            "supabase-test-secret",
            {
              algorithm: "HS256",
              issuer: "https://example.supabase.co/auth/v1",
              audience: "authenticated",
              expiresIn: "15m"
            }
          ),
          refresh_token: "refresh-token-3-abcdefghijklmnopqrstuvwxyz",
          expires_in: 3600,
          user: {
            id: "supa_usr_2",
            email: body.email,
            user_metadata: { name: body?.data?.name || "New User" }
          }
        });
      }

      throw new Error(`Unexpected fetch call in test: ${normalizedUrl}`);
    }));
  });

  it("supports register/login/refresh/logout/forgot-password via API routes", async () => {
    const { app } = await setupSupabaseApp();

    const register = await request(app).post("/api/auth/register").send({
      email: "newuser@example.com",
      password: "StrongPass!1234",
      name: "New User"
    });
    expect(register.status).toBe(201);
    expect(register.body.accessToken).toBeTruthy();
    expect(register.body.refreshToken).toBeTruthy();
    expect(register.body.user.email).toBe("newuser@example.com");

    const login = await request(app).post("/api/auth/login").send({
      email: "supa@example.com",
      password: "StrongPass!1234"
    });
    expect(login.status).toBe(200);
    expect(login.body.accessToken).toBeTruthy();
    expect(login.body.refreshToken).toBeTruthy();
    expect(login.body.user.email).toBe("supa@example.com");

    const me = await request(app).get("/api/auth/me").set("Authorization", `Bearer ${login.body.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe("supa@example.com");

    const refresh = await request(app).post("/api/auth/refresh").send({
      refreshToken: login.body.refreshToken
    });
    expect(refresh.status).toBe(200);
    expect(refresh.body.accessToken).toBeTruthy();
    expect(refresh.body.refreshToken).toBeTruthy();

    const forgot = await request(app).post("/api/auth/forgot-password").send({
      email: "supa@example.com"
    });
    expect(forgot.status).toBe(202);
    expect(forgot.body.accepted).toBe(true);

    const reset = await request(app).post("/api/auth/reset-password").send({
      accessToken: "recovery-token-abcdefghijklmnopqrstuvwxyz",
      password: "StrongPass!5678"
    });
    expect(reset.status).toBe(200);
    expect(reset.body.updated).toBe(true);

    const logout = await request(app)
      .post("/api/auth/logout")
      .set("Authorization", `Bearer ${refresh.body.accessToken}`)
      .send({
        refreshToken: refresh.body.refreshToken
      });
    expect(logout.status).toBe(204);
  });

  it("returns 202 when Supabase requires email confirmation before login", async () => {
    const { app } = await setupSupabaseApp();

    const register = await request(app).post("/api/auth/register").send({
      email: "confirm@example.com",
      password: "StrongPass!1234",
      name: "Pending User"
    });

    expect(register.status).toBe(202);
    expect(register.body.requiresEmailConfirmation).toBe(true);
    expect(register.body.email).toBe("confirm@example.com");
    expect(register.body.message).toMatch(/confirm your email/i);
  });

  it("returns 409 when Supabase signup payload indicates the email is already registered", async () => {
    const { app } = await setupSupabaseApp();

    const register = await request(app).post("/api/auth/register").send({
      email: "taken@example.com",
      password: "StrongPass!1234",
      name: "Taken User"
    });

    expect(register.status).toBe(409);
    expect(register.body.error.code).toBe("AUTH_EMAIL_EXISTS");
  });

  it("returns 409 when Supabase returns root-level obfuscated existing-user payload", async () => {
    const { app } = await setupSupabaseApp();

    const register = await request(app).post("/api/auth/register").send({
      email: "taken-root@example.com",
      password: "StrongPass!1234",
      name: "Taken Root User"
    });

    expect(register.status).toBe(409);
    expect(register.body.error.code).toBe("AUTH_EMAIL_EXISTS");
  });

  it("blocks repeat signup for pending-confirmation email by checking existing local auth record", async () => {
    const { app } = await setupSupabaseApp();

    const first = await request(app).post("/api/auth/register").send({
      email: "confirm@example.com",
      password: "StrongPass!1234",
      name: "Pending User"
    });
    expect(first.status).toBe(202);
    expect(first.body.requiresEmailConfirmation).toBe(true);

    const second = await request(app).post("/api/auth/register").send({
      email: "confirm@example.com",
      password: "StrongPass!1234",
      name: "Pending User"
    });
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe("AUTH_EMAIL_EXISTS");
  });

  it("falls back to /user introspection when shared JWT secret is not configured", async () => {
    const { app } = await setupSupabaseApp({ supabaseJwtSecret: "" });

    const me = await request(app).get("/api/auth/me").set("Authorization", "Bearer non-jwt-token");
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe("introspect@example.com");
  });
});
