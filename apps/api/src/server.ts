import express from "express";
import type { ErrorRequestHandler } from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import fetch from "node-fetch";
import { MongoServerError, ObjectId } from "mongodb";
import { loginSchema, registerSchema } from "@secure-wallet/shared";
import type { components } from "@secure-wallet/shared/api-client/types";

import { createLoginEventRepository, createUserRepository } from "./db/repositories";
import { logAuditEvent } from "./services/audit";
import { applySecurityHeaders } from "./middleware/secureHeaders";
import { rateLimitPlaceholder } from "./middleware/rateLimit";
import { lockoutPlaceholder } from "./middleware/lockout";
import { connectMongo, disconnectMongo, getDb } from "./db/mongo";
import { signAuthToken } from "./security/jwt";
import { hashPassword, verifyPassword } from "./security/password";

dotenv.config();

const app = express();
app.use(cors());
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
app.use(applySecurityHeaders);
app.use(rateLimitPlaceholder);
app.use(lockoutPlaceholder);

const PORT = process.env.PORT_API || 4000;
const AI_URL = process.env.AI_SERVICE_URL || "http://localhost:8000";
const DUPLICATE_KEY_ERROR_CODE = 11000;

const normalizeEmail = (email: string) => email.trim().toLowerCase();

const toEntityId = (value: unknown, fallback: string) => {
  if (value instanceof ObjectId) return value.toHexString();
  if (typeof value === "string" && value.trim()) return value;
  return fallback;
};

const toAnomalyScore = (value: unknown) =>
  typeof value === "number" && Number.isFinite(value) ? value : 0;

type AnomalyResponse = Partial<components["schemas"]["AnomalyScore"]> & Record<string, unknown>;

const registerShutdownHooks = () => {
  let shuttingDown = false;

  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;

    console.log(`Received ${signal}. Closing MongoDB connection...`);
    try {
      await disconnectMongo();
    } finally {
      process.exit(0);
    }
  };

  process.on("SIGINT", () => {
    void shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    void shutdown("SIGTERM");
  });
};

app.get("/health", async (_req, res) => {
  const timestamp = new Date().toISOString();

  try {
    await connectMongo();
    await getDb().command({ ping: 1 });

    res.json({ status: "ok", service: "api", db: "ok", timestamp });
  } catch (err) {
    console.error("Health-check failed (MongoDB)", err);
    res.status(503).json({ status: "degraded", service: "api", db: "down", timestamp });
  }
});

app.post("/auth/register", async (req, res) => {
  type RegisterReq = components["schemas"]["RegisterRequest"];
  const parsed = registerSchema.safeParse(req.body as RegisterReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const userRepository = createUserRepository();
  const email = normalizeEmail(parsed.data.email);

  try {
    const exists = await userRepository.existsByEmail(email);
    if (exists) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await hashPassword(parsed.data.password);
    const created = await userRepository.createUser({
      email,
      passwordHash,
      role: parsed.data.role,
    });

    const user: components["schemas"]["User"] = {
      id: created.insertedId.toString(),
      email,
      role: parsed.data.role,
    };

    const token = signAuthToken({ sub: user.id, email: user.email, role: user.role });
    await logAuditEvent({ actor: email, action: "REGISTER", userId: user.id, ipAddress: req.ip });

    return res.status(201).json({ token, user });
  } catch (err) {
    if (err instanceof MongoServerError && err.code === DUPLICATE_KEY_ERROR_CODE) {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error("Failed to register user", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/auth/login", async (req, res) => {
  type LoginReq = components["schemas"]["LoginRequest"];
  const parsed = loginSchema.safeParse(req.body as LoginReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const userRepository = createUserRepository();
  const loginEventRepository = createLoginEventRepository();
  const email = normalizeEmail(parsed.data.email);

  const userAgent = typeof req.headers["user-agent"] === "string" ? req.headers["user-agent"] : "unknown";

  try {
    const loginEvent = {
      ipAddress: req.ip,
      userAgent,
      timestamp: new Date().toISOString(),
    };

    let aiResult: AnomalyResponse = { score: 0.1, reasons: ["stubbed"] };
    try {
      const resp = await fetch(`${AI_URL}/ai/score`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(loginEvent),
      });
      aiResult = (await resp.json()) as AnomalyResponse;
    } catch (err) {
      console.warn("AI service not reachable, using default", err);
    }

    const userDoc = await userRepository.findByEmail(email);
    const score = toAnomalyScore(aiResult?.score);
    const isPasswordValid = userDoc ? await verifyPassword(parsed.data.password, userDoc.passwordHash) : false;

    await loginEventRepository.createLoginEvent({
      userId: userDoc?._id,
      email,
      ipAddress: req.ip,
      userAgent,
      success: isPasswordValid,
      anomaly: score,
      metadata: { aiResult },
    });

    if (!isPasswordValid || !userDoc) {
      await logAuditEvent({
        actor: email,
        action: "LOGIN_FAILED",
        details: `anomaly=${score}`,
        ipAddress: req.ip,
      });

      return res.status(401).json({ error: "Invalid credentials", anomaly: aiResult });
    }

    if (userDoc._id) {
      await userRepository.touchLastLogin(userDoc._id);
    }

    const user: components["schemas"]["User"] = {
      id: toEntityId(userDoc._id, email),
      email,
      role: userDoc.role,
    };

    const token = signAuthToken({ sub: user.id, email: user.email, role: user.role });
    await logAuditEvent({
      actor: email,
      action: "LOGIN",
      userId: user.id,
      details: `anomaly=${score}`,
      ipAddress: req.ip,
    });

    return res.json({ token, user, anomaly: aiResult });
  } catch (err) {
    console.error("Failed to login user", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/auth/logout", (_req, res) => {
  res.status(204).send();
});

// Contract placeholders below
app.get("/wallet/me", (_req, res) => {
  const wallet: components["schemas"]["Wallet"] = { id: "wallet1", balance: 0, currency: "USD" };
  res.json(wallet);
});

app.post("/wallet/deposit", (_req, res) => {
  res.json({ id: "wallet1", balance: 100, currency: "USD" });
});

app.post("/transfer", (_req, res) => {
  res.json({ status: "ok", transaction: { id: "txn1", amount: 10, type: "TRANSFER", createdAt: new Date().toISOString() } });
});

app.get("/transactions", (_req, res) => {
  res.json([]);
});

app.post("/security/login-events", (_req, res) => {
  res.json({ score: 0.1, reasons: ["stub"], received: _req.body });
});

app.get("/security/alerts", (_req, res) => {
  res.json([]);
});

app.get("/admin/users", (_req, res) => {
  res.json([]);
});

app.get("/admin/alerts", (_req, res) => {
  res.json([]);
});

app.get("/admin/audit-logs", (_req, res) => {
  res.json([]);
});

app.get("/admin/policies", (_req, res) => {
  res.json([]);
});

app.post("/admin/policies", (_req, res) => {
  res.json({ status: "updated" });
});

const errorHandler: ErrorRequestHandler = (err, _req, res, next) => {
  void next;
  console.error(err);
  res.status(500).json({ error: "Internal error" });
};

app.use(errorHandler);

const start = async () => {
  try {
    await connectMongo();
    registerShutdownHooks();
    app.listen(PORT, () => {
      console.log(`API listening on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("Failed to start API (MongoDB connection)", err);
    process.exit(1);
  }
};

start();
