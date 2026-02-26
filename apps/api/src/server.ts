import cors from "cors";
import dotenv from "dotenv";
import express, { type ErrorRequestHandler } from "express";
import fetch from "node-fetch";
import helmet from "helmet";
import { MongoServerError, ObjectId } from "mongodb";
import morgan from "morgan";

import { loginSchema, registerSchema } from "@secure-wallet/shared";
import type { components } from "@secure-wallet/shared/api-client/types";

import type { LoginEventDoc } from "./db/schemas";
import {
  connectMongo,
  disconnectMongo,
  getDb,
  readFromMongo,
} from "./db/mongo";
import {
  createLoginEventRepository,
  createUserRepository,
} from "./db/repositories";
import { applySecurityHeaders } from "./middleware/secureHeaders";
import { lockoutGuard } from "./middleware/lockout";
import { loginRateLimiter } from "./middleware/rateLimit";
import { requireAuth, requireRole } from "./middleware/auth";
import { decryptUserPII } from "./security/encryption";
import { signAuthToken } from "./security/jwt";
import { hashPassword, verifyPassword } from "./security/password";
import {
  getSecurityPolicy,
  getDefaultSecurityPolicy,
} from "./services/securityPolicy";
import { logAuditEvent } from "./services/audit";

dotenv.config();

const app = express();
app.use(cors());
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
app.use(applySecurityHeaders);
app.use(lockoutGuard);

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

type AnomalyResponse = Partial<components["schemas"]["AnomalyScore"]> &
  Record<string, unknown>;

const DEFAULT_SECURITY_POLICY = getDefaultSecurityPolicy();

const sanitizeUser = (doc: unknown) => {
  const validated = readFromMongo.user(doc);
  if (!validated) return null;
  const decrypted = decryptUserPII(validated);
  const { passwordHash, _id, ...rest } = decrypted;
  void passwordHash;

  return {
    ...rest,
    id: toEntityId(_id, decrypted.email),
    email: decrypted.email,
    role: decrypted.role,
    status: decrypted.status,
    lastLoginAt: decrypted.lastLoginAt,
    createdAt: decrypted.createdAt,
  };
};

const countRecentFailedAttempts = async (email: string, minutes: number) => {
  const loginEventRepository = createLoginEventRepository();
  const windowStart = new Date(Date.now() - minutes * 60 * 1000);
  return loginEventRepository.count({
    email,
    success: false,
    createdAt: { $gte: windowStart },
  } as never);
};

const lockUserAccount = async (
  userId: ObjectId | undefined,
  email: string,
  reason: string,
  ipAddress?: string,
) => {
  if (!userId) return;
  const userRepository = createUserRepository();
  await userRepository.updateOne({ _id: userId } as never, {
    $set: { status: "DISABLED", updatedAt: new Date() },
  });

  await logAuditEvent({
    actor: email || "system",
    userId: userId.toHexString(),
    action: "ACCOUNT_LOCKED",
    details: reason,
    ipAddress,
  });
};

const buildAlertFromLoginEvent = (
  event: LoginEventDoc,
  anomalyThreshold: number,
) => {
  const reasons: string[] = [];
  if (!event.success) reasons.push("Failed login");
  if ((event.anomaly ?? 0) >= anomalyThreshold)
    reasons.push("High anomaly score");
  if (!event.userAgent || event.userAgent === "unknown")
    reasons.push("Unknown device");
  if (!event.ipAddress) reasons.push("Missing IP address");

  return {
    id: toEntityId(event._id, event.email ?? "unknown"),
    email: event.email ?? "unknown",
    ipAddress: event.ipAddress ?? "unknown",
    userAgent: event.userAgent ?? "unknown",
    anomaly: event.anomaly ?? 0,
    success: Boolean(event.success),
    createdAt: event.createdAt ?? new Date(),
    reasons,
  };
};

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
    res
      .status(503)
      .json({ status: "degraded", service: "api", db: "down", timestamp });
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

    const token = signAuthToken({
      sub: user.id,
      email: user.email,
      role: user.role,
    });
    await logAuditEvent({
      actor: email,
      action: "REGISTER",
      userId: user.id,
      ipAddress: req.ip,
    });

    return res.status(201).json({ token, user });
  } catch (err) {
    if (
      err instanceof MongoServerError &&
      err.code === DUPLICATE_KEY_ERROR_CODE
    ) {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error("Failed to register user", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/auth/login", loginRateLimiter, async (req, res) => {
  type LoginReq = components["schemas"]["LoginRequest"];
  const parsed = loginSchema.safeParse(req.body as LoginReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const userRepository = createUserRepository();
  const loginEventRepository = createLoginEventRepository();
  const email = normalizeEmail(parsed.data.email);
  const policy = await getSecurityPolicy();

  const userAgent =
    typeof req.headers["user-agent"] === "string"
      ? req.headers["user-agent"]
      : "unknown";

  try {
    const loginEventPayload = {
      ipAddress: req.ip,
      userAgent,
      timestamp: new Date().toISOString(),
    };

    let aiResult: AnomalyResponse = { score: 0.1, reasons: ["stubbed"] };
    try {
      const resp = await fetch(`${AI_URL}/ai/score`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(loginEventPayload),
      });
      aiResult = (await resp.json()) as AnomalyResponse;
    } catch (err) {
      console.warn("AI service not reachable, using default", err);
    }

    const userDoc = await userRepository.findByEmail(email);
    const score = toAnomalyScore(aiResult?.score);

    if (userDoc?.status === "DISABLED") {
      await loginEventRepository.createLoginEvent({
        userId: userDoc._id,
        email,
        ipAddress: req.ip,
        userAgent,
        success: false,
        anomaly: score,
        metadata: { aiResult, reason: "ACCOUNT_DISABLED" },
      });
      await logAuditEvent({
        actor: email,
        userId: toEntityId(userDoc._id, email),
        action: "LOGIN_BLOCKED",
        details: "account disabled",
        ipAddress: req.ip,
      });
      return res
        .status(423)
        .json({ error: "Account is locked. Please contact support." });
    }

    const failedBefore = await countRecentFailedAttempts(
      email,
      policy.lockoutMinutes,
    );
    if (failedBefore >= policy.maxLoginAttempts) {
      if (userDoc?._id) {
        await lockUserAccount(
          userDoc._id,
          email,
          "Too many failed attempts",
          req.ip,
        );
      }
      await loginEventRepository.createLoginEvent({
        userId: userDoc?._id,
        email,
        ipAddress: req.ip,
        userAgent,
        success: false,
        anomaly: score,
        metadata: { aiResult, reason: "LOCKOUT_THRESHOLD" },
      });
      return res
        .status(423)
        .json({ error: "Account temporarily locked due to repeated failures" });
    }

    const isPasswordValid = userDoc
      ? await verifyPassword(parsed.data.password, userDoc.passwordHash)
      : false;

    await loginEventRepository.createLoginEvent({
      userId: userDoc?._id,
      email,
      ipAddress: req.ip,
      userAgent,
      success: isPasswordValid,
      anomaly: score,
      metadata: { aiResult },
    });

    if (score >= policy.anomalyAlertThreshold) {
      await logAuditEvent({
        actor: email,
        userId: userDoc?._id ? userDoc._id.toHexString() : undefined,
        action: "AI_ALERT",
        details: { score, reasons: aiResult?.reasons ?? [] },
        ipAddress: req.ip,
      });
    }

    if (!isPasswordValid || !userDoc) {
      await logAuditEvent({
        actor: email,
        action: "LOGIN_FAILED",
        details: `anomaly=${score}`,
        ipAddress: req.ip,
      });

      const failedAttempts = failedBefore + 1;
      if (userDoc?._id && failedAttempts >= policy.maxLoginAttempts) {
        await lockUserAccount(
          userDoc._id,
          email,
          "Exceeded failed attempts",
          req.ip,
        );
        return res.status(423).json({
          error: "Account locked after repeated failed attempts",
          anomaly: aiResult,
        });
      }

      return res
        .status(401)
        .json({ error: "Invalid credentials", anomaly: aiResult });
    }

    if (userDoc.status !== "ACTIVE") {
      await logAuditEvent({
        actor: email,
        userId: userDoc._id?.toHexString(),
        action: "LOGIN_BLOCKED",
        details: `status=${userDoc.status}`,
        ipAddress: req.ip,
      });
      return res
        .status(423)
        .json({ error: "Account is not active", anomaly: aiResult });
    }

    if (userDoc._id) {
      await userRepository.touchLastLogin(userDoc._id);
    }

    const user: components["schemas"]["User"] = {
      id: toEntityId(userDoc._id, email),
      email,
      role: userDoc.role,
    };

    const token = signAuthToken({
      sub: user.id,
      email: user.email,
      role: user.role,
    });
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

app.post("/auth/change-password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body as {
    currentPassword?: string;
    newPassword?: string;
  };
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: "Missing password fields" });
  }

  const userRepository = createUserRepository();
  const userDoc = await userRepository.findValidatedById(req.user?.sub ?? "");
  if (!userDoc) return res.status(404).json({ error: "User not found" });

  const isValid = await verifyPassword(currentPassword, userDoc.passwordHash);
  if (!isValid) return res.status(401).json({ error: "Invalid credentials" });

  const passwordHash = await hashPassword(newPassword);
  await userRepository.updatePassword(userDoc._id!, passwordHash);

  await logAuditEvent({
    actor: req.user?.email,
    userId: userDoc._id?.toHexString(),
    action: "CHANGE_PASSWORD",
    ipAddress: req.ip,
  });

  return res.status(204).send();
});

// Contract placeholders below
app.get("/wallet/me", requireAuth, (_req, res) => {
  const wallet: components["schemas"]["Wallet"] = {
    id: "wallet1",
    balance: 0,
    currency: "USD",
  };
  res.json(wallet);
});

app.post("/wallet/deposit", requireAuth, (_req, res) => {
  res.json({ id: "wallet1", balance: 100, currency: "USD" });
});

app.post("/transfer", requireAuth, (_req, res) => {
  res.json({
    status: "ok",
    transaction: {
      id: "txn1",
      amount: 10,
      type: "TRANSFER",
      createdAt: new Date().toISOString(),
    },
  });
});

app.get("/transactions", requireAuth, (_req, res) => {
  res.json([]);
});

app.post("/security/login-events", (_req, res) => {
  res.json({ score: 0.1, reasons: ["stub"], received: _req.body });
});

app.get("/security/alerts", async (_req, res) => {
  const policy = await getSecurityPolicy();
  const repo = createLoginEventRepository();
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const events = await repo.findMany({ createdAt: { $gte: since } } as never, {
    sort: { createdAt: -1 },
    limit: 100,
  });
  const normalized = events
    .map((e) => readFromMongo.loginEvent(e))
    .filter(Boolean) as LoginEventDoc[];
  const alerts = normalized
    .filter(
      (evt) =>
        !evt.success || (evt.anomaly ?? 0) >= policy.anomalyAlertThreshold,
    )
    .map((evt) => ({
      ...buildAlertFromLoginEvent(evt, policy.anomalyAlertThreshold),
      severity: !evt.success ? "high" : "medium",
    }));
  res.json(alerts);
});

app.get(
  "/admin/users",
  requireAuth,
  requireRole(["ADMIN"]),
  async (_req, res) => {
    const userRepository = createUserRepository();
    const docs = await userRepository.findMany(
      {},
      { sort: { createdAt: -1 }, limit: 200 },
    );
    const users = docs.map(sanitizeUser).filter(Boolean);
    res.json(users);
  },
);

app.patch(
  "/admin/users/:id/status",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const { status, reason } = req.body as { status?: string; reason?: string };
    const allowedStatuses = ["ACTIVE", "DISABLED", "PENDING"] as const;
    type UserStatus = (typeof allowedStatuses)[number];
    const statusNormalized =
      typeof status === "string" ? status.trim().toUpperCase() : "";
    if (!allowedStatuses.includes(statusNormalized as UserStatus)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    try {
      const id = new ObjectId(req.params.id);
      const userRepository = createUserRepository();
      await userRepository.updateOne({ _id: id } as never, {
        $set: { status: statusNormalized as UserStatus, updatedAt: new Date() },
      });
      const updated = await userRepository.findValidatedById(id);
      const sanitized = sanitizeUser(updated);

      await logAuditEvent({
        actor: "admin",
        userId: id.toHexString(),
        action:
          statusNormalized === "DISABLED"
            ? "ACCOUNT_LOCKED"
            : "ACCOUNT_UNLOCKED",
        details: reason ?? "manual update",
        ipAddress: req.ip,
      });

      return res.json({ user: sanitized });
    } catch (err) {
      console.error("Failed to update user status", err);
      return res.status(400).json({ error: "Invalid user id" });
    }
  },
);

app.get(
  "/admin/login-events",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const limit = Math.min(
      parseInt(String(req.query.limit ?? "50"), 10) || 50,
      200,
    );
    const repo = createLoginEventRepository();
    const events = await repo.findMany({}, { sort: { createdAt: -1 }, limit });
    const normalized = events
      .map((e) => readFromMongo.loginEvent(e))
      .filter(Boolean)
      .map((evt) => ({
        id: toEntityId(evt?._id, evt?.email ?? "unknown"),
        email: evt?.email ?? "unknown",
        ipAddress: evt?.ipAddress ?? "unknown",
        userAgent: evt?.userAgent ?? "unknown",
        success: evt?.success ?? false,
        anomaly: evt?.anomaly ?? 0,
        createdAt: evt?.createdAt ?? new Date(),
        metadata: evt?.metadata ?? {},
      }));
    res.json(normalized);
  },
);

app.get(
  "/admin/transactions",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const limit = Math.min(
      parseInt(String(req.query.limit ?? "50"), 10) || 50,
      200,
    );
    const docs = await getDb()
      .collection("transactions")
      .find({}, { sort: { createdAt: -1 }, limit })
      .toArray();
    const normalized = docs
      .map((d) => readFromMongo.transaction(d))
      .filter(Boolean)
      .map((txn) => ({
        id: toEntityId(txn?._id, "txn"),
        amount: txn?.amount ?? 0,
        type: txn?.type ?? "TRANSFER",
        status: txn?.status ?? "COMPLETED",
        description: txn?.description ?? "",
        createdAt: txn?.createdAt ?? new Date(),
        fromUserId: txn?.fromUserId?.toHexString?.() ?? undefined,
        toUserId: txn?.toUserId?.toHexString?.() ?? undefined,
      }));
    res.json(normalized);
  },
);

app.get(
  "/admin/alerts",
  requireAuth,
  requireRole(["ADMIN"]),
  async (_req, res) => {
    const policy = await getSecurityPolicy();
    const repo = createLoginEventRepository();
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const events = await repo.findMany(
      { createdAt: { $gte: since } } as never,
      {
        sort: { createdAt: -1 },
        limit: 100,
      },
    );
    const normalized = events
      .map((e) => readFromMongo.loginEvent(e))
      .filter(Boolean) as LoginEventDoc[];
    const alerts = normalized
      .filter(
        (evt) =>
          !evt.success || (evt.anomaly ?? 0) >= policy.anomalyAlertThreshold,
      )
      .map((evt) => ({
        ...buildAlertFromLoginEvent(evt, policy.anomalyAlertThreshold),
        severity: !evt.success ? "high" : "medium",
      }));
    res.json(alerts);
  },
);

app.get(
  "/admin/audit-logs",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const limit = Math.min(
      parseInt(String(req.query.limit ?? "100"), 10) || 100,
      300,
    );
    const docs = await getDb()
      .collection("auditLogs")
      .find({}, { sort: { createdAt: -1 }, limit })
      .toArray();
    const logs = docs
      .map((d) => readFromMongo.auditLog(d))
      .filter(Boolean)
      .map((log) => ({
        id: toEntityId(log?._id, log?.actor ?? "system"),
        actor: log?.actor ?? "system",
        action: log?.action ?? "UNKNOWN",
        details: log?.details ?? "",
        ipAddress: log?.ipAddress ?? "unknown",
        createdAt: log?.createdAt ?? new Date(),
      }));
    res.json(logs);
  },
);

app.get(
  "/admin/policies",
  requireAuth,
  requireRole(["ADMIN"]),
  async (_req, res) => {
    const policy = await getSecurityPolicy();
    res.json(policy);
  },
);

app.post(
  "/admin/policies",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const body = req.body as Partial<typeof DEFAULT_SECURITY_POLICY>;
    const policy = {
      ...DEFAULT_SECURITY_POLICY,
      ...body,
      updatedAt: new Date(),
      createdAt: new Date(),
    };
    await getDb()
      .collection("securityPolicies")
      .insertOne(policy as never);
    res.json({ status: "updated", policy });
  },
);

app.post(
  "/admin/demo/bruteforce",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const email =
      typeof req.body?.email === "string"
        ? normalizeEmail(req.body.email)
        : "bruteforce@example.com";
    const userAgent = "demo-script";
    const repo = createLoginEventRepository();
    const userRepo = createUserRepository();
    const userDoc = await userRepo.findByEmail(email);
    const userId = userDoc?._id;

    const entries = Array.from({ length: 6 }).map((_, i) => ({
      userId,
      email,
      ipAddress: `10.0.0.${i + 10}`,
      userAgent,
      success: false,
      anomaly: 0.8,
      metadata: { scenario: "bruteforce" },
    }));
    for (const evt of entries) {
      await repo.createLoginEvent(evt);
    }
    if (userId) {
      await lockUserAccount(userId, email, "Demo brute force lock", req.ip);
    }
    res.json({ inserted: entries.length, email });
  },
);

app.post(
  "/admin/demo/unusual-login",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const email =
      typeof req.body?.email === "string"
        ? normalizeEmail(req.body.email)
        : "anomaly@example.com";
    const repo = createLoginEventRepository();
    const userRepo = createUserRepository();
    const userDoc = await userRepo.findByEmail(email);
    const userId = userDoc?._id;

    const payload = {
      userId,
      email,
      ipAddress: req.body?.ipAddress || "203.0.113.42",
      userAgent: req.body?.userAgent || "UnknownDevice/1.0",
      success: true,
      anomaly: 0.92,
      metadata: {
        scenario: "unusual-device",
        reasons: ["new device", "geo mismatch"],
      },
    };
    await repo.createLoginEvent(payload);
    await logAuditEvent({
      actor: email,
      userId: userId?.toHexString(),
      action: "AI_ALERT",
      details: payload.metadata,
      ipAddress: payload.ipAddress,
    });
    res.json({ inserted: 1, email });
  },
);

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
