import crypto from "crypto";

import cors from "cors";
import dotenv from "dotenv";
import express, { type ErrorRequestHandler } from "express";
import fetch from "node-fetch";
import helmet from "helmet";
import morgan from "morgan";
import type { Wallet } from "@prisma/client";

import { loginSchema, registerSchema } from "@secure-wallet/shared";
import type { components } from "@secure-wallet/shared/api-client/types";

import { prisma } from "./db/prisma";
import {
  createAuditLogRepository,
  createLoginEventRepository,
  createUserRepository,
  type LoginEventEntity,
  type UserEntity,
} from "./db/repositories";
import { applySecurityHeaders } from "./middleware/secureHeaders";
import { lockoutGuard } from "./middleware/lockout";
import { loginRateLimiter } from "./middleware/rateLimit";
import { requireAuth, requireRole } from "./middleware/auth";
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
const ADMIN_EMAIL = "ledanhdat56@gmail.com";
const ADMIN_PASSWORD = "Ledanhdat2005@";

const normalizeEmail = (email: string) => email.trim().toLowerCase();

const toAnomalyScore = (value: unknown) =>
  typeof value === "number" && Number.isFinite(value) ? value : 0;

type AnomalyResponse = Partial<components["schemas"]["AnomalyScore"]> &
  Record<string, unknown>;

const DEFAULT_SECURITY_POLICY = getDefaultSecurityPolicy();

const sanitizeUser = (user: UserEntity | null) => {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  void passwordHash;
  return rest;
};

const countRecentFailedAttempts = async (email: string, minutes: number) => {
  const loginEventRepository = createLoginEventRepository();
  const windowStart = new Date(Date.now() - minutes * 60 * 1000);
  return loginEventRepository.countRecentFailures(email, windowStart);
};

const lockUserAccount = async (
  userId: string | undefined,
  email: string,
  reason: string,
  ipAddress?: string,
) => {
  if (!userId) return;
  const userRepository = createUserRepository();
  await userRepository.setStatus(userId, "DISABLED");

  await logAuditEvent({
    actor: email || "system",
    userId,
    action: "ACCOUNT_LOCKED",
    details: reason,
    ipAddress,
  });
};

const buildAlertFromLoginEvent = (
  event: LoginEventEntity,
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
    id: event.id,
    email: event.email ?? "unknown",
    ipAddress: event.ipAddress ?? "unknown",
    userAgent: event.userAgent ?? "unknown",
    anomaly: event.anomaly ?? 0,
    success: Boolean(event.success),
    createdAt: event.createdAt ?? new Date(),
    reasons,
  };
};

const toPositiveAmount = (value: unknown) => {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
};

const buildAccountNumber = (userId: string) => {
  const hash = crypto.createHash("sha256").update(userId).digest();
  let digits = "";
  for (const byte of hash) {
    digits += String(byte % 10);
    if (digits.length >= 10) break;
  }
  return `97${digits.padEnd(10, "0")}`;
};

const buildWalletQrPayload = (accountNumber: string) =>
  `EWALLET|ACC:${accountNumber}|BANK:SECURE-WALLET`;

const buildWalletQrImageUrl = (qrPayload: string) =>
  `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(qrPayload)}`;

const findWalletByAccountNumber = (accountNumber: string) =>
  prisma.wallet.findFirst({
    where: {
      metadata: {
        path: ["accountNumber"],
        equals: accountNumber,
      },
    },
  });

const attachWalletIdentity = async (wallet: Wallet): Promise<Wallet> => {
  if (!wallet.userId) return wallet;
  const metadata =
    wallet.metadata && typeof wallet.metadata === "object"
      ? (wallet.metadata as Record<string, unknown>)
      : {};
  const existingAccountNumber =
    typeof metadata.accountNumber === "string" ? metadata.accountNumber : "";
  const existingQrPayload =
    typeof metadata.qrPayload === "string" ? metadata.qrPayload : "";
  const existingQrImageUrl =
    typeof metadata.qrImageUrl === "string" ? metadata.qrImageUrl : "";

  if (existingAccountNumber && existingQrPayload && existingQrImageUrl) {
    return wallet;
  }

  const accountNumber = existingAccountNumber || buildAccountNumber(wallet.userId);
  const qrPayload = existingQrPayload || buildWalletQrPayload(accountNumber);
  const qrImageUrl = existingQrImageUrl || buildWalletQrImageUrl(qrPayload);

  return prisma.wallet.update({
    where: { id: wallet.id },
    data: {
      metadata: {
        ...metadata,
        accountNumber,
        qrPayload,
        qrImageUrl,
      } as never,
    },
  });
};

const getOrCreateWalletByUserId = async (userId: string) => {
  const existing = await prisma.wallet.findFirst({ where: { userId } });
  if (existing) return attachWalletIdentity(existing);

  const created = await prisma.wallet.create({
    data: {
      id: crypto.randomUUID(),
      userId,
      balance: 0,
      currency: "USD",
      status: "ACTIVE",
      metadata: {
        accountNumber: buildAccountNumber(userId),
      } as never,
    },
  });
  return attachWalletIdentity(created);
};

const registerShutdownHooks = () => {
  let shuttingDown = false;

  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;

    console.log(`Received ${signal}. Closing PostgreSQL connection...`);
    try {
      await prisma.$disconnect();
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
    await prisma.$queryRaw`SELECT 1`;

    res.json({ status: "ok", service: "api", db: "ok", timestamp });
  } catch (err) {
    console.error("Health-check failed (PostgreSQL)", err);
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
      role: "USER",
      fullName: parsed.data.fullName?.trim(),
    });
    await getOrCreateWalletByUserId(created.id);

    const user: components["schemas"]["User"] = {
      id: created.id,
      email,
      role: "USER",
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
    const errorCode =
      typeof err === "object" && err !== null && "code" in err
        ? (err as { code?: string }).code
        : undefined;
    if (errorCode === "P2002") {
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
        userId: userDoc.id,
        email,
        ipAddress: req.ip,
        userAgent,
        success: false,
        anomaly: score,
        metadata: { aiResult, reason: "ACCOUNT_DISABLED" },
      });
      await logAuditEvent({
        actor: email,
        userId: userDoc.id,
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
      if (userDoc?.id) {
        await lockUserAccount(
          userDoc.id,
          email,
          "Too many failed attempts",
          req.ip,
        );
      }
      await loginEventRepository.createLoginEvent({
        userId: userDoc?.id,
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
      userId: userDoc?.id,
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
        userId: userDoc?.id,
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
      if (userDoc?.id && failedAttempts >= policy.maxLoginAttempts) {
        await lockUserAccount(
          userDoc.id,
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
        userId: userDoc.id,
        action: "LOGIN_BLOCKED",
        details: `status=${userDoc.status}`,
        ipAddress: req.ip,
      });
      return res
        .status(423)
        .json({ error: "Account is not active", anomaly: aiResult });
    }

    await userRepository.touchLastLogin(userDoc.id);

    const user: components["schemas"]["User"] = {
      id: userDoc.id,
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
  await userRepository.updatePassword(userDoc.id, passwordHash);

  await logAuditEvent({
    actor: req.user?.email,
    userId: userDoc.id,
    action: "CHANGE_PASSWORD",
    ipAddress: req.ip,
  });

  return res.status(204).send();
});

app.get("/wallet/me", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const wallet = await getOrCreateWalletByUserId(userId);
    const metadata =
      wallet.metadata && typeof wallet.metadata === "object"
        ? (wallet.metadata as Record<string, unknown>)
        : {};
    const payload: components["schemas"]["Wallet"] = {
      id: wallet.id,
      balance: Number(wallet.balance),
      currency: wallet.currency,
    };
    return res.json({
      ...payload,
      accountNumber:
        typeof metadata.accountNumber === "string"
          ? metadata.accountNumber
          : "",
      qrPayload: typeof metadata.qrPayload === "string" ? metadata.qrPayload : "",
      qrImageUrl:
        typeof metadata.qrImageUrl === "string" ? metadata.qrImageUrl : "",
    });
  } catch (err) {
    console.error("Failed to get wallet", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.get("/wallet/resolve/:accountNumber", requireAuth, async (req, res) => {
  const requesterId = req.user?.sub;
  if (!requesterId) return res.status(401).json({ error: "Unauthorized" });

  const accountNumber = String(req.params.accountNumber || "")
    .replace(/\D/g, "")
    .slice(0, 19);
  if (!/^\d{8,19}$/.test(accountNumber)) {
    return res.status(400).json({ error: "Invalid account number" });
  }

  try {
    const wallet = await findWalletByAccountNumber(accountNumber);
    if (!wallet?.userId) {
      return res.status(404).json({ error: "Recipient account not found" });
    }
    if (wallet.userId === requesterId) {
      return res.status(400).json({ error: "Cannot transfer to self" });
    }

    const receiver = await prisma.user.findUnique({
      where: { id: wallet.userId },
      select: {
        id: true,
        email: true,
        fullName: true,
        status: true,
      },
    });
    if (!receiver) {
      return res.status(404).json({ error: "Recipient account not found" });
    }
    if (receiver.status !== "ACTIVE") {
      return res.status(423).json({ error: "Recipient account is locked" });
    }

    return res.json({
      accountNumber,
      userId: receiver.id,
      holderName: receiver.fullName || receiver.email.split("@")[0] || "User",
      holderEmail: receiver.email,
    });
  } catch (err) {
    console.error("Failed to resolve account", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/wallet/deposit", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const amount = toPositiveAmount((req.body as { amount?: unknown })?.amount);
  if (!amount) return res.status(400).json({ error: "Invalid amount" });

  try {
    const updatedWallet = await prisma.$transaction(async (tx) => {
      const wallet = await tx.wallet.findFirst({ where: { userId } });
      const nextWallet =
        wallet ??
        (await tx.wallet.create({
          data: {
            id: crypto.randomUUID(),
            userId,
            balance: 0,
            currency: "USD",
            status: "ACTIVE",
          },
        }));

      const updated = await tx.wallet.update({
        where: { id: nextWallet.id },
        data: { balance: { increment: amount } },
      });

      await tx.transaction.create({
        data: {
          id: crypto.randomUUID(),
          walletId: updated.id,
          amount,
          type: "DEPOSIT",
          status: "COMPLETED",
          description: "Wallet deposit",
          fromUserId: userId,
          toUserId: userId,
        },
      });

      return updated;
    });

    return res.json({
      id: updatedWallet.id,
      balance: Number(updatedWallet.balance),
      currency: updatedWallet.currency,
    });
  } catch (err) {
    console.error("Failed to deposit", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/transfer", requireAuth, async (req, res) => {
  const senderUserId = req.user?.sub;
  if (!senderUserId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    toUserId?: string;
    toAccount?: string;
    amount?: unknown;
    note?: string;
  };
  const toUserId =
    typeof body.toUserId === "string" ? body.toUserId.trim() : "";
  const toAccount =
    typeof body.toAccount === "string"
      ? body.toAccount.replace(/\D/g, "").slice(0, 19)
      : "";
  const note = typeof body.note === "string" ? body.note.trim() : "";
  const amount = toPositiveAmount(body.amount);

  if (!toUserId && !toAccount) {
    return res.status(400).json({ error: "Missing recipient account" });
  }
  if (!amount) return res.status(400).json({ error: "Invalid amount" });

  try {
    const senderWallet = await getOrCreateWalletByUserId(senderUserId);
    const senderMeta =
      senderWallet.metadata && typeof senderWallet.metadata === "object"
        ? (senderWallet.metadata as Record<string, unknown>)
        : {};
    const senderAccountNumber =
      typeof senderMeta.accountNumber === "string"
        ? senderMeta.accountNumber
        : "";

    let resolvedReceiverUserId = toUserId;
    let receiverWalletByAccount:
      | { id: string; userId: string | null; metadata: unknown }
      | null = null;

    if (toAccount) {
      receiverWalletByAccount = await findWalletByAccountNumber(toAccount);
      if (!receiverWalletByAccount?.userId) {
        return res.status(404).json({ error: "Recipient account not found" });
      }
      resolvedReceiverUserId = receiverWalletByAccount.userId;
    }

    if (resolvedReceiverUserId === senderUserId) {
      return res.status(400).json({ error: "Cannot transfer to self" });
    }

    if (!resolvedReceiverUserId) {
      return res.status(404).json({ error: "Recipient not found" });
    }

    const receiver = await prisma.user.findUnique({
      where: { id: resolvedReceiverUserId },
    });
    if (!receiver) return res.status(404).json({ error: "Recipient not found" });

    const transferResult = await prisma.$transaction(async (tx) => {
      const senderWallet = await tx.wallet.findFirst({
        where: { userId: senderUserId },
      });
      if (!senderWallet) throw new Error("SENDER_WALLET_NOT_FOUND");
      if (Number(senderWallet.balance) < amount)
        throw new Error("INSUFFICIENT_BALANCE");

      const receiverWallet =
        (receiverWalletByAccount
          ? await tx.wallet.findFirst({ where: { id: receiverWalletByAccount.id } })
          : null) ??
        (await tx.wallet.findFirst({ where: { userId: resolvedReceiverUserId } })) ??
        (await tx.wallet.create({
          data: {
            id: crypto.randomUUID(),
            userId: resolvedReceiverUserId,
            balance: 0,
            currency: senderWallet.currency,
            status: "ACTIVE",
            metadata: {
              accountNumber: buildAccountNumber(resolvedReceiverUserId),
            } as never,
          },
        }));

      const receiverMeta =
        receiverWallet.metadata && typeof receiverWallet.metadata === "object"
          ? (receiverWallet.metadata as Record<string, unknown>)
          : {};
      const receiverAccountNumber =
        typeof receiverMeta.accountNumber === "string"
          ? receiverMeta.accountNumber
          : buildAccountNumber(resolvedReceiverUserId);
      const reconciliationId = crypto.randomUUID();

      await tx.wallet.update({
        where: { id: senderWallet.id },
        data: { balance: { decrement: amount } },
      });
      await tx.wallet.update({
        where: { id: receiverWallet.id },
        data: { balance: { increment: amount } },
      });

      const debitTx = await tx.transaction.create({
        data: {
          id: crypto.randomUUID(),
          walletId: senderWallet.id,
          counterpartyWalletId: receiverWallet.id,
          amount,
          type: "TRANSFER",
          status: "COMPLETED",
          description: note || `Transfer to ${receiverAccountNumber}`,
          fromUserId: senderUserId,
          toUserId: resolvedReceiverUserId,
          metadata: {
            entry: "DEBIT",
            reconciliationId,
            fromAccount: senderAccountNumber,
            toAccount: receiverAccountNumber,
          } as never,
        },
      });

      await tx.transaction.create({
        data: {
          id: crypto.randomUUID(),
          walletId: receiverWallet.id,
          counterpartyWalletId: senderWallet.id,
          amount,
          type: "TRANSFER",
          status: "COMPLETED",
          description: note || `Receive from ${senderAccountNumber}`,
          fromUserId: senderUserId,
          toUserId: resolvedReceiverUserId,
          metadata: {
            entry: "CREDIT",
            reconciliationId,
            fromAccount: senderAccountNumber,
            toAccount: receiverAccountNumber,
          } as never,
        },
      });

      return {
        transaction: debitTx,
        reconciliationId,
        receiverAccountNumber,
      };
    });

    return res.json({
      status: "ok",
      reconciliationId: transferResult.reconciliationId,
      transaction: {
        id: transferResult.transaction.id,
        amount: Number(transferResult.transaction.amount),
        type: transferResult.transaction.type,
        description: transferResult.transaction.description ?? undefined,
        createdAt: transferResult.transaction.createdAt.toISOString(),
        toAccount: transferResult.receiverAccountNumber,
      },
    });
  } catch (err) {
    if (err instanceof Error && err.message === "SENDER_WALLET_NOT_FOUND") {
      return res.status(400).json({ error: "Sender wallet not found" });
    }
    if (err instanceof Error && err.message === "INSUFFICIENT_BALANCE") {
      return res.status(400).json({ error: "Insufficient balance" });
    }
    console.error("Failed to transfer", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.get("/transactions", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const wallets = await prisma.wallet.findMany({
      where: { userId },
      select: { id: true },
    });
    const walletIds = wallets.map((w) => w.id);

    const txns = await prisma.transaction.findMany({
      where: {
        OR: [
          { fromUserId: userId },
          { toUserId: userId },
          ...(walletIds.length ? [{ walletId: { in: walletIds } }] : []),
        ],
      },
      orderBy: { createdAt: "desc" },
      take: 200,
    });

    return res.json(
      txns.map((txn) => ({
        id: txn.id,
        amount: Number(txn.amount),
        type: txn.type,
        description: txn.description ?? undefined,
        createdAt: txn.createdAt.toISOString(),
        metadata:
          txn.metadata && typeof txn.metadata === "object"
            ? (txn.metadata as Record<string, unknown>)
            : undefined,
      })),
    );
  } catch (err) {
    console.error("Failed to list transactions", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/security/login-events", (_req, res) => {
  res.json({ score: 0.1, reasons: ["stub"], received: _req.body });
});

app.get("/security/alerts", async (_req, res) => {
  const policy = await getSecurityPolicy();
  const repo = createLoginEventRepository();
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const events = await repo.findSince(since, 100);
  const alerts = events
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
    const docs = await userRepository.findMany(200);
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
      const userRepository = createUserRepository();
      await userRepository.setStatus(req.params.id, statusNormalized as UserStatus);
      const updated = await userRepository.findValidatedById(req.params.id);
      const sanitized = sanitizeUser(updated);

      await logAuditEvent({
        actor: "admin",
        userId: req.params.id,
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
    const events = await repo.findLatest(limit);
    const normalized = events.map((evt) => ({
      id: evt.id,
      email: evt.email ?? "unknown",
      ipAddress: evt.ipAddress ?? "unknown",
      userAgent: evt.userAgent ?? "unknown",
      success: evt.success,
      anomaly: evt.anomaly,
      createdAt: evt.createdAt,
      metadata: evt.metadata ?? {},
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
    const txns = await prisma.transaction.findMany({
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    const normalized = txns.map((txn) => ({
      id: txn.id,
      amount: Number(txn.amount),
      type: txn.type,
      status: txn.status,
      description: txn.description ?? "",
      createdAt: txn.createdAt,
      fromUserId: txn.fromUserId ?? undefined,
      toUserId: txn.toUserId ?? undefined,
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
    const events = await repo.findSince(since, 100);
    const alerts = events
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
    const logs = await createAuditLogRepository().findLatest(limit);
    const normalized = logs.map((log) => ({
      id: log.id,
      actor: log.actor,
      action: log.action,
      details: log.details ?? "",
      ipAddress: log.ipAddress ?? "unknown",
      createdAt: log.createdAt,
    }));
    res.json(normalized);
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

    await prisma.securityPolicy.create({
      data: {
        id: crypto.randomUUID(),
        maxLoginAttempts: policy.maxLoginAttempts,
        lockoutMinutes: policy.lockoutMinutes,
        anomalyAlertThreshold: policy.anomalyAlertThreshold,
      },
    });

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
    const userId = userDoc?.id;

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
    const userId = userDoc?.id;

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
      userId,
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

const sleep = (ms: number) =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

const initializeDatabase = async () => {
  const maxAttempts = 8;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await prisma.$connect();
      const adminPasswordHash = await hashPassword(ADMIN_PASSWORD);
      await prisma.user.upsert({
        where: { email: ADMIN_EMAIL },
        update: {
          passwordHash: adminPasswordHash,
          role: "ADMIN",
          status: "ACTIVE",
        },
        create: {
          id: crypto.randomUUID(),
          email: ADMIN_EMAIL,
          passwordHash: adminPasswordHash,
          role: "ADMIN",
          status: "ACTIVE",
        },
      });
      console.log(`Default admin ready. email=${ADMIN_EMAIL}`);
      return;
    } catch (err) {
      console.error(
        `Database init failed (attempt ${attempt}/${maxAttempts})`,
        err,
      );
      if (attempt < maxAttempts) {
        await sleep(3000);
      }
    }
  }
  console.error("Database init failed after max retries.");
};

const start = async () => {
  try {
    registerShutdownHooks();
    app.listen(PORT, () => {
      console.log(`API listening on http://localhost:${PORT}`);
    });
    void initializeDatabase();
  } catch (err) {
    console.error("Failed to start API server", err);
    process.exit(1);
  }
};

start();

