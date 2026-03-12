import crypto from "crypto";
import path from "path";

import cors from "cors";
import dotenv from "dotenv";
import express, { type ErrorRequestHandler, type Request } from "express";
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
import { signAuthToken, verifySessionAlertToken } from "./security/jwt";
import { hashPassword, verifyPassword } from "./security/password";
import {
  getSecurityPolicy,
  getDefaultSecurityPolicy,
} from "./services/securityPolicy";
import { logAuditEvent } from "./services/audit";
import {
  sendBalanceChangeEmail,
  sendLoginOtpEmail,
  sendPasswordResetOtpEmail,
  sendRegisterOtpEmail,
  sendTransferOtpEmail,
} from "./services/email";
import {
  activateAuthSession,
  buildRecentIpNotice,
  clearActiveAuthSession,
  getAuthSecurityState,
  getLatestDifferentTrustedIp,
  isTrustedIp,
  normalizeIpAddress,
  recordSuccessfulLoginIp,
  resolveRequestIpAddress,
  setAuthSecurityState,
  type TrustedIpEntry,
} from "./services/trustedIp";
import {
  buildEncryptedTransactionCreateData,
  decryptStoredTransaction,
  generateEncryptedTransactionId,
} from "./services/transactionSecurity";
import {
  createStoredCard,
  getStoredCards,
  normalizePrimaryCard,
  setStoredCards,
  type CardType,
  type StoredCard,
} from "./services/cards";
import {
  consumeOtpChallenge,
  createEmailOtpChallenge,
  maskEmail,
  verifyEmailOtpChallenge,
} from "./services/otp";

// Support running from both repo root and apps/api folders.
dotenv.config({ path: path.resolve(process.cwd(), ".env"), override: true });
dotenv.config({
  path: path.resolve(process.cwd(), "../../.env"),
  override: true,
});

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
app.use(applySecurityHeaders);
app.use(lockoutGuard);

const PORT = process.env.PORT_API || 4000;
const AI_URL = process.env.AI_SERVICE_URL || "http://localhost:8000";
const APP_TIMEZONE = process.env.APP_TIMEZONE || "Asia/Ho_Chi_Minh";
const ADMIN_EMAIL = "ledanhdat56@gmail.com";
const ADMIN_PASSWORD = "Ledanhdat2005@";
const TRANSFER_OTP_TTL_MINUTES = Number(
  process.env.TRANSFER_OTP_TTL_MINUTES || "5",
);
const TRANSFER_OTP_MAX_ATTEMPTS = Number(
  process.env.TRANSFER_OTP_MAX_ATTEMPTS || "5",
);
const LOGIN_OTP_TTL_MINUTES = Number(process.env.LOGIN_OTP_TTL_MINUTES || "5");
const REGISTER_OTP_TTL_MINUTES = LOGIN_OTP_TTL_MINUTES;
const RESET_PASSWORD_OTP_TTL_MINUTES = Number(
  process.env.RESET_PASSWORD_OTP_TTL_MINUTES || "10",
);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || "5");
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || "";

const normalizeEmail = (email: string) => email.trim().toLowerCase();

const getRequestIp = (req: Request) => resolveRequestIpAddress(req);

const toAnomalyScore = (value: unknown) =>
  typeof value === "number" && Number.isFinite(value) ? value : 0;

type AnomalyResponse = Partial<components["schemas"]["AnomalyScore"]> &
  Record<string, unknown>;

type DepositAgentResponse = {
  recommendedAmount: number;
  reasoning: string[];
  riskLevel: string;
  nextAction: string;
  confidence: number;
};

type CopilotMessagePayload = {
  role: "user" | "assistant" | "system";
  content: string;
};

type CopilotTransactionPayload = {
  amount: number;
  type: string;
  description?: string;
  createdAt: string;
  direction: "credit" | "debit";
};

type CopilotResponsePayload = {
  reply: string;
  topic: string;
  suggestedActions: string[];
  suggestedDepositAmount?: number | null;
  riskLevel: string;
  confidence: number;
  followUpQuestion?: string | null;
};

const DEFAULT_SECURITY_POLICY = getDefaultSecurityPolicy();

const sanitizeUser = (user: UserEntity | null) => {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  void passwordHash;
  return rest;
};

const buildAuthPayload = (
  userDoc: UserEntity,
  sessionId: string,
  extra?: { notice?: string; status?: "authenticated" },
) => {
  const user: components["schemas"]["User"] = {
    id: userDoc.id,
    email: userDoc.email,
    role: userDoc.role,
  };

  return {
    status: extra?.status ?? "authenticated",
    token: signAuthToken({
      sub: user.id,
      email: user.email,
      role: user.role,
      sid: sessionId,
    }),
    user,
    notice: extra?.notice,
  };
};

const verifyRecaptchaToken = async (token: string, remoteIp?: string) => {
  if (!RECAPTCHA_SECRET_KEY) {
    throw new Error("RECAPTCHA_NOT_CONFIGURED");
  }

  const body = new URLSearchParams({
    secret: RECAPTCHA_SECRET_KEY,
    response: token,
  });
  if (remoteIp) {
    body.set("remoteip", remoteIp);
  }

  const response = await fetch(
    "https://www.google.com/recaptcha/api/siteverify",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    },
  );
  const data = (await response.json().catch(() => null)) as {
    success?: boolean;
    ["error-codes"]?: string[];
  } | null;

  return Boolean(data?.success);
};

const getRecipientName = (input: {
  fullName?: string | null;
  email: string;
}) => {
  const fullName =
    typeof input.fullName === "string" ? input.fullName.trim() : "";
  if (fullName) return fullName;
  return input.email.split("@")[0] || "User";
};

const notifyBalanceChange = (input: {
  to: string;
  recipientName: string;
  direction: "credit" | "debit";
  amount: number;
  balance: number;
  currency: string;
  transactionType: "DEPOSIT" | "TRANSFER";
  description: string;
  occurredAt: string;
  counterpartyLabel?: string;
}) => {
  void sendBalanceChangeEmail(input).catch((err) => {
    console.error("Failed to send balance change email", err);
  });
};

const persistAuthSecurityState = async (
  userRepository: ReturnType<typeof createUserRepository>,
  userDoc: UserEntity,
  nextState: ReturnType<typeof getAuthSecurityState>,
) => {
  await userRepository.updateMetadata(
    userDoc.id,
    setAuthSecurityState(userDoc.metadata, nextState),
  );
};

const issueExclusiveUserSession = async (input: {
  userRepository: ReturnType<typeof createUserRepository>;
  userDoc: UserEntity;
  authState: ReturnType<typeof getAuthSecurityState>;
  ipAddress?: string;
  userAgent?: string;
}) => {
  const nextSessionId = crypto.randomUUID();
  const previousSession = input.authState.activeSession;
  const nextAuthState = activateAuthSession(input.authState, {
    sessionId: nextSessionId,
    ipAddress: input.ipAddress,
    userAgent: input.userAgent,
  });

  await persistAuthSecurityState(
    input.userRepository,
    input.userDoc,
    nextAuthState,
  );

  return {
    sessionId: nextSessionId,
    replacedSession: previousSession,
    authState: nextAuthState,
  };
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

const SECURITY_OVERVIEW_WINDOW_DAYS = 30;
const SECURITY_VERIFICATION_MATCH_WINDOW_MS = 10 * 60 * 1000;

const buildSecurityLocationLabel = (input: {
  location?: string;
  ipAddress?: string;
}) => {
  const location =
    typeof input.location === "string" ? input.location.trim() : "";
  if (location) return location;
  const ipAddress = normalizeIpAddress(input.ipAddress);
  return ipAddress ? `IP ${ipAddress}` : "Unknown location";
};

const buildUserSecurityAlert = (
  event: LoginEventEntity,
  anomalyThreshold: number,
  trustedIp?: TrustedIpEntry,
) => {
  const reasons = buildAlertFromLoginEvent(event, anomalyThreshold).reasons;
  const location = buildSecurityLocationLabel(event);
  const userAgent = event.userAgent ?? "Unknown device";
  const riskScore = Math.round((event.anomaly ?? 0) * 100);
  const verifiedAt = trustedIp
    ? Date.parse(trustedIp.lastVerifiedAt)
    : Number.NaN;
  const isVerificationEvent =
    trustedIp &&
    Number.isFinite(verifiedAt) &&
    Math.abs(event.createdAt.getTime() - verifiedAt) <=
      SECURITY_VERIFICATION_MATCH_WINDOW_MS;

  if (!event.success) {
    return {
      id: event.id,
      title: "Blocked Sign-In Attempt",
      location,
      detail: [
        `Device: ${userAgent}.`,
        reasons.length ? `Reasons: ${reasons.join(", ")}.` : "",
        riskScore > 0 ? `Risk score: ${riskScore}%.` : "",
      ]
        .filter(Boolean)
        .join(" "),
      tone: "warn" as const,
      occurredAt: event.createdAt.toISOString(),
    };
  }

  if (isVerificationEvent && trustedIp) {
    return {
      id: event.id,
      title: "New Device Verified",
      location,
      detail: `Device: ${userAgent}. IP ${trustedIp.ipAddress} was verified and saved for future sign-ins.`,
      tone: "info" as const,
      occurredAt: event.createdAt.toISOString(),
    };
  }

  if (trustedIp) {
    return {
      id: event.id,
      title: "Session Verified",
      location,
      detail: `Device: ${userAgent}. Sign-in matched the saved IP ${trustedIp.ipAddress}.`,
      tone: "safe" as const,
      occurredAt: event.createdAt.toISOString(),
    };
  }

  return {
    id: event.id,
    title:
      (event.anomaly ?? 0) >= anomalyThreshold
        ? "Risk Review Required"
        : "Sign-In Recorded",
    location,
    detail: [
      `Device: ${userAgent}.`,
      riskScore > 0 ? `Risk score: ${riskScore}%.` : "",
      "This sign-in is not saved as a trusted device yet.",
    ]
      .filter(Boolean)
      .join(" "),
    tone:
      (event.anomaly ?? 0) >= anomalyThreshold
        ? ("warn" as const)
        : ("info" as const),
    occurredAt: event.createdAt.toISOString(),
  };
};

const serializeCard = (card: StoredCard) => ({
  id: card.id,
  type: card.type,
  bank: card.bank,
  holder: card.holder,
  number: card.maskedNumber,
  last4: card.last4,
  expiryMonth: card.expiryMonth,
  expiryYear: card.expiryYear,
  status: card.status,
  isPrimary: card.isPrimary,
  createdAt: card.createdAt,
  updatedAt: card.updatedAt,
});

const toPositiveAmount = (value: unknown) => {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
};

type ResolvedTransferContext = {
  amount: number;
  note: string;
  resolvedReceiverUserId: string;
  senderWallet: Wallet;
  senderAccountNumber: string;
  receiverAccountNumber: string;
  receiverWalletByAccount: {
    id: string;
    userId: string | null;
    metadata: unknown;
  } | null;
};

const resolveTransferContext = async (input: {
  senderUserId: string;
  toUserId?: string;
  toAccount?: string;
  amount: number;
  note?: string;
}) => {
  const toUserId =
    typeof input.toUserId === "string" ? input.toUserId.trim() : "";
  const toAccount =
    typeof input.toAccount === "string"
      ? input.toAccount.replace(/\D/g, "").slice(0, 19)
      : "";
  const note = typeof input.note === "string" ? input.note.trim() : "";

  if (!toUserId && !toAccount) {
    throw new Error("MISSING_RECIPIENT_ACCOUNT");
  }

  const senderWallet = await getOrCreateWalletByUserId(input.senderUserId);
  const senderMeta =
    senderWallet.metadata && typeof senderWallet.metadata === "object"
      ? (senderWallet.metadata as Record<string, unknown>)
      : {};
  const senderAccountNumber =
    typeof senderMeta.accountNumber === "string"
      ? senderMeta.accountNumber
      : "";

  let resolvedReceiverUserId = toUserId;
  let receiverWalletByAccount: {
    id: string;
    userId: string | null;
    metadata: unknown;
  } | null = null;

  if (toAccount) {
    receiverWalletByAccount = await findWalletByAccountNumber(toAccount);
    if (!receiverWalletByAccount?.userId) {
      throw new Error("RECIPIENT_ACCOUNT_NOT_FOUND");
    }
    resolvedReceiverUserId = receiverWalletByAccount.userId;
  }

  if (resolvedReceiverUserId === input.senderUserId) {
    throw new Error("CANNOT_TRANSFER_TO_SELF");
  }

  if (!resolvedReceiverUserId) {
    throw new Error("RECIPIENT_NOT_FOUND");
  }

  const receiver = await prisma.user.findUnique({
    where: { id: resolvedReceiverUserId },
  });
  if (!receiver) {
    throw new Error("RECIPIENT_NOT_FOUND");
  }
  if (receiver.status !== "ACTIVE") {
    throw new Error("RECIPIENT_LOCKED");
  }

  const receiverWallet =
    receiverWalletByAccount ??
    (await prisma.wallet.findFirst({
      where: { userId: resolvedReceiverUserId },
      select: { id: true, userId: true, metadata: true },
    }));
  const receiverMeta =
    receiverWallet?.metadata && typeof receiverWallet.metadata === "object"
      ? (receiverWallet.metadata as Record<string, unknown>)
      : {};
  const receiverAccountNumber =
    typeof receiverMeta.accountNumber === "string"
      ? receiverMeta.accountNumber
      : buildAccountNumber(resolvedReceiverUserId);

  if (Number(senderWallet.balance) < input.amount) {
    throw new Error("INSUFFICIENT_BALANCE");
  }

  return {
    amount: input.amount,
    note,
    resolvedReceiverUserId,
    senderWallet,
    senderAccountNumber,
    receiverAccountNumber,
    receiverWalletByAccount,
  } satisfies ResolvedTransferContext;
};

const executeTransfer = async (input: {
  senderUserId: string;
  resolvedReceiverUserId: string;
  amount: number;
  note: string;
  senderAccountNumber: string;
  receiverAccountNumber: string;
  receiverWalletByAccount: {
    id: string;
    userId: string | null;
    metadata: unknown;
  } | null;
}) => {
  return prisma.$transaction(async (tx) => {
    const senderWallet = await tx.wallet.findFirst({
      where: { userId: input.senderUserId },
    });
    if (!senderWallet) throw new Error("SENDER_WALLET_NOT_FOUND");
    if (Number(senderWallet.balance) < input.amount) {
      throw new Error("INSUFFICIENT_BALANCE");
    }

    const receiverWallet =
      (input.receiverWalletByAccount
        ? await tx.wallet.findFirst({
            where: { id: input.receiverWalletByAccount.id },
          })
        : null) ??
      (await tx.wallet.findFirst({
        where: { userId: input.resolvedReceiverUserId },
      })) ??
      (await tx.wallet.create({
        data: {
          id: crypto.randomUUID(),
          userId: input.resolvedReceiverUserId,
          balance: 0,
          currency: senderWallet.currency,
          status: "ACTIVE",
          metadata: {
            accountNumber: input.receiverAccountNumber,
          } as never,
        },
      }));

    const reconciliationId = crypto.randomUUID();

    await tx.wallet.update({
      where: { id: senderWallet.id },
      data: { balance: { decrement: input.amount } },
    });
    await tx.wallet.update({
      where: { id: receiverWallet.id },
      data: { balance: { increment: input.amount } },
    });

    const debitTxId = generateEncryptedTransactionId();
    const debitTx = decryptStoredTransaction(
      await tx.transaction.create({
        data: {
          id: debitTxId,
          ...buildEncryptedTransactionCreateData(debitTxId, {
            walletId: senderWallet.id,
            sensitive: {
              amount: input.amount,
              type: "TRANSFER",
              status: "COMPLETED",
              description:
                input.note || `Transfer to ${input.receiverAccountNumber}`,
              counterpartyWalletId: receiverWallet.id,
              fromUserId: input.senderUserId,
              toUserId: input.resolvedReceiverUserId,
              metadata: {
                entry: "DEBIT",
                reconciliationId,
                fromAccount: input.senderAccountNumber,
                toAccount: input.receiverAccountNumber,
              },
            },
          }),
        },
      }),
    );

    const creditTxId = generateEncryptedTransactionId();
    await tx.transaction.create({
      data: {
        id: creditTxId,
        ...buildEncryptedTransactionCreateData(creditTxId, {
          walletId: receiverWallet.id,
          sensitive: {
            amount: input.amount,
            type: "TRANSFER",
            status: "COMPLETED",
            description:
              input.note || `Receive from ${input.senderAccountNumber}`,
            counterpartyWalletId: senderWallet.id,
            fromUserId: input.senderUserId,
            toUserId: input.resolvedReceiverUserId,
            metadata: {
              entry: "CREDIT",
              reconciliationId,
              fromAccount: input.senderAccountNumber,
              toAccount: input.receiverAccountNumber,
            },
          },
        }),
      },
    });

    return {
      transaction: debitTx,
      reconciliationId,
      receiverAccountNumber: input.receiverAccountNumber,
      senderBalance: Number(senderWallet.balance) - input.amount,
      receiverBalance: Number(receiverWallet.balance) + input.amount,
      currency: senderWallet.currency,
    };
  });
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

  const accountNumber =
    existingAccountNumber || buildAccountNumber(wallet.userId);
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

app.post("/ai/deposit-agent", requireAuth, async (_req, res) => {
  return res.status(404).json({ error: "Feature removed" });
});

app.post("/ai/copilot-chat", requireAuth, async (_req, res) => {
  return res.status(404).json({ error: "Feature removed" });
});

app.post("/auth/register", async (req, res) => {
  type RegisterReq = components["schemas"]["RegisterRequest"];
  const recaptchaToken =
    typeof req.body?.recaptchaToken === "string"
      ? req.body.recaptchaToken.trim()
      : "";
  const parsed = registerSchema.safeParse(req.body as RegisterReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  if (!recaptchaToken) {
    return res.status(400).json({ error: "Missing reCAPTCHA token" });
  }

  const userRepository = createUserRepository();
  const email = normalizeEmail(parsed.data.email);

  try {
    const recaptchaVerified = await verifyRecaptchaToken(
      recaptchaToken,
      getRequestIp(req),
    );
    if (!recaptchaVerified) {
      return res.status(403).json({ error: "reCAPTCHA verification failed" });
    }

    const existingUser = await userRepository.findByEmail(email);
    if (existingUser && existingUser.status !== "PENDING") {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await hashPassword(parsed.data.password);
    const profilePayload = {
      fullName: parsed.data.fullName?.trim(),
      phone: parsed.data.phone?.trim(),
      address: parsed.data.address?.trim(),
      dob: parsed.data.dob?.trim(),
      metadata: parsed.data.userName
        ? { userName: parsed.data.userName.trim() }
        : undefined,
    };
    const pendingUser = existingUser
      ? await (async () => {
          await userRepository.updatePassword(existingUser.id, passwordHash);
          await userRepository.setStatus(existingUser.id, "PENDING");
          return userRepository.updateProfile(existingUser.id, profilePayload);
        })()
      : await userRepository.createUser({
          email,
          passwordHash,
          role: "USER",
          status: "PENDING",
          ...profilePayload,
        });

    const otpChallenge = await createEmailOtpChallenge({
      userId: pendingUser.id,
      purpose: "REGISTER",
      destination: email,
      ttlMinutes: REGISTER_OTP_TTL_MINUTES,
      maxAttempts: OTP_MAX_ATTEMPTS,
    });

    await sendRegisterOtpEmail({
      to: email,
      recipientName: pendingUser.fullName || email.split("@")[0] || "User",
      otpCode: otpChallenge.otpCode,
      expiresInMinutes: REGISTER_OTP_TTL_MINUTES,
    });

    await logAuditEvent({
      actor: email,
      action: "REGISTER_OTP_SENT",
      userId: pendingUser.id,
      ipAddress: getRequestIp(req),
    });

    return res.status(201).json({
      status: "otp_required",
      challengeId: otpChallenge.challengeId,
      destination: email,
      expiresAt: otpChallenge.expiresAt.toISOString(),
      retryAfterSeconds: otpChallenge.retryAfterSeconds,
    });
  } catch (err) {
    const errorCode =
      typeof err === "object" && err !== null && "code" in err
        ? (err as { code?: string }).code
        : undefined;
    if (errorCode === "P2002") {
      return res.status(409).json({ error: "Email already registered" });
    }
    if (err instanceof Error && err.message === "OTP_COOLDOWN_ACTIVE") {
      return res.status(429).json({
        error: "OTP recently sent. Please wait before requesting another code.",
        retryAfterSeconds:
          "retryAfterSeconds" in err
            ? (err as { retryAfterSeconds: number }).retryAfterSeconds
            : 60,
      });
    }
    if (err instanceof Error && err.message === "RECAPTCHA_NOT_CONFIGURED") {
      return res.status(500).json({ error: "reCAPTCHA is not configured" });
    }
    console.error("Failed to register user", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/auth/register/verify", async (req, res) => {
  const body = req.body as {
    challengeId?: unknown;
    otp?: unknown;
  };
  const challengeId =
    typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.replace(/\D/g, "") : "";
  if (!challengeId || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: "Invalid registration OTP payload" });
  }

  try {
    const challenge = await prisma.otpChallenge.findUnique({
      where: { id: challengeId },
    });
    if (
      !challenge ||
      challenge.purpose !== "REGISTER" ||
      challenge.channel !== "EMAIL"
    ) {
      return res.status(404).json({ error: "OTP challenge not found" });
    }

    await verifyEmailOtpChallenge({
      userId: challenge.userId,
      purpose: "REGISTER",
      challengeId,
      otp,
    });

    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(challenge.userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    await userRepository.setStatus(userDoc.id, "ACTIVE");
    await userRepository.touchLastLogin(userDoc.id);
    const currentIp = getRequestIp(req);
    const currentUserAgent =
      typeof req.headers["user-agent"] === "string"
        ? req.headers["user-agent"]
        : undefined;
    const nextAuthState = recordSuccessfulLoginIp(
      getAuthSecurityState(userDoc.metadata),
      currentIp,
      { trustIp: true },
    );
    const sessionResult = await issueExclusiveUserSession({
      userRepository,
      userDoc,
      authState: nextAuthState,
      ipAddress: currentIp,
      userAgent: currentUserAgent,
    });
    await consumeOtpChallenge(challengeId);
    await getOrCreateWalletByUserId(userDoc.id);
    await logAuditEvent({
      actor: userDoc.email,
      action: "REGISTER",
      userId: userDoc.id,
      ipAddress: getRequestIp(req),
    });

    if (sessionResult.replacedSession) {
      await logAuditEvent({
        actor: userDoc.email,
        action: "SESSION_REPLACED",
        userId: userDoc.id,
        details: {
          previousSessionId: sessionResult.replacedSession.sessionId,
          previousIp: sessionResult.replacedSession.ipAddress,
          previousUserAgent: sessionResult.replacedSession.userAgent,
          newIp: currentIp,
          newUserAgent: currentUserAgent,
        },
        ipAddress: currentIp,
      });
    }

    return res.json(
      buildAuthPayload(userDoc, sessionResult.sessionId, {
        notice: currentIp
          ? `IP ${currentIp} is trusted for future sign-ins.`
          : undefined,
      }),
    );
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_CHALLENGE_NOT_FOUND") {
      return res.status(404).json({ error: "OTP challenge not found" });
    }
    if (err instanceof Error && err.message === "OTP_CHALLENGE_ALREADY_USED") {
      return res.status(400).json({ error: "OTP challenge already used" });
    }
    if (err instanceof Error && err.message === "OTP_EXPIRED") {
      return res.status(400).json({ error: "OTP has expired" });
    }
    if (err instanceof Error && err.message === "OTP_TOO_MANY_ATTEMPTS") {
      return res.status(429).json({ error: "Too many invalid OTP attempts" });
    }
    if (err instanceof Error && err.message === "OTP_INCORRECT") {
      return res.status(400).json({ error: "Incorrect OTP" });
    }
    console.error("Failed to verify register OTP", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/auth/login", loginRateLimiter, async (req, res) => {
  type LoginReq = components["schemas"]["LoginRequest"];
  const recaptchaToken =
    typeof req.body?.recaptchaToken === "string"
      ? req.body.recaptchaToken.trim()
      : "";
  const parsed = loginSchema.safeParse(req.body as LoginReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  if (!recaptchaToken) {
    return res.status(400).json({ error: "Missing reCAPTCHA token" });
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
    const recaptchaVerified = await verifyRecaptchaToken(
      recaptchaToken,
      getRequestIp(req),
    );
    if (!recaptchaVerified) {
      return res.status(403).json({ error: "reCAPTCHA verification failed" });
    }

    const loginEventPayload = {
      ipAddress: getRequestIp(req),
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
        ipAddress: getRequestIp(req),
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
        ipAddress: getRequestIp(req),
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
          getRequestIp(req),
        );
      }
      await loginEventRepository.createLoginEvent({
        userId: userDoc?.id,
        email,
        ipAddress: getRequestIp(req),
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
      ipAddress: getRequestIp(req),
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
        ipAddress: getRequestIp(req),
      });
    }

    if (!isPasswordValid || !userDoc) {
      await logAuditEvent({
        actor: email,
        action: "LOGIN_FAILED",
        details: `anomaly=${score}`,
        ipAddress: getRequestIp(req),
      });

      const failedAttempts = failedBefore + 1;
      if (userDoc?.id && failedAttempts >= policy.maxLoginAttempts) {
        await lockUserAccount(
          userDoc.id,
          email,
          "Exceeded failed attempts",
          getRequestIp(req),
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
        ipAddress: getRequestIp(req),
      });
      return res
        .status(423)
        .json({ error: "Account is not active", anomaly: aiResult });
    }

    const currentIp = getRequestIp(req);
    const currentUserAgent =
      typeof req.headers["user-agent"] === "string"
        ? req.headers["user-agent"]
        : undefined;
    const authSecurityState = getAuthSecurityState(userDoc.metadata);
    if (isTrustedIp(authSecurityState, currentIp)) {
      const notice = buildRecentIpNotice(
        authSecurityState,
        currentIp,
        APP_TIMEZONE,
      );
      const nextAuthState = recordSuccessfulLoginIp(
        authSecurityState,
        currentIp,
      );

      await userRepository.touchLastLogin(userDoc.id);
      const sessionResult = await issueExclusiveUserSession({
        userRepository,
        userDoc,
        authState: nextAuthState,
        ipAddress: currentIp,
        userAgent: currentUserAgent,
      });

      await logAuditEvent({
        actor: email,
        action: "LOGIN_TRUSTED_IP",
        userId: userDoc.id,
        details: {
          anomaly: score,
          trustedIp: currentIp,
        },
        ipAddress: getRequestIp(req),
      });

      if (sessionResult.replacedSession) {
        await logAuditEvent({
          actor: email,
          action: "SESSION_REPLACED",
          userId: userDoc.id,
          details: {
            previousSessionId: sessionResult.replacedSession.sessionId,
            previousIp: sessionResult.replacedSession.ipAddress,
            previousUserAgent: sessionResult.replacedSession.userAgent,
            newIp: currentIp,
            newUserAgent: currentUserAgent,
          },
          ipAddress: currentIp,
        });
      }

      return res.json({
        ...buildAuthPayload(userDoc, sessionResult.sessionId, { notice }),
        anomaly: aiResult,
      });
    }

    const previousTrustedIp = getLatestDifferentTrustedIp(
      authSecurityState,
      currentIp,
    );
    const otpNotice = previousTrustedIp
      ? `New IP detected. Verification code sent. Most recent trusted IP: ${previousTrustedIp.ipAddress}.`
      : "New IP detected. Verification code sent to your email.";

    const otpChallenge = await createEmailOtpChallenge({
      userId: userDoc.id,
      purpose: "LOGIN",
      destination: userDoc.email,
      ttlMinutes: LOGIN_OTP_TTL_MINUTES,
      maxAttempts: OTP_MAX_ATTEMPTS,
      metadata: {
        anomalyScore: score,
        aiReasons: Array.isArray(aiResult?.reasons) ? aiResult.reasons : [],
        currentIp,
        previousTrustedIp: previousTrustedIp?.ipAddress,
      },
    });
    await sendLoginOtpEmail({
      to: userDoc.email,
      recipientName: userDoc.fullName || userDoc.email.split("@")[0] || "User",
      otpCode: otpChallenge.otpCode,
      expiresInMinutes: LOGIN_OTP_TTL_MINUTES,
    });

    await logAuditEvent({
      actor: email,
      action: "LOGIN_OTP_SENT",
      userId: userDoc.id,
      details: {
        anomaly: score,
        challengeId: otpChallenge.challengeId,
        currentIp,
        previousTrustedIp: previousTrustedIp?.ipAddress,
      },
      ipAddress: getRequestIp(req),
    });

    return res.json({
      status: "otp_required",
      challengeId: otpChallenge.challengeId,
      destination: maskEmail(userDoc.email),
      expiresAt: otpChallenge.expiresAt.toISOString(),
      retryAfterSeconds: otpChallenge.retryAfterSeconds,
      notice: otpNotice,
      anomaly: aiResult,
    });
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_COOLDOWN_ACTIVE") {
      return res.status(429).json({
        error: "OTP recently sent. Please wait before requesting another code.",
        retryAfterSeconds:
          "retryAfterSeconds" in err
            ? (err as { retryAfterSeconds: number }).retryAfterSeconds
            : 60,
      });
    }
    if (err instanceof Error && err.message === "RECAPTCHA_NOT_CONFIGURED") {
      return res.status(500).json({ error: "reCAPTCHA is not configured" });
    }
    console.error("Failed to login user", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/auth/login/verify", async (req, res) => {
  const body = req.body as {
    challengeId?: unknown;
    otp?: unknown;
  };
  const challengeId =
    typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.replace(/\D/g, "") : "";
  if (!challengeId || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: "Invalid login OTP payload" });
  }

  try {
    const challenge = await prisma.otpChallenge.findUnique({
      where: { id: challengeId },
    });
    if (
      !challenge ||
      challenge.purpose !== "LOGIN" ||
      challenge.channel !== "EMAIL"
    ) {
      return res.status(404).json({ error: "OTP challenge not found" });
    }

    await verifyEmailOtpChallenge({
      userId: challenge.userId,
      purpose: "LOGIN",
      challengeId,
      otp,
    });

    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(challenge.userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });
    if (userDoc.status !== "ACTIVE") {
      return res.status(423).json({ error: "Account is not active" });
    }

    await consumeOtpChallenge(challengeId);
    await userRepository.touchLastLogin(userDoc.id);

    const metadata =
      challenge.metadata && typeof challenge.metadata === "object"
        ? (challenge.metadata as Record<string, unknown>)
        : {};
    const anomalyScore =
      typeof metadata.anomalyScore === "number" ? metadata.anomalyScore : 0;
    const verifiedIp = normalizeIpAddress(
      typeof metadata.currentIp === "string"
        ? metadata.currentIp
        : getRequestIp(req),
    );
    const previousTrustedIp = normalizeIpAddress(
      typeof metadata.previousTrustedIp === "string"
        ? metadata.previousTrustedIp
        : undefined,
    );
    const nextAuthState = recordSuccessfulLoginIp(
      getAuthSecurityState(userDoc.metadata),
      verifiedIp,
      { trustIp: true },
    );
    const currentUserAgent =
      typeof req.headers["user-agent"] === "string"
        ? req.headers["user-agent"]
        : undefined;
    const sessionResult = await issueExclusiveUserSession({
      userRepository,
      userDoc,
      authState: nextAuthState,
      ipAddress: verifiedIp,
      userAgent: currentUserAgent,
    });

    const notice = verifiedIp
      ? previousTrustedIp && previousTrustedIp !== verifiedIp
        ? `IP ${verifiedIp} is now trusted. Previous trusted IP: ${previousTrustedIp}.`
        : `IP ${verifiedIp} is now trusted for future sign-ins.`
      : undefined;

    await logAuditEvent({
      actor: userDoc.email,
      action: "LOGIN",
      userId: userDoc.id,
      details: {
        anomaly: anomalyScore,
        trustedIp: verifiedIp,
      },
      ipAddress: getRequestIp(req),
    });

    if (sessionResult.replacedSession) {
      await logAuditEvent({
        actor: userDoc.email,
        action: "SESSION_REPLACED",
        userId: userDoc.id,
        details: {
          previousSessionId: sessionResult.replacedSession.sessionId,
          previousIp: sessionResult.replacedSession.ipAddress,
          previousUserAgent: sessionResult.replacedSession.userAgent,
          newIp: verifiedIp,
          newUserAgent: currentUserAgent,
        },
        ipAddress: verifiedIp,
      });
    }

    return res.json(
      buildAuthPayload(userDoc, sessionResult.sessionId, { notice }),
    );
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_CHALLENGE_NOT_FOUND") {
      return res.status(404).json({ error: "OTP challenge not found" });
    }
    if (err instanceof Error && err.message === "OTP_CHALLENGE_ALREADY_USED") {
      return res.status(400).json({ error: "OTP challenge already used" });
    }
    if (err instanceof Error && err.message === "OTP_EXPIRED") {
      return res.status(400).json({ error: "OTP has expired" });
    }
    if (err instanceof Error && err.message === "OTP_TOO_MANY_ATTEMPTS") {
      return res.status(429).json({ error: "Too many invalid OTP attempts" });
    }
    if (err instanceof Error && err.message === "OTP_INCORRECT") {
      return res.status(400).json({ error: "Incorrect OTP" });
    }
    console.error("Failed to login user", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/auth/password/otp/send", async (req, res) => {
  const email =
    typeof req.body?.email === "string" ? normalizeEmail(req.body.email) : "";
  const recaptchaToken =
    typeof req.body?.recaptchaToken === "string"
      ? req.body.recaptchaToken.trim()
      : "";
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }
  if (!recaptchaToken) {
    return res.status(400).json({ error: "Missing reCAPTCHA token" });
  }

  try {
    const recaptchaVerified = await verifyRecaptchaToken(
      recaptchaToken,
      getRequestIp(req),
    );
    if (!recaptchaVerified) {
      return res.status(403).json({ error: "reCAPTCHA verification failed" });
    }

    const userRepository = createUserRepository();
    const userDoc = await userRepository.findByEmail(email);
    if (!userDoc) {
      return res.status(404).json({ error: "Email not found" });
    }
    if (userDoc.status !== "ACTIVE") {
      return res.status(423).json({ error: "Account is not active" });
    }

    const otpChallenge = await createEmailOtpChallenge({
      userId: userDoc.id,
      purpose: "RESET_PASSWORD",
      destination: userDoc.email,
      ttlMinutes: RESET_PASSWORD_OTP_TTL_MINUTES,
      maxAttempts: OTP_MAX_ATTEMPTS,
    });

    await sendPasswordResetOtpEmail({
      to: userDoc.email,
      recipientName: userDoc.fullName || userDoc.email.split("@")[0] || "User",
      otpCode: otpChallenge.otpCode,
      expiresInMinutes: RESET_PASSWORD_OTP_TTL_MINUTES,
    });

    await logAuditEvent({
      actor: userDoc.email,
      action: "RESET_PASSWORD_OTP_SENT",
      userId: userDoc.id,
      ipAddress: getRequestIp(req),
    });

    return res.json({
      status: "ok",
      challengeId: otpChallenge.challengeId,
      destination: maskEmail(userDoc.email),
      expiresAt: otpChallenge.expiresAt.toISOString(),
      retryAfterSeconds: otpChallenge.retryAfterSeconds,
    });
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_COOLDOWN_ACTIVE") {
      return res.status(429).json({
        error: "OTP recently sent. Please wait before requesting another code.",
        retryAfterSeconds:
          "retryAfterSeconds" in err
            ? (err as { retryAfterSeconds: number }).retryAfterSeconds
            : 60,
      });
    }
    if (err instanceof Error && err.message === "RECAPTCHA_NOT_CONFIGURED") {
      return res.status(500).json({ error: "reCAPTCHA is not configured" });
    }
    console.error("Failed to send password reset OTP", err);
    return res.status(500).json({ error: "Failed to send password reset OTP" });
  }
});

app.post("/auth/password/reset", async (req, res) => {
  const body = req.body as {
    email?: unknown;
    challengeId?: unknown;
    otp?: unknown;
    newPassword?: unknown;
  };
  const email =
    typeof body.email === "string" ? normalizeEmail(body.email) : "";
  const challengeId =
    typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.replace(/\D/g, "") : "";
  const newPassword =
    typeof body.newPassword === "string" ? body.newPassword.trim() : "";

  if (
    !email ||
    !challengeId ||
    !/^\d{6}$/.test(otp) ||
    newPassword.length < 8
  ) {
    return res.status(400).json({ error: "Invalid password reset payload" });
  }

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findByEmail(email);
    if (!userDoc) return res.status(404).json({ error: "Email not found" });

    await verifyEmailOtpChallenge({
      userId: userDoc.id,
      purpose: "RESET_PASSWORD",
      challengeId,
      otp,
    });

    const passwordHash = await hashPassword(newPassword);
    await userRepository.updatePassword(userDoc.id, passwordHash);
    await consumeOtpChallenge(challengeId);

    await logAuditEvent({
      actor: userDoc.email,
      userId: userDoc.id,
      action: "RESET_PASSWORD",
      ipAddress: getRequestIp(req),
    });

    return res.status(204).send();
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_CHALLENGE_NOT_FOUND") {
      return res.status(404).json({ error: "OTP challenge not found" });
    }
    if (err instanceof Error && err.message === "OTP_CHALLENGE_ALREADY_USED") {
      return res.status(400).json({ error: "OTP challenge already used" });
    }
    if (err instanceof Error && err.message === "OTP_EXPIRED") {
      return res.status(400).json({ error: "OTP has expired" });
    }
    if (err instanceof Error && err.message === "OTP_TOO_MANY_ATTEMPTS") {
      return res.status(429).json({ error: "Too many invalid OTP attempts" });
    }
    if (err instanceof Error && err.message === "OTP_INCORRECT") {
      return res.status(400).json({ error: "Incorrect OTP" });
    }
    console.error("Failed to reset password", err);
    return res.status(500).json({ error: "Failed to reset password" });
  }
});

app.post("/auth/logout", (_req, res) => {
  res.status(204).send();
});

app.post("/auth/session-alert/respond", async (req, res) => {
  const body = req.body as {
    alertToken?: unknown;
    action?: unknown;
  };
  const alertToken =
    typeof body.alertToken === "string" ? body.alertToken.trim() : "";
  const action =
    body.action === "confirm" || body.action === "secure_account"
      ? body.action
      : "";

  if (!alertToken || !action) {
    return res.status(400).json({ error: "Invalid session alert payload" });
  }

  try {
    const payload = verifySessionAlertToken(alertToken);
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(payload.sub);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    const authSecurityState = getAuthSecurityState(userDoc.metadata);
    const activeSession = authSecurityState.activeSession;
    const sessionStillActive = activeSession?.sessionId === payload.activeSid;

    if (action === "confirm") {
      await logAuditEvent({
        actor: userDoc.email,
        action: "SESSION_REPLACEMENT_CONFIRMED",
        userId: userDoc.id,
        details: {
          revokedSessionId: payload.revokedSid,
          activeSessionId: payload.activeSid,
          activeIp: payload.activeSessionIp,
          activeUserAgent: payload.activeSessionUserAgent,
        },
      });

      return res.json({
        status: "acknowledged",
        message: "Security notice dismissed.",
        active: sessionStillActive,
      });
    }

    if (sessionStillActive) {
      const nextAuthState = clearActiveAuthSession(authSecurityState);
      await persistAuthSecurityState(userRepository, userDoc, nextAuthState);
    }

    let challengeId: string | undefined;
    let expiresAt: string | undefined;
    let retryAfterSeconds = 0;

    try {
      const otpChallenge = await createEmailOtpChallenge({
        userId: userDoc.id,
        purpose: "RESET_PASSWORD",
        destination: userDoc.email,
        ttlMinutes: RESET_PASSWORD_OTP_TTL_MINUTES,
        maxAttempts: OTP_MAX_ATTEMPTS,
      });

      await sendPasswordResetOtpEmail({
        to: userDoc.email,
        recipientName:
          userDoc.fullName || userDoc.email.split("@")[0] || "User",
        otpCode: otpChallenge.otpCode,
        expiresInMinutes: RESET_PASSWORD_OTP_TTL_MINUTES,
      });

      challengeId = otpChallenge.challengeId;
      expiresAt = otpChallenge.expiresAt.toISOString();
      retryAfterSeconds = otpChallenge.retryAfterSeconds;
    } catch (err) {
      if (err instanceof Error && err.message === "OTP_COOLDOWN_ACTIVE") {
        retryAfterSeconds =
          "retryAfterSeconds" in err
            ? (err as { retryAfterSeconds: number }).retryAfterSeconds
            : 60;
      } else {
        throw err;
      }
    }

    await logAuditEvent({
      actor: userDoc.email,
      action: "ACCOUNT_SECURED_AFTER_SESSION_REPLACEMENT",
      userId: userDoc.id,
      details: {
        revokedSessionId: payload.activeSid,
        reportedBySessionId: payload.revokedSid,
        activeIp: payload.activeSessionIp,
        activeUserAgent: payload.activeSessionUserAgent,
      },
      ipAddress: payload.activeSessionIp,
    });

    return res.json({
      status: "secured",
      message:
        "The newer device has been signed out. Complete the password reset to secure your account.",
      email: userDoc.email,
      destination: maskEmail(userDoc.email),
      challengeId,
      expiresAt,
      retryAfterSeconds,
    });
  } catch (err) {
    if (err instanceof Error && err.message.includes("jwt")) {
      return res
        .status(400)
        .json({ error: "Session alert is invalid or expired" });
    }
    console.error("Failed to respond to session alert", err);
    return res.status(500).json({ error: "Internal error" });
  }
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
    ipAddress: getRequestIp(req),
  });

  return res.status(204).send();
});

app.get("/auth/me", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    const metadata =
      userDoc.metadata && typeof userDoc.metadata === "object"
        ? (userDoc.metadata as Record<string, unknown>)
        : {};

    return res.json({
      id: userDoc.id,
      email: userDoc.email,
      role: userDoc.role,
      fullName: userDoc.fullName ?? "",
      phone: typeof userDoc.phone === "string" ? userDoc.phone : "",
      address: typeof userDoc.address === "string" ? userDoc.address : "",
      dob: typeof userDoc.dob === "string" ? userDoc.dob : "",
      avatar: typeof metadata.avatar === "string" ? metadata.avatar : undefined,
      metadata,
    });
  } catch (err) {
    console.error("Failed to get profile", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.patch("/auth/me", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    fullName?: unknown;
    phone?: unknown;
    address?: unknown;
    dob?: unknown;
    metadata?: unknown;
  };

  const fullName =
    typeof body.fullName === "string" ? body.fullName.trim().slice(0, 120) : "";
  const phone = typeof body.phone === "string" ? body.phone.trim() : "";
  const address = typeof body.address === "string" ? body.address.trim() : "";
  const dob = typeof body.dob === "string" ? body.dob.trim() : "";
  const metadata =
    body.metadata && typeof body.metadata === "object"
      ? (body.metadata as Record<string, unknown>)
      : {};
  const avatar =
    typeof metadata.avatar === "string" &&
    metadata.avatar.length > 0 &&
    metadata.avatar.length <= 2_000_000
      ? metadata.avatar
      : undefined;
  const safeMetadata = {
    ...metadata,
    ...(avatar ? { avatar } : {}),
  };

  try {
    const userRepository = createUserRepository();
    const updated = await userRepository.updateProfile(userId, {
      fullName: fullName || undefined,
      phone: phone || undefined,
      address: address || undefined,
      dob: dob || undefined,
      metadata: safeMetadata,
    });

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action: "PROFILE_UPDATED",
      details: { fullName: Boolean(fullName), phone: Boolean(phone) },
      ipAddress: getRequestIp(req),
    });

    return res.json({
      id: updated.id,
      email: updated.email,
      role: updated.role,
      fullName: updated.fullName ?? "",
      phone: typeof updated.phone === "string" ? updated.phone : "",
      address: typeof updated.address === "string" ? updated.address : "",
      dob: typeof updated.dob === "string" ? updated.dob : "",
      avatar:
        updated.metadata &&
        typeof updated.metadata === "object" &&
        typeof (updated.metadata as Record<string, unknown>).avatar === "string"
          ? ((updated.metadata as Record<string, unknown>).avatar as string)
          : undefined,
      metadata:
        updated.metadata && typeof updated.metadata === "object"
          ? (updated.metadata as Record<string, unknown>)
          : {},
    });
  } catch (err) {
    console.error("Failed to update profile", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.get("/cards", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    return res.json({
      cards: getStoredCards(userDoc.metadata).map(serializeCard),
    });
  } catch (err) {
    console.error("Failed to list cards", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/cards", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    type?: unknown;
    bank?: unknown;
    number?: unknown;
    holder?: unknown;
    expiryMonth?: unknown;
    expiryYear?: unknown;
  };
  const type =
    body.type === "Mastercard" ||
    body.type === "Visa" ||
    body.type === "Payoneer" ||
    body.type === "Skrill"
      ? (body.type as CardType)
      : undefined;
  const bank = typeof body.bank === "string" ? body.bank.trim() : "";
  const holder = typeof body.holder === "string" ? body.holder.trim() : "";
  const number =
    typeof body.number === "string" ? body.number.replace(/\D/g, "") : "";
  const expiryMonth =
    typeof body.expiryMonth === "string" ? body.expiryMonth.trim() : "";
  const expiryYear =
    typeof body.expiryYear === "string" ? body.expiryYear.trim() : "";

  if (
    !type ||
    !bank ||
    !holder ||
    !/^\d{12,19}$/.test(number) ||
    !/^(0[1-9]|1[0-2])$/.test(expiryMonth) ||
    !/^\d{2,4}$/.test(expiryYear)
  ) {
    return res.status(400).json({ error: "Invalid card payload" });
  }

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    const cards = getStoredCards(userDoc.metadata);
    if (cards.length >= 8) {
      return res.status(400).json({ error: "Card limit reached" });
    }

    const nextCards = normalizePrimaryCard([
      createStoredCard({
        id: crypto.randomUUID(),
        type,
        bank,
        holder,
        rawCardNumber: number,
        expiryMonth,
        expiryYear: expiryYear.length === 2 ? `20${expiryYear}` : expiryYear,
        isPrimary: cards.length === 0,
      }),
      ...cards.map((card) => ({
        ...card,
        isPrimary: cards.length === 0 ? false : card.isPrimary,
      })),
    ]);

    await userRepository.updateMetadata(
      userId,
      setStoredCards(userDoc.metadata, nextCards),
    );

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action: "CARD_ADDED",
      details: {
        type,
        bank,
        last4: number.slice(-4),
      },
      ipAddress: getRequestIp(req),
    });

    return res.status(201).json({
      cards: nextCards.map(serializeCard),
    });
  } catch (err) {
    console.error("Failed to add card", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.patch("/cards/:id", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const action =
    req.body?.action === "set_primary" ||
    req.body?.action === "freeze" ||
    req.body?.action === "unfreeze"
      ? (req.body.action as "set_primary" | "freeze" | "unfreeze")
      : null;
  if (!action) {
    return res.status(400).json({ error: "Invalid card action" });
  }

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    const cards = getStoredCards(userDoc.metadata);
    const target = cards.find((card) => card.id === req.params.id);
    if (!target) return res.status(404).json({ error: "Card not found" });

    const nextCards = normalizePrimaryCard(
      cards.map((card) => {
        if (card.id !== req.params.id) {
          return action === "set_primary"
            ? { ...card, isPrimary: false }
            : card;
        }

        return {
          ...card,
          isPrimary: action === "set_primary" ? true : card.isPrimary,
          status:
            action === "freeze"
              ? "FROZEN"
              : action === "unfreeze"
                ? "ACTIVE"
                : card.status,
          updatedAt: new Date().toISOString(),
        };
      }),
    );

    await userRepository.updateMetadata(
      userId,
      setStoredCards(userDoc.metadata, nextCards),
    );

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action:
        action === "set_primary"
          ? "CARD_PRIMARY_UPDATED"
          : action === "freeze"
            ? "CARD_FROZEN"
            : "CARD_UNFROZEN",
      details: {
        cardId: target.id,
        type: target.type,
        last4: target.last4,
      },
      ipAddress: getRequestIp(req),
    });

    return res.json({
      cards: nextCards.map(serializeCard),
    });
  } catch (err) {
    console.error("Failed to update card", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.delete("/cards/:id", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    const cards = getStoredCards(userDoc.metadata);
    const target = cards.find((card) => card.id === req.params.id);
    if (!target) return res.status(404).json({ error: "Card not found" });

    const nextCards = normalizePrimaryCard(
      cards
        .filter((card) => card.id !== req.params.id)
        .map((card) => ({
          ...card,
          updatedAt: card.updatedAt,
        })),
    );

    await userRepository.updateMetadata(
      userId,
      setStoredCards(userDoc.metadata, nextCards),
    );

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action: "CARD_REMOVED",
      details: {
        cardId: target.id,
        type: target.type,
        last4: target.last4,
      },
      ipAddress: getRequestIp(req),
    });

    return res.status(204).send();
  } catch (err) {
    console.error("Failed to delete card", err);
    return res.status(500).json({ error: "Internal error" });
  }
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
      qrPayload:
        typeof metadata.qrPayload === "string" ? metadata.qrPayload : "",
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
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

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

      const transactionId = generateEncryptedTransactionId();
      await tx.transaction.create({
        data: {
          id: transactionId,
          ...buildEncryptedTransactionCreateData(transactionId, {
            walletId: updated.id,
            sensitive: {
              amount,
              type: "DEPOSIT",
              status: "COMPLETED",
              description: "Wallet deposit",
              fromUserId: userId,
              toUserId: userId,
            },
          }),
        },
      });

      return updated;
    });

    notifyBalanceChange({
      to: userDoc.email,
      recipientName: getRecipientName(userDoc),
      direction: "credit",
      amount,
      balance: Number(updatedWallet.balance),
      currency: updatedWallet.currency,
      transactionType: "DEPOSIT",
      description: "Wallet deposit",
      occurredAt: new Date().toISOString(),
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

app.post("/transfer/otp/send", requireAuth, async (req, res) => {
  const senderUserId = req.user?.sub;
  if (!senderUserId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    toUserId?: string;
    toAccount?: string;
    amount?: unknown;
    note?: string;
  };
  const amount = toPositiveAmount(body.amount);
  if (!amount) return res.status(400).json({ error: "Invalid amount" });

  try {
    const context = await resolveTransferContext({
      senderUserId,
      toUserId: body.toUserId,
      toAccount: body.toAccount,
      amount,
      note: body.note,
    });
    const userRepository = createUserRepository();
    const user = await userRepository.findValidatedById(senderUserId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const otpChallenge = await createEmailOtpChallenge({
      userId: senderUserId,
      purpose: "TRANSFER",
      destination: user.email,
      ttlMinutes: TRANSFER_OTP_TTL_MINUTES,
      maxAttempts: TRANSFER_OTP_MAX_ATTEMPTS,
      metadata: {
        toUserId: context.resolvedReceiverUserId,
        toAccount: context.receiverAccountNumber,
        amount: context.amount,
        note: context.note,
      },
    });

    await sendTransferOtpEmail({
      to: user.email,
      recipientName: user.fullName || user.email.split("@")[0] || "User",
      otpCode: otpChallenge.otpCode,
      expiresInMinutes: TRANSFER_OTP_TTL_MINUTES,
      amount: context.amount,
      toAccount: context.receiverAccountNumber,
    });

    await logAuditEvent({
      actor: req.user?.email,
      userId: senderUserId,
      action: "TRANSFER_OTP_SENT",
      details: {
        challengeId: otpChallenge.challengeId,
        amount: context.amount,
        toAccount: context.receiverAccountNumber,
      },
      ipAddress: getRequestIp(req),
    });

    return res.json({
      status: "ok",
      challengeId: otpChallenge.challengeId,
      expiresAt: otpChallenge.expiresAt.toISOString(),
      destination: maskEmail(user.email),
      retryAfterSeconds: otpChallenge.retryAfterSeconds,
    });
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_COOLDOWN_ACTIVE") {
      return res.status(429).json({
        error: "OTP recently sent. Please wait before requesting another code.",
        retryAfterSeconds:
          "retryAfterSeconds" in err
            ? (err as { retryAfterSeconds: number }).retryAfterSeconds
            : 60,
      });
    }
    if (err instanceof Error) {
      if (err.message === "MISSING_RECIPIENT_ACCOUNT") {
        return res.status(400).json({ error: "Missing recipient account" });
      }
      if (err.message === "RECIPIENT_ACCOUNT_NOT_FOUND") {
        return res.status(404).json({ error: "Recipient account not found" });
      }
      if (err.message === "RECIPIENT_NOT_FOUND") {
        return res.status(404).json({ error: "Recipient not found" });
      }
      if (err.message === "CANNOT_TRANSFER_TO_SELF") {
        return res.status(400).json({ error: "Cannot transfer to self" });
      }
      if (err.message === "RECIPIENT_LOCKED") {
        return res.status(423).json({ error: "Recipient account is locked" });
      }
      if (err.message === "INSUFFICIENT_BALANCE") {
        return res.status(400).json({ error: "Insufficient balance" });
      }
    }
    console.error("Failed to send transfer OTP", err);
    return res.status(500).json({ error: "Failed to send transfer OTP" });
  }
});

app.post("/transfer/confirm", requireAuth, async (req, res) => {
  const senderUserId = req.user?.sub;
  if (!senderUserId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    challengeId?: unknown;
    otp?: unknown;
  };
  const challengeId =
    typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.replace(/\D/g, "") : "";
  if (!challengeId || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: "Invalid OTP confirmation payload" });
  }

  try {
    const userRepository = createUserRepository();
    const senderUser = await userRepository.findValidatedById(senderUserId);
    if (!senderUser) return res.status(404).json({ error: "User not found" });

    const { challenge, metadata } = await verifyEmailOtpChallenge({
      userId: senderUserId,
      purpose: "TRANSFER",
      challengeId,
      otp,
    });

    const amount = toPositiveAmount(metadata.amount);
    const toAccount =
      typeof metadata.toAccount === "string" ? metadata.toAccount : "";
    const toUserId =
      typeof metadata.toUserId === "string" ? metadata.toUserId : "";
    const note = typeof metadata.note === "string" ? metadata.note : "";
    if (!amount || (!toAccount && !toUserId)) {
      return res
        .status(400)
        .json({ error: "Stored OTP transfer payload is invalid" });
    }

    const context = await resolveTransferContext({
      senderUserId,
      toUserId,
      toAccount,
      amount,
      note,
    });
    const receiverUser = await userRepository.findValidatedById(
      context.resolvedReceiverUserId,
    );
    if (!receiverUser)
      return res.status(404).json({ error: "Recipient not found" });

    const transferResult = await executeTransfer({
      senderUserId,
      resolvedReceiverUserId: context.resolvedReceiverUserId,
      amount: context.amount,
      note: context.note,
      senderAccountNumber: context.senderAccountNumber,
      receiverAccountNumber: context.receiverAccountNumber,
      receiverWalletByAccount: context.receiverWalletByAccount,
    });

    await consumeOtpChallenge(challenge.id);

    await logAuditEvent({
      actor: req.user?.email,
      userId: senderUserId,
      action: "TRANSFER_OTP_VERIFIED",
      details: {
        challengeId: challenge.id,
        transactionId: transferResult.transaction.id,
      },
      ipAddress: getRequestIp(req),
    });

    notifyBalanceChange({
      to: senderUser.email,
      recipientName: getRecipientName(senderUser),
      direction: "debit",
      amount: context.amount,
      balance: transferResult.senderBalance,
      currency: transferResult.currency,
      transactionType: "TRANSFER",
      description:
        transferResult.transaction.description ??
        `Transfer to ${transferResult.receiverAccountNumber}`,
      occurredAt: transferResult.transaction.createdAt.toISOString(),
      counterpartyLabel: getRecipientName(receiverUser),
    });
    notifyBalanceChange({
      to: receiverUser.email,
      recipientName: getRecipientName(receiverUser),
      direction: "credit",
      amount: context.amount,
      balance: transferResult.receiverBalance,
      currency: transferResult.currency,
      transactionType: "TRANSFER",
      description:
        context.note || `Receive from ${context.senderAccountNumber}`,
      occurredAt: transferResult.transaction.createdAt.toISOString(),
      counterpartyLabel: getRecipientName(senderUser),
    });

    return res.json({
      status: "ok",
      reconciliationId: transferResult.reconciliationId,
      transaction: {
        id: transferResult.transaction.id,
        amount: transferResult.transaction.amount,
        type: transferResult.transaction.type,
        description: transferResult.transaction.description ?? undefined,
        createdAt: transferResult.transaction.createdAt.toISOString(),
        toAccount: transferResult.receiverAccountNumber,
      },
    });
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_CHALLENGE_NOT_FOUND") {
      return res.status(404).json({ error: "OTP challenge not found" });
    }
    if (err instanceof Error && err.message === "OTP_CHALLENGE_ALREADY_USED") {
      return res.status(400).json({ error: "OTP challenge already used" });
    }
    if (err instanceof Error && err.message === "OTP_EXPIRED") {
      return res.status(400).json({ error: "OTP has expired" });
    }
    if (err instanceof Error && err.message === "OTP_TOO_MANY_ATTEMPTS") {
      return res.status(429).json({ error: "Too many invalid OTP attempts" });
    }
    if (err instanceof Error && err.message === "OTP_INCORRECT") {
      return res.status(400).json({ error: "Incorrect OTP" });
    }
    if (err instanceof Error && err.message === "SENDER_WALLET_NOT_FOUND") {
      return res.status(400).json({ error: "Sender wallet not found" });
    }
    if (err instanceof Error && err.message === "INSUFFICIENT_BALANCE") {
      return res.status(400).json({ error: "Insufficient balance" });
    }
    if (err instanceof Error && err.message === "RECIPIENT_ACCOUNT_NOT_FOUND") {
      return res.status(404).json({ error: "Recipient account not found" });
    }
    if (err instanceof Error && err.message === "RECIPIENT_NOT_FOUND") {
      return res.status(404).json({ error: "Recipient not found" });
    }
    if (err instanceof Error && err.message === "RECIPIENT_LOCKED") {
      return res.status(423).json({ error: "Recipient account is locked" });
    }
    console.error("Failed to confirm transfer with OTP", err);
    return res.status(500).json({ error: "Failed to confirm transfer" });
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
    const userRepository = createUserRepository();
    const senderUser = await userRepository.findValidatedById(senderUserId);
    if (!senderUser) return res.status(404).json({ error: "User not found" });

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
    let receiverWalletByAccount: {
      id: string;
      userId: string | null;
      metadata: unknown;
    } | null = null;

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
    if (!receiver)
      return res.status(404).json({ error: "Recipient not found" });
    const transferResult = await executeTransfer({
      senderUserId,
      resolvedReceiverUserId,
      amount,
      note,
      senderAccountNumber,
      receiverAccountNumber:
        toAccount || buildAccountNumber(resolvedReceiverUserId),
      receiverWalletByAccount,
    });

    notifyBalanceChange({
      to: senderUser.email,
      recipientName: getRecipientName(senderUser),
      direction: "debit",
      amount,
      balance: transferResult.senderBalance,
      currency: transferResult.currency,
      transactionType: "TRANSFER",
      description:
        transferResult.transaction.description ??
        `Transfer to ${transferResult.receiverAccountNumber}`,
      occurredAt: transferResult.transaction.createdAt.toISOString(),
      counterpartyLabel: getRecipientName(receiver),
    });
    notifyBalanceChange({
      to: receiver.email,
      recipientName: getRecipientName(receiver),
      direction: "credit",
      amount,
      balance: transferResult.receiverBalance,
      currency: transferResult.currency,
      transactionType: "TRANSFER",
      description: note || `Receive from ${senderAccountNumber}`,
      occurredAt: transferResult.transaction.createdAt.toISOString(),
      counterpartyLabel: getRecipientName(senderUser),
    });

    return res.json({
      status: "ok",
      reconciliationId: transferResult.reconciliationId,
      transaction: {
        id: transferResult.transaction.id,
        amount: transferResult.transaction.amount,
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
        ...(walletIds.length
          ? { walletId: { in: walletIds } }
          : { walletId: "__NO_WALLET__" }),
      },
      orderBy: { createdAt: "desc" },
      take: 200,
    });

    return res.json(
      txns.map((txn) => {
        const decrypted = decryptStoredTransaction(txn);
        return {
          id: decrypted.id,
          amount: decrypted.amount,
          type: decrypted.type,
          status: decrypted.status,
          description: decrypted.description ?? undefined,
          createdAt: decrypted.createdAt.toISOString(),
          metadata: decrypted.metadata,
        };
      }),
    );
  } catch (err) {
    console.error("Failed to list transactions", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/security/login-events", (_req, res) => {
  res.json({ score: 0.1, reasons: ["stub"], received: _req.body });
});

app.get("/security/overview", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const [policy, userDoc] = await Promise.all([
      getSecurityPolicy(),
      createUserRepository().findValidatedById(userId),
    ]);

    if (!userDoc) return res.status(404).json({ error: "User not found" });

    const authSecurityState = getAuthSecurityState(userDoc.metadata);
    const repo = createLoginEventRepository();
    const since = new Date(
      Date.now() - SECURITY_OVERVIEW_WINDOW_DAYS * 24 * 60 * 60 * 1000,
    );
    const events = await repo.findByUserSince(userId, since, 50);
    const trustedByIp = new Map(
      authSecurityState.trustedIps.map((entry) => [entry.ipAddress, entry]),
    );

    const alerts = events.slice(0, 12).map((event) => {
      const normalizedIp = normalizeIpAddress(event.ipAddress);
      return buildUserSecurityAlert(
        event,
        policy.anomalyAlertThreshold,
        normalizedIp ? trustedByIp.get(normalizedIp) : undefined,
      );
    });

    const recentLogins = events.slice(0, 20).map((event) => {
      const normalizedIp = normalizeIpAddress(event.ipAddress);
      const trustedIp = normalizedIp
        ? trustedByIp.get(normalizedIp)
        : undefined;
      return {
        id: event.id,
        location: buildSecurityLocationLabel(event),
        ipAddress: normalizedIp ?? undefined,
        userAgent: event.userAgent ?? "Unknown device",
        success: Boolean(event.success),
        anomaly: event.anomaly ?? 0,
        createdAt: event.createdAt.toISOString(),
        trustedIp: Boolean(trustedIp),
      };
    });

    const trustedDevices = authSecurityState.trustedIps.map((entry, index) => {
      const matchingEvent = events.find(
        (event) =>
          Boolean(event.success) &&
          normalizeIpAddress(event.ipAddress) === entry.ipAddress,
      );

      return {
        id: `trusted-device-${index + 1}`,
        ipAddress: entry.ipAddress,
        location: buildSecurityLocationLabel({
          location: matchingEvent?.location,
          ipAddress: entry.ipAddress,
        }),
        userAgent: matchingEvent?.userAgent ?? "Saved trusted device",
        firstSeenAt: entry.firstSeenAt,
        lastSeenAt: entry.lastSeenAt,
        lastVerifiedAt: entry.lastVerifiedAt,
        current: entry.ipAddress === authSecurityState.lastLoginIp,
      };
    });

    return res.json({
      alerts,
      recentLogins,
      trustedDevices,
    });
  } catch (err) {
    console.error("Failed to load security overview", err);
    return res.status(500).json({ error: "Internal error" });
  }
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
      await userRepository.setStatus(
        req.params.id,
        statusNormalized as UserStatus,
      );
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
        ipAddress: getRequestIp(req),
      });

      return res.json({ user: sanitized });
    } catch (err) {
      console.error("Failed to update user status", err);
      return res.status(400).json({ error: "Invalid user id" });
    }
  },
);

app.post(
  "/admin/users/:id/deposit",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const adminUserId = req.user?.sub;
    const targetUserId = req.params.id;
    const amount = toPositiveAmount((req.body as { amount?: unknown })?.amount);
    if (!amount) return res.status(400).json({ error: "Invalid amount" });

    try {
      const targetUser = await prisma.user.findUnique({
        where: { id: targetUserId },
        select: { id: true, email: true, fullName: true, status: true },
      });
      if (!targetUser) return res.status(404).json({ error: "User not found" });
      if (targetUser.status !== "ACTIVE") {
        return res.status(423).json({ error: "Target user is not active" });
      }

      const wallet = await getOrCreateWalletByUserId(targetUserId);
      const updated = await prisma.$transaction(async (tx) => {
        const nextWallet = await tx.wallet.update({
          where: { id: wallet.id },
          data: { balance: { increment: amount } },
        });

        const transactionId = generateEncryptedTransactionId();
        const transaction = decryptStoredTransaction(
          await tx.transaction.create({
            data: {
              id: transactionId,
              ...buildEncryptedTransactionCreateData(transactionId, {
                walletId: nextWallet.id,
                sensitive: {
                  amount,
                  type: "DEPOSIT",
                  status: "COMPLETED",
                  description: `Admin top-up for ${targetUser.email}`,
                  fromUserId: adminUserId,
                  toUserId: targetUser.id,
                  metadata: {
                    entry: "CREDIT",
                    source: "ADMIN_TOPUP",
                  },
                },
              }),
            },
          }),
        );

        return { nextWallet, transaction };
      });

      await logAuditEvent({
        actor: req.user?.email ?? "admin",
        userId: targetUserId,
        action: "ADMIN_DEPOSIT",
        details: {
          amount,
          currency: updated.nextWallet.currency,
        },
        ipAddress: getRequestIp(req),
      });

      notifyBalanceChange({
        to: targetUser.email,
        recipientName: getRecipientName(targetUser),
        direction: "credit",
        amount,
        balance: Number(updated.nextWallet.balance),
        currency: updated.nextWallet.currency,
        transactionType: "DEPOSIT",
        description: updated.transaction.description ?? "Admin top-up",
        occurredAt: updated.transaction.createdAt.toISOString(),
        counterpartyLabel: "FPIPay Admin",
      });

      return res.json({
        wallet: {
          id: updated.nextWallet.id,
          balance: Number(updated.nextWallet.balance),
          currency: updated.nextWallet.currency,
        },
        transaction: {
          id: updated.transaction.id,
          amount: updated.transaction.amount,
          type: updated.transaction.type,
          status: updated.transaction.status,
          description: updated.transaction.description ?? "",
          createdAt: updated.transaction.createdAt.toISOString(),
          fromUserId: updated.transaction.fromUserId ?? undefined,
          toUserId: updated.transaction.toUserId ?? undefined,
        },
      });
    } catch (err) {
      console.error("Failed to deposit for user", err);
      return res.status(500).json({ error: "Internal error" });
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
    const normalized = txns.map((txn) => {
      const decrypted = decryptStoredTransaction(txn);
      return {
        id: decrypted.id,
        amount: decrypted.amount,
        type: decrypted.type,
        status: decrypted.status,
        description: decrypted.description ?? "",
        createdAt: decrypted.createdAt,
        fromUserId: decrypted.fromUserId ?? undefined,
        toUserId: decrypted.toUserId ?? undefined,
      };
    });
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
      await lockUserAccount(
        userId,
        email,
        "Demo brute force lock",
        getRequestIp(req),
      );
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

const normalizeTimezone = (value: string) => {
  const trimmed = value.trim();
  if (/^[A-Za-z0-9_+\-/:]+$/.test(trimmed)) {
    return trimmed;
  }
  return "Asia/Ho_Chi_Minh";
};

const configureDatabaseTimezone = async () => {
  const tz = normalizeTimezone(APP_TIMEZONE);
  const escapedTz = tz.replace(/'/g, "''");

  await prisma.$executeRawUnsafe(`SET TIME ZONE '${escapedTz}'`);

  try {
    await prisma.$executeRawUnsafe(
      `ALTER ROLE CURRENT_USER SET timezone TO '${escapedTz}'`,
    );
    console.log(`Database role timezone set to ${tz}`);
  } catch (err) {
    console.warn(
      `Cannot persist DB role timezone (${tz}). Session timezone is still applied.`,
      err,
    );
  }
};

const initializeDatabase = async () => {
  const maxAttempts = 8;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await prisma.$connect();
      await configureDatabaseTimezone();
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
    const server = app.listen(PORT, () => {
      console.log(`API listening on http://localhost:${PORT}`);
    });
    server.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        console.error(
          `Port ${PORT} is already in use. Stop the existing process or restart the VS Code api:dev task.`,
        );
        process.exit(1);
      }
      console.error("Failed to start API server", err);
      process.exit(1);
    });
    void initializeDatabase();
  } catch (err) {
    console.error("Failed to start API server", err);
    process.exit(1);
  }
};

start();
