import crypto from "crypto";
import { existsSync } from "fs";
import path from "path";
import { spawn } from "child_process";

import cors from "cors";
import dotenv from "dotenv";
import express, { type ErrorRequestHandler, type Request } from "express";
import fetch from "node-fetch";
import helmet from "helmet";
import morgan from "morgan";
import OpenAI from "openai";
import { Prisma, type Wallet } from "@prisma/client";
import { z } from "zod";

import {
  PROFESSIONAL_PASSWORD_MIN_LENGTH,
  loginSchema,
  meetsProfessionalPasswordPolicy,
  registerSchema,
} from "@secure-wallet/shared";
import type { components } from "@secure-wallet/shared/api-client/types";

import {
  COPILOT_FINANCE_KNOWLEDGE,
  COPILOT_COMMON_MARKET_SYMBOLS,
  COPILOT_COMPANY_ALIASES,
  COPILOT_INDEX_ALIASES,
  type MarketIntent,
} from "./data/financeKnowledge";
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
  invalidateSecurityPolicyCache,
} from "./services/securityPolicy";
import { logAuditEvent } from "./services/audit";
import {
  sendBalanceChangeEmail,
  sendBudgetCategoryAlertEmail,
  sendBudgetDigestEmail,
  sendBudgetPacingReminderEmail,
  sendBudgetThresholdAlertEmail,
  sendCardDetailsOtpEmail,
  sendLoginOtpEmail,
  sendLoginRiskAlertEmail,
  sendPasswordResetOtpEmail,
  sendRegisterOtpEmail,
  sendTransferRiskAlertEmail,
  sendTransferPinOtpEmail,
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
  deriveVirtualCardCvv,
  deriveVirtualCardNumber,
  getStoredCardCvv,
  getStoredCardFullNumber,
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
  verifyAndConsumeEmailOtpChallenge,
  verifyEmailOtpChallenge,
} from "./services/otp";

// Support running from both repo root and apps/api folders.
dotenv.config({ path: path.resolve(process.cwd(), ".env"), override: true });
dotenv.config({
  path: path.resolve(process.cwd(), "../../.env"),
  override: true,
});

const AI_SERVICE_WORKDIR =
  [
    path.resolve(process.cwd(), "../ai-service"),
    path.resolve(process.cwd(), "apps/ai-service"),
    path.resolve(process.cwd(), "../../apps/ai-service"),
  ].find((candidate) => existsSync(candidate)) ||
  path.resolve(process.cwd(), "../ai-service");

function runAsyncSideEffect(label: string, work: () => Promise<unknown>) {
  void work().catch((error) => {
    console.error(`Background side effect failed: ${label}`, error);
  });
}

const SAFE_AVATAR_MIME_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
]);
const MAX_AVATAR_BINARY_BYTES = 900 * 1024;

function hasMagicBytes(buffer: Buffer, signature: number[], offset = 0) {
  if (buffer.length < offset + signature.length) return false;
  return signature.every((byte, index) => buffer[offset + index] === byte);
}

function isSafeAvatarBuffer(buffer: Buffer, mimeType: string) {
  if (mimeType === "image/jpeg") {
    return hasMagicBytes(buffer, [0xff, 0xd8, 0xff]);
  }
  if (mimeType === "image/png") {
    return hasMagicBytes(
      buffer,
      [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    );
  }
  if (mimeType === "image/webp") {
    return (
      hasMagicBytes(buffer, [0x52, 0x49, 0x46, 0x46]) &&
      hasMagicBytes(buffer, [0x57, 0x45, 0x42, 0x50], 8)
    );
  }
  return false;
}

function parseSafeAvatarDataUrl(input: unknown) {
  if (typeof input !== "string") return undefined;
  const value = input.trim();
  if (!value) return undefined;
  if (value.length > 2_000_000) {
    throw new Error("AVATAR_TOO_LARGE");
  }

  const match = value.match(
    /^data:([a-z0-9.+-]+\/[a-z0-9.+-]+);base64,([a-z0-9+/=]+)$/i,
  );
  if (!match) {
    throw new Error("AVATAR_INVALID_FORMAT");
  }

  const mimeType = match[1].toLowerCase();
  if (!SAFE_AVATAR_MIME_TYPES.has(mimeType)) {
    throw new Error("AVATAR_UNSUPPORTED_TYPE");
  }

  const base64Payload = match[2];
  const buffer = Buffer.from(base64Payload, "base64");
  if (!buffer.length) {
    throw new Error("AVATAR_INVALID_FORMAT");
  }
  if (buffer.byteLength > MAX_AVATAR_BINARY_BYTES) {
    throw new Error("AVATAR_TOO_LARGE");
  }
  if (!isSafeAvatarBuffer(buffer, mimeType)) {
    throw new Error("AVATAR_CONTENT_MISMATCH");
  }

  return `data:${mimeType};base64,${buffer.toString("base64")}`;
}

type UserCacheScope = "auth" | "wallet" | "transactions" | "security";

const USER_RESPONSE_CACHE_TTL_MS = Number(
  process.env.USER_RESPONSE_CACHE_TTL_MS || "4000",
);
const userResponseCache = new Map<
  string,
  { expiresAt: number; value: unknown }
>();

function getUserCacheKey(userId: string, scope: UserCacheScope) {
  return `${scope}:${userId}`;
}

async function getCachedUserResponse<T>(
  userId: string,
  scope: UserCacheScope,
  load: () => Promise<T>,
  ttlMs = USER_RESPONSE_CACHE_TTL_MS,
): Promise<T> {
  const key = getUserCacheKey(userId, scope);
  const cached = userResponseCache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value as T;
  }

  const value = await load();
  userResponseCache.set(key, {
    value,
    expiresAt: Date.now() + ttlMs,
  });
  return value;
}

function invalidateUserResponseCache(
  userId: string,
  scopes?: UserCacheScope[],
) {
  const targets: UserCacheScope[] = scopes || [
    "auth",
    "wallet",
    "transactions",
    "security",
  ];

  for (const scope of targets) {
    userResponseCache.delete(getUserCacheKey(userId, scope));
  }
}

const app = express();
app.set("trust proxy", true);
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "25mb";
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json({ limit: JSON_BODY_LIMIT }));
app.use(applySecurityHeaders);
app.use(lockoutGuard);

const PORT = Number(process.env.PORT || process.env.PORT_API || 4000);
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";
const AI_URL = process.env.AI_SERVICE_URL || "http://localhost:8000";
const AI_API_KEY = process.env.AI_API_KEY || "local-dev-key";
const OLLAMA_URL = (process.env.OLLAMA_URL || "http://127.0.0.1:11434").replace(
  /\/$/,
  "",
);
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "";
const OLLAMA_TIMEOUT_MS = Number(process.env.OLLAMA_TIMEOUT_MS || "15000");
const OLLAMA_FALLBACK_MODEL = process.env.OLLAMA_FALLBACK_MODEL || "";
const OLLAMA_FALLBACK_TIMEOUT_MS = Number(
  process.env.OLLAMA_FALLBACK_TIMEOUT_MS || "20000",
);
const OLLAMA_TEMPERATURE = Number(process.env.OLLAMA_TEMPERATURE || "0.25");
const OLLAMA_TOP_P = Number(process.env.OLLAMA_TOP_P || "0.9");
const OLLAMA_REPEAT_PENALTY = Number(
  process.env.OLLAMA_REPEAT_PENALTY || "1.08",
);
const OLLAMA_NUM_CTX = Number(process.env.OLLAMA_NUM_CTX || "4096");
const OLLAMA_NUM_PREDICT = Number(process.env.OLLAMA_NUM_PREDICT || "768");
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";
const OPENAI_REASONING_EFFORT = process.env.OPENAI_REASONING_EFFORT || "low";
const ALLOW_EXTERNAL_FINANCIAL_CONTEXT = !["0", "false", "no"].includes(
  String(process.env.ALLOW_EXTERNAL_FINANCIAL_CONTEXT || "0")
    .trim()
    .toLowerCase(),
);
const ENABLE_TRANSFER_LLM_RULES = !["0", "false", "no"].includes(
  String(process.env.ENABLE_TRANSFER_LLM_RULES || "0")
    .trim()
    .toLowerCase(),
);
const TRANSFER_LLM_RULES_CACHE_TTL_MS = Number(
  process.env.TRANSFER_LLM_RULES_CACHE_TTL_MS || "300000",
);
const APP_TIMEZONE = process.env.APP_TIMEZONE || "Asia/Ho_Chi_Minh";
const APP_BASE_URL = (process.env.APP_BASE_URL || "").trim().replace(/\/$/, "");
const DEFAULT_ADMIN_EMAIL = (process.env.DEFAULT_ADMIN_EMAIL || "")
  .trim()
  .toLowerCase();
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || "";
const BOOTSTRAP_DEFAULT_ADMIN = !["0", "false", "no"].includes(
  String(process.env.BOOTSTRAP_DEFAULT_ADMIN || "0")
    .trim()
    .toLowerCase(),
);
const TRANSFER_OTP_TTL_MINUTES = Math.max(
  5,
  Number(process.env.TRANSFER_OTP_TTL_MINUTES || "5"),
);
const TRANSFER_OTP_MAX_ATTEMPTS = Number(
  process.env.TRANSFER_OTP_MAX_ATTEMPTS || "5",
);
const LARGE_TRANSFER_ADVISORY_AMOUNT = Number(
  process.env.LARGE_TRANSFER_ADVISORY_AMOUNT || "1000",
);
const HIGH_TRANSFER_ADVISORY_AMOUNT = Number(
  process.env.HIGH_TRANSFER_ADVISORY_AMOUNT || "5000",
);
const BALANCE_DRAIN_ADVISORY_RATIO = Number(
  process.env.BALANCE_DRAIN_ADVISORY_RATIO || "0.85",
);
const BALANCE_DRAIN_WARNING_RATIO = Number(
  process.env.BALANCE_DRAIN_WARNING_RATIO || "0.95",
);
const LOW_REMAINING_BALANCE_ADVISORY = Number(
  process.env.LOW_REMAINING_BALANCE_ADVISORY || "25",
);
const BALANCE_DRAIN_ADVISORY_MIN_AMOUNT = Number(
  process.env.BALANCE_DRAIN_ADVISORY_MIN_AMOUNT ||
    LARGE_TRANSFER_ADVISORY_AMOUNT,
);
const BALANCE_DRAIN_WARNING_MIN_AMOUNT = Number(
  process.env.BALANCE_DRAIN_WARNING_MIN_AMOUNT ||
    Math.max(LARGE_TRANSFER_ADVISORY_AMOUNT, 2000),
);
const TRANSFER_PROBE_SMALL_AMOUNT_MAX = Number(
  process.env.TRANSFER_PROBE_SMALL_AMOUNT_MAX || "150",
);
const TRANSFER_PROBE_BURST_COUNT_24H = Number(
  process.env.TRANSFER_PROBE_BURST_COUNT_24H || "3",
);
const SMALL_TRANSFER_BURST_WINDOW_MINUTES = Number(
  process.env.SMALL_TRANSFER_BURST_WINDOW_MINUTES || "5",
);
const SMALL_TRANSFER_BURST_COUNT = Number(
  process.env.SMALL_TRANSFER_BURST_COUNT || "5",
);
const SMALL_TRANSFER_BURST_SAME_RECIPIENT_COUNT = Number(
  process.env.SMALL_TRANSFER_BURST_SAME_RECIPIENT_COUNT || "3",
);
const SMALL_TRANSFER_BURST_BLOCK_MINUTES = Number(
  process.env.SMALL_TRANSFER_BURST_BLOCK_MINUTES || "10",
);
const TRANSFER_PROBE_LARGE_ESCALATION_MIN_AMOUNT = Number(
  process.env.TRANSFER_PROBE_LARGE_ESCALATION_MIN_AMOUNT ||
    HIGH_TRANSFER_ADVISORY_AMOUNT,
);
const TRANSFER_SCAM_BLOCK_MIN_AMOUNT = Number(
  process.env.TRANSFER_SCAM_BLOCK_MIN_AMOUNT || "100000",
);
const TRANSFER_SCAM_BLOCK_MAX_REMAINING_BALANCE = Number(
  process.env.TRANSFER_SCAM_BLOCK_MAX_REMAINING_BALANCE || "0.01",
);
const TRANSFER_SCAM_BLOCK_SPEND_SURGE_RATIO = Number(
  process.env.TRANSFER_SCAM_BLOCK_SPEND_SURGE_RATIO || "6",
);
const TRANSFER_SCAM_HOLD_MS = Number.isFinite(
  Number(process.env.TRANSFER_SCAM_HOLD_SECONDS),
)
  ? Number(process.env.TRANSFER_SCAM_HOLD_SECONDS) * 1000
  : Number(process.env.TRANSFER_SCAM_HOLD_MINUTES || "30") * 60 * 1000;
const KNOWN_RECIPIENT_LOOKBACK_DAYS = Number(
  process.env.KNOWN_RECIPIENT_LOOKBACK_DAYS || "180",
);
const LOGIN_OTP_TTL_MINUTES = Number(process.env.LOGIN_OTP_TTL_MINUTES || "5");
const HIGH_RISK_LOGIN_OTP_MAX_ATTEMPTS = Number(
  process.env.HIGH_RISK_LOGIN_OTP_MAX_ATTEMPTS || "3",
);
const REGISTER_OTP_TTL_MINUTES = LOGIN_OTP_TTL_MINUTES;
const RESET_PASSWORD_OTP_TTL_MINUTES = Number(
  process.env.RESET_PASSWORD_OTP_TTL_MINUTES || "10",
);
const CARD_DETAILS_OTP_TTL_MINUTES = Number(
  process.env.CARD_DETAILS_OTP_TTL_MINUTES || "5",
);
const TRANSFER_PIN_OTP_TTL_MINUTES = Number(
  process.env.TRANSFER_PIN_OTP_TTL_MINUTES || "5",
);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || "5");
const CAPTCHA_TRACK_WIDTH_PX = Number(
  process.env.CAPTCHA_TRACK_WIDTH_PX || "440",
);
const CAPTCHA_PIECE_WIDTH_PX = Number(
  process.env.CAPTCHA_PIECE_WIDTH_PX || "82",
);
const CAPTCHA_TOLERANCE_PX = Number(process.env.CAPTCHA_TOLERANCE_PX || "12");
const CAPTCHA_TTL_MS = Number(process.env.CAPTCHA_TTL_SECONDS || "180") * 1000;
const CAPTCHA_SECRET_KEY =
  process.env.CAPTCHA_SECRET_KEY ||
  process.env.JWT_SECRET ||
  "dev-insecure-captcha-secret";
const FACE_ID_CHALLENGE_TTL_MS =
  Number(process.env.FACE_ID_CHALLENGE_TTL_SECONDS || "300") * 1000;
const FACE_ID_SECRET_KEY = process.env.FACE_ID_SECRET_KEY || CAPTCHA_SECRET_KEY;
const FACE_ID_MIN_LIVENESS_SCORE = Number(
  process.env.FACE_ID_MIN_LIVENESS_SCORE || "0.54",
);
const FACE_ID_MIN_MOTION_SCORE = Number(
  process.env.FACE_ID_MIN_MOTION_SCORE || "0.12",
);
const FACE_ID_MIN_EYE_MOTION_SCORE = Number(
  process.env.FACE_ID_MIN_EYE_MOTION_SCORE || "0.04",
);
const FACE_ID_MIN_FACE_COVERAGE = Number(
  process.env.FACE_ID_MIN_FACE_COVERAGE || "0.06",
);
const FACE_ID_MIN_SAMPLE_COUNT = Number(
  process.env.FACE_ID_MIN_SAMPLE_COUNT || "10",
);
const FACE_ID_MIN_VIDEO_DURATION_MS = Number(
  process.env.FACE_ID_MIN_VIDEO_DURATION_MS || "5000",
);
const FACE_ID_MAX_VIDEO_DATA_URL_LENGTH = Number(
  process.env.FACE_ID_MAX_VIDEO_DATA_URL_LENGTH || "18000000",
);
const FACE_ID_LEGACY_MATCH_THRESHOLD = Number(
  process.env.FACE_ID_LEGACY_MATCH_THRESHOLD || "0.84",
);
const FACE_ID_V2_MATCH_THRESHOLD = Number(
  process.env.FACE_ID_V2_MATCH_THRESHOLD || "0.72",
);
const FACE_ID_V2_ALIGNED_MATCH_THRESHOLD = Number(
  process.env.FACE_ID_V2_ALIGNED_MATCH_THRESHOLD || "0.68",
);
const FACE_ID_V2_GEOMETRY_MATCH_THRESHOLD = Number(
  process.env.FACE_ID_V2_GEOMETRY_MATCH_THRESHOLD || "0.64",
);
const FACE_ID_V2_RESCUE_GEOMETRY_THRESHOLD = Number(
  process.env.FACE_ID_V2_RESCUE_GEOMETRY_THRESHOLD || "0.985",
);
const FACE_ID_V2_RESCUE_LEGACY_THRESHOLD = Number(
  process.env.FACE_ID_V2_RESCUE_LEGACY_THRESHOLD || "0.6",
);
const FACE_ID_V2_RESCUE_ALIGNED_FLOOR = Number(
  process.env.FACE_ID_V2_RESCUE_ALIGNED_FLOOR || "0.45",
);
const FACE_ID_DESCRIPTOR_V2_PREFIX = "faceid_v2:";
const TRANSFER_FACE_ID_THRESHOLD = Number(
  process.env.TRANSFER_FACE_ID_THRESHOLD || "10000",
);
const CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES = Number(
  process.env.CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES || "10",
);
const CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_SECONDS = Math.max(
  1,
  Math.round(
    Number(
      process.env.CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_SECONDS ||
        (process.env.CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES
          ? Number(process.env.CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES) *
            60
          : 150),
    ),
  ),
);
const CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES =
  CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_SECONDS / 60;
const CONTINUOUS_LARGE_TRANSFER_BLOCK_COUNT = Number(
  process.env.CONTINUOUS_LARGE_TRANSFER_BLOCK_COUNT || "1",
);
const TRANSFER_HIGH_RISK_IMMEDIATE_BLOCK = !["0", "false", "no"].includes(
  String(process.env.TRANSFER_HIGH_RISK_IMMEDIATE_BLOCK || "0")
    .trim()
    .toLowerCase(),
);
const TRANSFER_MEDIUM_RISK_OTP_MIN_AMOUNT = Number(
  process.env.TRANSFER_MEDIUM_RISK_OTP_MIN_AMOUNT || "250",
);
const MEDIUM_RISK_TRANSFER_LIMIT = Number(
  process.env.MEDIUM_RISK_TRANSFER_LIMIT || "500",
);
const HIGH_RISK_LOGIN_BLOCK_MINUTES = Number(
  process.env.HIGH_RISK_LOGIN_BLOCK_MINUTES || "10",
);
const AUTO_START_LOCAL_AI_SERVICE = !["0", "false", "no"].includes(
  String(process.env.AUTO_START_LOCAL_AI_SERVICE || (IS_PRODUCTION ? "0" : "1"))
    .trim()
    .toLowerCase(),
);

const parseAllowedOrigins = () => {
  const configuredOrigins = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim().replace(/\/$/, ""))
    .filter(Boolean);

  if (APP_BASE_URL) {
    configuredOrigins.push(APP_BASE_URL);
  }

  if (!configuredOrigins.length && !IS_PRODUCTION) {
    configuredOrigins.push(
      "http://localhost:5173",
      "http://127.0.0.1:5173",
      "http://localhost:4173",
      "http://127.0.0.1:4173",
    );
  }

  return new Set(configuredOrigins);
};

const ALLOWED_ORIGINS = parseAllowedOrigins();

const validateStartupConfiguration = () => {
  const requiredProductionEnv = [
    {
      key: "JWT_SECRET",
      isInvalid: (value: string) =>
        !value ||
        value === "changemejwtsecret" ||
        value === "dev-insecure-jwt-secret",
      message:
        "Set JWT_SECRET to a long random secret before starting production.",
    },
    {
      key: "ENCRYPTION_KEY",
      isInvalid: (value: string) =>
        !value || value === "replace-with-a-real-base64-32-byte-key",
      message:
        "Set ENCRYPTION_KEY to a real 32-byte base64 or hex key before starting production.",
    },
  ];

  for (const requirement of requiredProductionEnv) {
    const value = String(process.env[requirement.key] || "").trim();
    if (IS_PRODUCTION && requirement.isInvalid(value)) {
      throw new Error(requirement.message);
    }
  }

  if (IS_PRODUCTION && !ALLOWED_ORIGINS.size) {
    throw new Error(
      "Set APP_BASE_URL or ALLOWED_ORIGINS before starting production so CORS stays restricted.",
    );
  }

  if (
    IS_PRODUCTION &&
    BOOTSTRAP_DEFAULT_ADMIN &&
    (!DEFAULT_ADMIN_EMAIL || !DEFAULT_ADMIN_PASSWORD)
  ) {
    throw new Error(
      "BOOTSTRAP_DEFAULT_ADMIN is enabled but DEFAULT_ADMIN_EMAIL / DEFAULT_ADMIN_PASSWORD are missing.",
    );
  }
};

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        callback(null, true);
        return;
      }

      const normalizedOrigin = origin.replace(/\/$/, "");
      if (ALLOWED_ORIGINS.has(normalizedOrigin)) {
        callback(null, true);
        return;
      }

      callback(new Error("CORS origin not allowed."));
    },
  }),
);

const normalizeEmail = (email: string) => email.trim().toLowerCase();

const getRequestIp = (req: Request) => resolveRequestIpAddress(req);

const isLocalAiServiceUrl = (value: string) => {
  try {
    const parsed = new URL(value);
    return parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost";
  } catch {
    return false;
  }
};

const toAnomalyScore = (value: unknown) =>
  typeof value === "number" && Number.isFinite(value) ? value : 0;

type AnomalyResponse = {
  score: number;
  riskLevel: "low" | "medium" | "high";
  reasons: string[];
  archetype?: string | null;
  timeline?: string[];
  headline?: string | null;
  summary?: string | null;
  nextStep?: string | null;
  recommendedActions?: string[];
  monitoringOnly: boolean;
  action?: string;
  requireOtp: boolean;
  otpChannel?: string | null;
  otpReason?: string | null;
  modelSource?: string | null;
  modelVersion?: string | null;
  requestKey?: string | null;
  ruleRiskLevel?: "low" | "medium" | "high";
  modelRiskLevel?: "low" | "medium" | "high";
  ruleScore?: number;
  ruleHitCount?: number;
  baseScore?: number;
  finalScore?: number;
  mitigationScore?: number;
  mitigationReasons?: string[];
  counterArguments?: string[];
  accountSegment?: "personal" | "sme" | "enterprise";
  accountCategory?: "personal" | "business";
  accountTier?: string | null;
  accountProfileCode?: string | null;
  accountProfileStatus?: string | null;
  accountProfileConfidence?: number;
  analysisSignals?: Record<string, unknown>;
  finalAction?:
    | "ALLOW"
    | "ALLOW_WITH_WARNING"
    | "REQUIRE_OTP"
    | "REQUIRE_OTP_FACE_ID"
    | "HOLD_REVIEW";
  stepUpLevel?: string | null;
  decisionComponents?: Record<string, number>;
  adminSummary?: string | null;
  ruleHits?: Array<{
    ruleId?: string;
    title?: string;
    reason?: string;
    userWarning?: string;
    riskLevel?: string;
  }>;
  warning?: {
    title?: string;
    message?: string;
    doNot?: string[];
    mustDo?: string[];
    promptTemplateId?: string;
  } | null;
  inputContract?: {
    version: string;
    accountProfile?: Record<string, unknown> | null;
    transferContext?: Record<string, unknown> | null;
    behaviorSnapshot?: Record<string, unknown> | null;
  } | null;
  mlAnalysis?: {
    anomalyScore: number;
    rawScore: number;
    baseRiskLevel: "low" | "medium" | "high";
    adjustedRiskLevel: "low" | "medium" | "high";
    model?: {
      name?: string;
      version?: string | null;
      source?: string | null;
    } | null;
    topSignals?: Array<{
      feature: string;
      value: number;
      zScore?: number | null;
      baselineMean?: number | null;
      baselineStd?: number | null;
      direction?: "high" | "low" | "neutral";
    }>;
  } | null;
  llmAnalysis?: {
    riskLevel: "low" | "medium" | "high";
    signalCount: number;
    signals: string[];
    ruleTags: string[];
    summary?: string | null;
    source?: string | null;
    model?: string | null;
  } | null;
  finalDecision?: {
    riskLevel: "low" | "medium" | "high";
    finalAction?:
      | "ALLOW"
      | "ALLOW_WITH_WARNING"
      | "REQUIRE_OTP"
      | "REQUIRE_OTP_FACE_ID"
      | "HOLD_REVIEW";
    finalScore?: number;
    headline?: string | null;
    summary?: string | null;
    nextStep?: string | null;
    recommendedActions?: string[];
    stepUpLevel?: string | null;
  } | null;
};

type TransferSafetyAdvisory = {
  requestKey: string | null;
  severity: "caution" | "warning" | "blocked";
  title: string;
  message: string;
  archetype?: string | null;
  timeline?: string[];
  recommendedActions?: string[];
  confirmationLabel: string;
  reasons: string[];
  requiresAcknowledgement: boolean;
  transferRatio: number;
  remainingBalance: number;
  remainingBalanceRatio: number;
  amount: number;
  currency: string;
  blockedUntil?: string | null;
};

type TransferSpendProfile = {
  todaySpendBefore: number;
  dailySpendAvg30d: number;
  projectedDailySpend: number;
  spendSurgeRatio: number | null;
};

type TransferRecipientProfile = {
  isKnownRecipient: boolean;
  completedTransfers: number;
  totalSent: number;
  lastTransferAt: string | null;
};

type RecentTransferRecipient = {
  accountNumber: string;
  holderName: string;
  userId?: string;
  lastTransferredAt: string;
  transferCount: number;
};

type TransferBehaviorProfile = {
  recentReviewCount30d: number;
  recentBlockedCount30d: number;
  recentPendingOtpCount7d: number;
  averageCompletedOutflow90d: number;
  maxCompletedOutflow90d: number;
  similarFlaggedAmountCount90d: number;
  sameRecipientFlaggedCount90d: number;
  recentInboundAmount24h: number;
  recentAdminTopUpAmount24h: number;
  recentSelfDepositAmount24h: number;
  smallProbeCount24h: number;
  smallProbeTotal24h: number;
  distinctSmallProbeRecipients24h: number;
  sameRecipientSmallProbeCount24h: number;
  newRecipientSmallProbeCount24h: number;
  probeThenLargeRiskScore: number;
  rapidCashOutRiskScore: number;
};

type TransferNoteLlmAnalysis = {
  riskLevel: "low" | "medium" | "high";
  signals: string[];
  ruleTags: string[];
  summary: string | null;
  purposeTags: string[];
  purposeConfidence: number;
  source: "disabled" | "heuristic" | "openai" | "fallback";
  model?: string | null;
};

type TransferRiskLlmContextInput = {
  note: string;
  amount: number;
  currency: string;
  accountCategory: "personal" | "business";
  accountSegment: "personal" | "sme" | "enterprise";
  recipientKnown: boolean;
  balanceImpactRatio: number;
  sessionRiskLevel: "low" | "medium" | "high";
  velocity1h: number;
  recentReviewCount30d: number;
  recentBlockedCount30d: number;
  spendSurgeRatio: number | null;
};

type TransferStepUpPolicy = {
  faceIdRequired: boolean;
  faceIdReason: string | null;
  rollingOutflowAmount: number;
  recentLargeCompletedCount: number;
  shouldBlockContinuousLargeTransfer: boolean;
  shouldBlockSmallTransferBurst: boolean;
  recentSmallTransferCount: number;
  recentSmallTransferSameRecipientCount: number;
  blockReason: string | null;
  blockedUntil: string | null;
  retryAfterSeconds: number | null;
};

type TransferSafetyHold = {
  toAccount: string;
  toUserId: string;
  amount: number;
  requestKey: string | null;
  reason: string;
  blockedUntil: string;
  createdAt: string;
};

type AdminAlertStatus =
  | "pending_review"
  | "confirmed_risk"
  | "false_positive"
  | "escalated";

type AdminAlertSignal = {
  label: string;
  value: string;
  tone: "neutral" | "warn" | "info";
};

type AdminAlertResponse = {
  id: string;
  type: "login" | "transaction";
  sourceAction: string;
  actor: string;
  userId: string | null;
  createdAt: string;
  ipAddress: string | null;
  riskLevel: AnomalyResponse["riskLevel"];
  anomalyScore: number;
  reasons: string[];
  summary: string;
  explanation: string;
  keySignals: AdminAlertSignal[];
  adminStatus: AdminAlertStatus;
  adminNote: string | null;
  reviewedAt: string | null;
  reviewedBy: string | null;
  monitoringOnly: boolean;
  aiDecision: string | null;
  modelVersion: string | null;
  modelSource: string | null;
  eventId: string | null;
  transactionId: string | null;
  amount: number | null;
  currency: string | null;
  location: string | null;
  paymentMethod: string | null;
  merchantCategory: string | null;
  baseScore: number | null;
  finalScore: number | null;
  mitigationScore: number | null;
  mitigationReasons: string[];
  counterArguments: string[];
  accountSegment: AnomalyResponse["accountSegment"] | null;
  adminSummary: string | null;
  decisionComponents: Record<string, number> | null;
  segmentHistoryCount30d: number | null;
  segmentAmountP90_30d: number | null;
  segmentAmountMedian30d: number | null;
  smallProbeCount24h: number | null;
  distinctSmallProbeRecipients24h: number | null;
  sameRecipientSmallProbeCount24h: number | null;
  newRecipientSmallProbeCount24h: number | null;
  probeThenLargeRiskScore: number | null;
  recentInboundAmount24h: number | null;
  recentAdminTopUpAmount24h: number | null;
  recentSelfDepositAmount24h: number | null;
  rapidCashOutRiskScore: number | null;
  transferAdvisorySeverity: TransferSafetyAdvisory["severity"] | null;
  transferAdvisoryTitle: string | null;
  transferAdvisoryMessage: string | null;
  transferBlockedUntil: string | null;
  finalAction: AnomalyResponse["finalAction"] | null;
  stepUpLevel: string | null;
  nextStep: string | null;
  archetype: string | null;
  timeline: string[];
  recommendedActions: string[];
  ruleHits: Array<{
    ruleId?: string;
    title?: string;
    reason?: string;
    userWarning?: string;
    riskLevel?: string;
  }>;
  warningTitle: string | null;
  warningMessage: string | null;
  warningMustDo: string[];
  warningDoNot: string[];
  analysisSignals: Record<string, unknown> | null;
};

type SessionSecurityState = {
  riskLevel: "low" | "medium" | "high";
  reviewReason?: string;
  verificationMethod?: "password" | "email_otp" | "sms_otp";
  restrictLargeTransfers?: boolean;
  maxTransferAmount?: number;
};

const RECENT_TRANSFER_RECIPIENTS_KEY = "recentTransferRecipients";
const MAX_RECENT_TRANSFER_RECIPIENTS = 8;

type ClientDeviceContext = {
  browser?: string;
  browserVersion?: string;
  platform?: string;
  platformVersion?: string;
  deviceType?: string;
  mobile?: boolean;
  deviceTitle?: string;
  deviceDetail?: string;
};

type SliderCaptchaPayload = {
  kind: "slider_v1";
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  targetOffsetPx: number;
  maxOffsetPx: number;
  tolerancePx: number;
};

type FaceIdStep = "center" | "move_left" | "move_right" | "move_closer";

type FaceIdChallengePayload = {
  kind: "faceid_v1";
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  steps: FaceIdStep[];
  minLivenessScore: number;
  minMotionScore: number;
  minEyeMotionScore: number;
  minFaceCoverage: number;
  minSampleCount: number;
};

type FaceIdEnrollmentSubmission = {
  challengeToken: string;
  descriptor: string;
  livenessScore: number;
  motionScore: number;
  eyeMotionScore: number;
  faceCoverage: number;
  sampleCount: number;
  completedSteps: FaceIdStep[];
  stepCaptures: Array<{
    step: FaceIdStep;
    image: string;
    centerX: number;
    centerY: number;
    coverage: number;
    motion: number;
    aligned?: boolean;
  }>;
  previewImage?: string;
  videoEvidence?: string;
  videoDurationMs?: number;
  videoMimeType?: string;
};

type FaceIdAntiSpoofResult = {
  passed: boolean;
  spoofScore: number;
  confidence: number;
  riskLevel: "low" | "medium" | "high";
  reasons: string[];
  modelSource?: string | null;
  modelVersion?: string | null;
};

type FaceIdLoginPayload = {
  kind: "faceid_login_v1";
  userId: string;
  email: string;
  currentIp: string;
  currentUserAgent?: string;
  issuedAt: number;
  expiresAt: number;
  score: number;
  aiResult: AnomalyResponse;
  wasTrustedIp: boolean;
  previousTrustedIp?: string | null;
  deviceContext?: ClientDeviceContext;
};

const DEFAULT_AI_RESPONSE: AnomalyResponse = {
  score: 0,
  riskLevel: "low",
  reasons: ["AI monitoring unavailable"],
  monitoringOnly: true,
  action: "NOTIFY_ADMIN_ONLY",
  requireOtp: false,
  otpChannel: null,
  otpReason: null,
  modelSource: "fallback",
  modelVersion: null,
  requestKey: null,
  finalAction: "ALLOW",
  finalScore: 0,
};

const buildHeuristicLoginAiResponse = (input: {
  currentIp?: string;
  wasTrustedIp: boolean;
  previousTrustedIp?: string | null;
  failedBefore: number;
  isPasswordValid: boolean;
}): AnomalyResponse => {
  let score = 0.12;
  const reasons = ["Heuristic login risk estimate was used."];

  if (!input.wasTrustedIp) {
    score += 0.38;
    reasons.push("Sign-in came from a new or untrusted IP.");
  }

  if (input.previousTrustedIp && input.previousTrustedIp !== input.currentIp) {
    score += 0.08;
    reasons.push("IP differs from the most recent trusted sign-in.");
  }

  if (input.failedBefore >= 3) {
    score += 0.22;
    reasons.push("There were multiple recent failed attempts.");
  } else if (input.failedBefore >= 1) {
    score += 0.1;
    reasons.push("There was at least one recent failed attempt.");
  }

  if (!input.isPasswordValid) {
    score += 0.1;
    reasons.push("Credential verification failed.");
  }

  score = clamp(score, 0.05, 0.98);

  const riskLevel = score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low";
  const requireOtp = !input.wasTrustedIp;
  const otpChannel = requireOtp ? "email" : null;
  const otpReason = requireOtp
    ? "the sign-in came from a new or untrusted IP"
    : null;
  const guidance = buildAnomalyGuidance({
    riskLevel,
    reasons,
    requireOtp,
    otpChannel,
    otpReason,
  });

  return {
    score,
    riskLevel,
    reasons,
    archetype: guidance.archetype,
    timeline: guidance.timeline,
    headline: guidance.headline,
    summary: guidance.summary,
    nextStep: guidance.nextStep,
    recommendedActions: guidance.recommendedActions,
    monitoringOnly: false,
    action: "NOTIFY_ADMIN_ONLY",
    requireOtp,
    otpChannel,
    otpReason,
    modelSource: "api-heuristic-fallback",
    modelVersion: "login-risk-v1",
    requestKey: null,
  };
};

const toStringList = (value: unknown) =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

const normalizeRiskLevel = (value: unknown): AnomalyResponse["riskLevel"] => {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (normalized === "high" || normalized === "medium") return normalized;
  return "low";
};

const normalizeAccountSegmentValue = (
  value: unknown,
): NonNullable<AnomalyResponse["accountSegment"]> => {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[\s_-]+/g, "");
  if (normalized === "enterprise" || normalized === "corporate") {
    return "enterprise";
  }
  if (normalized === "sme" || normalized === "smallbusiness") {
    return "sme";
  }
  return "personal";
};

const normalizeWarningPayload = (
  value: unknown,
): AnomalyResponse["warning"] => {
  if (!value || typeof value !== "object") return null;
  const data = value as Record<string, unknown>;
  const toList = (input: unknown) =>
    Array.isArray(input)
      ? input.filter((item): item is string => typeof item === "string")
      : [];
  return {
    title: typeof data.title === "string" ? data.title : undefined,
    message: typeof data.message === "string" ? data.message : undefined,
    doNot: toList(data.do_not ?? data.doNot),
    mustDo: toList(data.must_do ?? data.mustDo),
    promptTemplateId:
      typeof data.prompt_template_id === "string"
        ? data.prompt_template_id
        : typeof data.promptTemplateId === "string"
          ? data.promptTemplateId
          : undefined,
  };
};

const normalizeRuleHits = (value: unknown): AnomalyResponse["ruleHits"] => {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const data = entry as Record<string, unknown>;
    return [
      {
        ruleId:
          typeof data.rule_id === "string"
            ? data.rule_id
            : typeof data.ruleId === "string"
              ? data.ruleId
              : undefined,
        title: typeof data.title === "string" ? data.title : undefined,
        reason: typeof data.reason === "string" ? data.reason : undefined,
        userWarning:
          typeof data.user_warning === "string"
            ? data.user_warning
            : typeof data.userWarning === "string"
              ? data.userWarning
              : undefined,
        riskLevel:
          typeof data.risk_level === "string"
            ? data.risk_level
            : typeof data.riskLevel === "string"
              ? data.riskLevel
              : undefined,
      },
    ];
  });
};

const normalizeNumberRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const entries = Object.entries(value as Record<string, unknown>).filter(
    ([, entry]) => typeof entry === "number" && Number.isFinite(entry),
  );
  return entries.length
    ? Object.fromEntries(entries.map(([key, entry]) => [key, entry as number]))
    : undefined;
};

const normalizeMlSignals = (value: unknown): AnomalyResponse["mlAnalysis"] => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const data = value as Record<string, unknown>;
  const topSignals = Array.isArray(data.topSignals)
    ? data.topSignals.flatMap((entry) => {
        if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
          return [];
        }
        const item = entry as Record<string, unknown>;
        if (
          typeof item.feature !== "string" ||
          typeof item.value !== "number" ||
          !Number.isFinite(item.value)
        ) {
          return [];
        }
        const direction: "high" | "low" | "neutral" =
          item.direction === "high" ||
          item.direction === "low" ||
          item.direction === "neutral"
            ? item.direction
            : "neutral";
        return [
          {
            feature: item.feature,
            value: item.value,
            zScore:
              typeof item.zScore === "number" && Number.isFinite(item.zScore)
                ? item.zScore
                : null,
            baselineMean:
              typeof item.baselineMean === "number" &&
              Number.isFinite(item.baselineMean)
                ? item.baselineMean
                : null,
            baselineStd:
              typeof item.baselineStd === "number" &&
              Number.isFinite(item.baselineStd)
                ? item.baselineStd
                : null,
            direction,
          },
        ];
      })
    : [];

  return {
    anomalyScore:
      typeof data.anomalyScore === "number" &&
      Number.isFinite(data.anomalyScore)
        ? data.anomalyScore
        : 0,
    rawScore:
      typeof data.rawScore === "number" && Number.isFinite(data.rawScore)
        ? data.rawScore
        : 0,
    baseRiskLevel: normalizeRiskLevel(data.baseRiskLevel),
    adjustedRiskLevel: normalizeRiskLevel(data.adjustedRiskLevel),
    model:
      data.model && typeof data.model === "object" && !Array.isArray(data.model)
        ? {
            name:
              typeof (data.model as Record<string, unknown>).name === "string"
                ? ((data.model as Record<string, unknown>).name as string)
                : undefined,
            version:
              typeof (data.model as Record<string, unknown>).version ===
              "string"
                ? ((data.model as Record<string, unknown>).version as string)
                : null,
            source:
              typeof (data.model as Record<string, unknown>).source === "string"
                ? ((data.model as Record<string, unknown>).source as string)
                : null,
          }
        : null,
    topSignals,
  };
};

const normalizeLlmAnalysis = (
  value: unknown,
): AnomalyResponse["llmAnalysis"] => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const data = value as Record<string, unknown>;
  return {
    riskLevel: normalizeRiskLevel(data.riskLevel),
    signalCount:
      typeof data.signalCount === "number" && Number.isFinite(data.signalCount)
        ? data.signalCount
        : 0,
    signals: toStringList(data.signals).slice(0, 6),
    ruleTags: toStringList(data.ruleTags).slice(0, 6),
    summary: typeof data.summary === "string" ? data.summary : null,
    source: typeof data.source === "string" ? data.source : null,
    model: typeof data.model === "string" ? data.model : null,
  };
};

const normalizeFinalDecision = (
  value: unknown,
): AnomalyResponse["finalDecision"] => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const data = value as Record<string, unknown>;
  const finalAction =
    typeof data.finalAction === "string"
      ? (data.finalAction as
          | "ALLOW"
          | "ALLOW_WITH_WARNING"
          | "REQUIRE_OTP"
          | "REQUIRE_OTP_FACE_ID"
          | "HOLD_REVIEW")
      : undefined;
  return {
    riskLevel: normalizeRiskLevel(data.riskLevel),
    finalAction,
    finalScore:
      typeof data.finalScore === "number" && Number.isFinite(data.finalScore)
        ? data.finalScore
        : undefined,
    headline: typeof data.headline === "string" ? data.headline : null,
    summary: typeof data.summary === "string" ? data.summary : null,
    nextStep: typeof data.nextStep === "string" ? data.nextStep : null,
    recommendedActions: toStringList(data.recommendedActions).slice(0, 4),
    stepUpLevel: typeof data.stepUpLevel === "string" ? data.stepUpLevel : null,
  };
};

const normalizeAiResponse = (value: unknown): AnomalyResponse => {
  if (!value || typeof value !== "object") return DEFAULT_AI_RESPONSE;
  const data = value as Record<string, unknown>;
  const rawAccountSegment = data.account_segment ?? data.accountSegment;
  const rawAccountCategory = data.account_category ?? data.accountCategory;
  const rawAccountTier = data.account_tier ?? data.accountTier;
  const rawAccountProfileCode =
    data.account_profile_code ?? data.accountProfileCode;
  const rawAccountProfileStatus =
    data.account_profile_status ?? data.accountProfileStatus;
  const rawAccountProfileConfidence =
    data.account_profile_confidence ?? data.accountProfileConfidence;
  const riskLevel = normalizeRiskLevel(data.risk_level ?? data.riskLevel);
  const reasons = toStringList(data.reasons);
  const requireOtp = Boolean(data.require_otp_sms ?? data.requireOtp);
  const otpChannel =
    typeof data.otp_channel === "string"
      ? data.otp_channel
      : typeof data.otpChannel === "string"
        ? data.otpChannel
        : null;
  const otpReason =
    typeof data.otp_reason === "string"
      ? data.otp_reason
      : typeof data.otpReason === "string"
        ? data.otpReason
        : null;
  const warning = normalizeWarningPayload(data.warning_vi ?? data.warning);
  const guidance = buildAnomalyGuidance({
    riskLevel,
    reasons,
    requireOtp,
    otpChannel,
    otpReason,
    warning,
  });
  const normalizedInputContract =
    data.input_contract &&
    typeof data.input_contract === "object" &&
    !Array.isArray(data.input_contract)
      ? (data.input_contract as Record<string, unknown>)
      : data.inputContract &&
          typeof data.inputContract === "object" &&
          !Array.isArray(data.inputContract)
        ? (data.inputContract as Record<string, unknown>)
        : null;
  const mlAnalysis = normalizeMlSignals(data.ml_analysis ?? data.mlAnalysis);
  const llmAnalysis = normalizeLlmAnalysis(
    data.llm_analysis ?? data.llmAnalysis,
  );
  const finalDecision = normalizeFinalDecision(
    data.final_decision ?? data.finalDecision,
  );

  return {
    score: toAnomalyScore(data.anomaly_score ?? data.score),
    riskLevel,
    reasons,
    archetype:
      typeof data.archetype === "string" ? data.archetype : guidance.archetype,
    timeline: dedupeStringList([
      ...(Array.isArray(data.timeline)
        ? data.timeline.filter(
            (item): item is string => typeof item === "string",
          )
        : []),
      ...guidance.timeline,
    ]).slice(0, 4),
    headline:
      typeof data.headline === "string" ? data.headline : guidance.headline,
    summary: typeof data.summary === "string" ? data.summary : guidance.summary,
    nextStep:
      typeof data.next_step === "string"
        ? data.next_step
        : typeof data.nextStep === "string"
          ? data.nextStep
          : guidance.nextStep,
    recommendedActions: dedupeStringList([
      ...(Array.isArray(data.recommended_actions)
        ? data.recommended_actions.filter(
            (item): item is string => typeof item === "string",
          )
        : []),
      ...(Array.isArray(data.recommendedActions)
        ? data.recommendedActions.filter(
            (item): item is string => typeof item === "string",
          )
        : []),
      ...guidance.recommendedActions,
    ]).slice(0, 4),
    monitoringOnly: Boolean(
      data.monitoring_only ?? data.monitoringOnly ?? true,
    ),
    action: typeof data.action === "string" ? data.action : undefined,
    requireOtp,
    otpChannel,
    otpReason,
    modelSource:
      typeof data.model_source === "string"
        ? data.model_source
        : typeof data.modelSource === "string"
          ? data.modelSource
          : null,
    modelVersion:
      typeof data.model_version === "string"
        ? data.model_version
        : typeof data.modelVersion === "string"
          ? data.modelVersion
          : null,
    requestKey:
      typeof data.request_key === "string"
        ? data.request_key
        : typeof data.requestKey === "string"
          ? data.requestKey
          : null,
    ruleRiskLevel: normalizeRiskLevel(
      data.rule_risk_level ?? data.ruleRiskLevel,
    ),
    modelRiskLevel: normalizeRiskLevel(
      data.model_risk_level ??
        data.modelRiskLevel ??
        data.risk_level ??
        data.riskLevel,
    ),
    ruleScore:
      typeof data.rule_score === "number"
        ? data.rule_score
        : typeof data.ruleScore === "number"
          ? data.ruleScore
          : undefined,
    baseScore:
      typeof data.base_score === "number"
        ? data.base_score
        : typeof data.baseScore === "number"
          ? data.baseScore
          : undefined,
    finalScore:
      typeof data.final_score === "number"
        ? data.final_score
        : typeof data.finalScore === "number"
          ? data.finalScore
          : undefined,
    mitigationScore:
      typeof data.mitigation_score === "number"
        ? data.mitigation_score
        : typeof data.mitigationScore === "number"
          ? data.mitigationScore
          : undefined,
    mitigationReasons: dedupeStringList([
      ...(Array.isArray(data.mitigation_reasons)
        ? data.mitigation_reasons.filter(
            (item): item is string => typeof item === "string",
          )
        : []),
      ...(Array.isArray(data.mitigationReasons)
        ? data.mitigationReasons.filter(
            (item): item is string => typeof item === "string",
          )
        : []),
    ]).slice(0, 5),
    counterArguments: dedupeStringList([
      ...(Array.isArray(data.counter_arguments)
        ? data.counter_arguments.filter(
            (item): item is string => typeof item === "string",
          )
        : []),
      ...(Array.isArray(data.counterArguments)
        ? data.counterArguments.filter(
            (item): item is string => typeof item === "string",
          )
        : []),
    ]).slice(0, 4),
    accountSegment:
      rawAccountSegment === undefined || rawAccountSegment === null
        ? undefined
        : normalizeAccountSegmentValue(rawAccountSegment),
    accountCategory:
      typeof rawAccountCategory === "string" &&
      rawAccountCategory.trim().toLowerCase() === "business"
        ? "business"
        : typeof rawAccountCategory === "string"
          ? "personal"
          : undefined,
    accountTier:
      typeof rawAccountTier === "string" && rawAccountTier.trim()
        ? rawAccountTier.trim().toUpperCase()
        : null,
    accountProfileCode:
      typeof rawAccountProfileCode === "string" && rawAccountProfileCode.trim()
        ? rawAccountProfileCode.trim().toUpperCase()
        : null,
    accountProfileStatus:
      typeof rawAccountProfileStatus === "string" &&
      rawAccountProfileStatus.trim()
        ? rawAccountProfileStatus.trim().toUpperCase()
        : null,
    accountProfileConfidence:
      typeof rawAccountProfileConfidence === "number" &&
      Number.isFinite(rawAccountProfileConfidence)
        ? rawAccountProfileConfidence
        : undefined,
    analysisSignals:
      data.analysis_signals &&
      typeof data.analysis_signals === "object" &&
      !Array.isArray(data.analysis_signals)
        ? (data.analysis_signals as Record<string, unknown>)
        : data.analysisSignals &&
            typeof data.analysisSignals === "object" &&
            !Array.isArray(data.analysisSignals)
          ? (data.analysisSignals as Record<string, unknown>)
          : undefined,
    finalAction:
      typeof data.final_action === "string"
        ? (data.final_action as AnomalyResponse["finalAction"])
        : typeof data.finalAction === "string"
          ? (data.finalAction as AnomalyResponse["finalAction"])
          : undefined,
    stepUpLevel:
      typeof data.step_up_level === "string"
        ? data.step_up_level
        : typeof data.stepUpLevel === "string"
          ? data.stepUpLevel
          : null,
    decisionComponents:
      normalizeNumberRecord(
        data.decision_components ?? data.decisionComponents,
      ) ?? undefined,
    adminSummary:
      typeof data.admin_summary === "string"
        ? data.admin_summary
        : typeof data.adminSummary === "string"
          ? data.adminSummary
          : null,
    ruleHitCount:
      typeof data.rule_hit_count === "number"
        ? data.rule_hit_count
        : typeof data.ruleHitCount === "number"
          ? data.ruleHitCount
          : undefined,
    ruleHits: normalizeRuleHits(data.rule_hits ?? data.ruleHits),
    warning,
    inputContract: normalizedInputContract
      ? {
          version:
            typeof normalizedInputContract.version === "string"
              ? normalizedInputContract.version
              : "tx_risk_input_v1",
          accountProfile:
            normalizeRecord(normalizedInputContract.accountProfile)
              .constructor === Object
              ? normalizeRecord(normalizedInputContract.accountProfile)
              : null,
          transferContext:
            normalizeRecord(normalizedInputContract.transferContext)
              .constructor === Object
              ? normalizeRecord(normalizedInputContract.transferContext)
              : null,
          behaviorSnapshot:
            normalizeRecord(normalizedInputContract.behaviorSnapshot)
              .constructor === Object
              ? normalizeRecord(normalizedInputContract.behaviorSnapshot)
              : null,
        }
      : null,
    mlAnalysis,
    llmAnalysis,
    finalDecision,
  };
};

const AI_ALERT_ACTIONS = [
  "AI_LOGIN_ALERT",
  "AI_TRANSACTION_ALERT",
  "AI_ALERT",
  "TRANSFER_ADVISORY_PRESENTED",
  "TRANSFER_SAFETY_BLOCKED",
] as const;

const normalizeRecord = (value: unknown): Record<string, unknown> => {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
};

const extractAdminAlertRequestKey = (
  details: unknown,
  metadata: unknown,
): string | null => {
  const detailsRecord = normalizeRecord(details);
  const metadataRecord = normalizeRecord(metadata);
  const aiMonitoring = normalizeRecord(metadataRecord.aiMonitoring);
  const transferAdvisory = normalizeTransferSafetyAdvisory(
    metadataRecord.transferAdvisory ?? detailsRecord.transferAdvisory,
  );

  return (
    asStringOrNull(detailsRecord.requestKey) ||
    asStringOrNull(metadataRecord.requestKey) ||
    asStringOrNull(aiMonitoring.requestKey) ||
    transferAdvisory?.requestKey ||
    null
  );
};

const buildAdminAlertDedupKey = (input: {
  userId: string | null;
  action: string;
  createdAt: Date;
  details: unknown;
  metadata: unknown;
}) => {
  const requestKey = extractAdminAlertRequestKey(input.details, input.metadata);
  if (requestKey) {
    return `req:${input.userId || "anon"}:${input.action}:${requestKey}`;
  }

  const detailsRecord = normalizeRecord(input.details);
  const metadataRecord = normalizeRecord(input.metadata);
  const aiMonitoring = normalizeRecord(metadataRecord.aiMonitoring);
  const transferAdvisory = normalizeTransferSafetyAdvisory(
    metadataRecord.transferAdvisory ?? detailsRecord.transferAdvisory,
  );
  const riskLevel = normalizeRiskLevel(
    detailsRecord.riskLevel ??
      aiMonitoring.riskLevel ??
      metadataRecord.riskLevel,
  );
  const amount =
    asNumberOrNull(detailsRecord.amount) ??
    asNumberOrNull(aiMonitoring.amount) ??
    transferAdvisory?.amount ??
    0;
  const toAccount =
    asStringOrNull(detailsRecord.toAccount) ||
    asStringOrNull(metadataRecord.toAccount) ||
    "-";
  const summary =
    asStringOrNull(detailsRecord.message) ||
    asStringOrNull(aiMonitoring.headline) ||
    transferAdvisory?.title ||
    toStringList(detailsRecord.reasons)[0] ||
    toStringList(aiMonitoring.reasons)[0] ||
    transferAdvisory?.reasons[0] ||
    "-";
  const timeBucket = Math.floor(input.createdAt.getTime() / 30_000);

  return [
    "fp",
    input.userId || "anon",
    input.action,
    riskLevel,
    Math.round(amount * 100),
    toAccount,
    summary.trim().toLowerCase(),
    timeBucket,
  ].join(":");
};

const inferAdminAuditCategory = (action: string) => {
  const normalized = action.toUpperCase();
  if (normalized.includes("LOGIN") || normalized.includes("MFA"))
    return "login";
  if (
    normalized.includes("TRANSFER") ||
    normalized.includes("TRANSACTION") ||
    normalized.includes("WITHDRAW") ||
    normalized.includes("DEPOSIT") ||
    normalized.includes("PAYMENT") ||
    normalized.includes("REFUND")
  ) {
    return "tx";
  }
  if (normalized.includes("USER") || normalized.includes("ROLE")) return "um";
  if (
    normalized.includes("PROFILE") ||
    normalized.includes("PASSWORD") ||
    normalized.includes("ACCOUNT")
  ) {
    return "acc";
  }
  return "sec";
};

const inferAdminAuditStatus = (action: string, details: unknown) => {
  const normalizedAction = action.toUpperCase();
  const normalizedDetails =
    typeof details === "string"
      ? details.toUpperCase()
      : JSON.stringify(details ?? {}).toUpperCase();
  if (
    normalizedAction.includes("FAIL") ||
    normalizedAction.includes("BLOCK") ||
    normalizedAction.includes("DENY") ||
    normalizedAction.includes("ALERT") ||
    normalizedDetails.includes("FAIL") ||
    normalizedDetails.includes("BLOCK")
  ) {
    return "fail";
  }
  if (
    normalizedAction.includes("PENDING") ||
    normalizedAction.includes("REVIEW") ||
    normalizedDetails.includes("PENDING") ||
    normalizedDetails.includes("REVIEW")
  ) {
    return "pending";
  }
  return "ok";
};

const inferAdminAuditSource = (input: {
  actor: string;
  action: string;
  metadata: unknown;
}) => {
  const metadata = normalizeRecord(input.metadata);
  if (
    input.actor === "ai-service" ||
    input.action.toUpperCase().startsWith("AI_") ||
    metadata.category === "funds_flow_training"
  ) {
    return "ai";
  }
  return "human";
};

const asStringOrNull = (value: unknown) =>
  typeof value === "string" && value.trim() ? value.trim() : null;

const asNumberOrNull = (value: unknown) =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const toTitleCase = (value: string) =>
  value
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");

const normalizeAdminAlertStatus = (value: unknown): AdminAlertStatus => {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (
    normalized === "confirmed_risk" ||
    normalized === "false_positive" ||
    normalized === "escalated"
  ) {
    return normalized;
  }
  return "pending_review";
};

const buildAdminAlertExplanation = (input: {
  type: "login" | "transaction";
  riskLevel: AnomalyResponse["riskLevel"];
  reasons: string[];
  monitoringOnly: boolean;
  aiDecision?: string | null;
}) => {
  const subject = input.type === "transaction" ? "transaction" : "login";
  const reasonText = input.reasons.length
    ? input.reasons.join(", ")
    : "unusual behavior";
  const modeText = input.monitoringOnly
    ? "The model is currently operating in monitoring mode."
    : "The model is currently configured to trigger an active response.";
  const decisionText = input.aiDecision
    ? ` Current AI decision: ${toTitleCase(input.aiDecision)}.`
    : "";

  return {
    summary: `${toTitleCase(input.riskLevel)} risk ${subject} alert`,
    explanation: `AI flagged this ${subject} because it detected ${reasonText}. ${modeText}${decisionText}`,
  };
};

const buildAdminAlertSignals = (
  type: "login" | "transaction",
  detail: Record<string, unknown>,
  riskLevel: AnomalyResponse["riskLevel"],
): AdminAlertSignal[] => {
  const signals: AdminAlertSignal[] = [
    {
      label: "Risk level",
      value: toTitleCase(riskLevel),
      tone:
        riskLevel === "high"
          ? "warn"
          : riskLevel === "medium"
            ? "info"
            : "neutral",
    },
  ];

  const anomalyScore = asNumberOrNull(detail.anomalyScore);
  if (anomalyScore !== null) {
    signals.push({
      label: "Anomaly score",
      value: `${Math.round(anomalyScore * 100)}%`,
      tone:
        anomalyScore >= 0.9 ? "warn" : anomalyScore >= 0.7 ? "info" : "neutral",
    });
  }

  const modelVersion = asStringOrNull(detail.modelVersion);
  if (modelVersion) {
    signals.push({
      label: "Model version",
      value: modelVersion,
      tone: "neutral",
    });
  }

  const finalScore = asNumberOrNull(detail.finalScore);
  if (finalScore !== null) {
    signals.push({
      label: "Final risk",
      value: `${Math.round(finalScore)}/100`,
      tone: finalScore >= 80 ? "warn" : finalScore >= 60 ? "info" : "neutral",
    });
  }

  const mitigationScore = asNumberOrNull(detail.mitigationScore);
  if (mitigationScore !== null && mitigationScore > 0) {
    signals.push({
      label: "Mitigation",
      value: `-${Math.round(mitigationScore)}`,
      tone: "info",
    });
  }

  const finalAction = asStringOrNull(detail.finalAction);
  if (finalAction) {
    signals.push({
      label: "AI action",
      value: toTitleCase(finalAction),
      tone:
        finalAction === "HOLD_REVIEW" || finalAction === "REQUIRE_OTP_FACE_ID"
          ? "warn"
          : finalAction === "REQUIRE_OTP" ||
              finalAction === "ALLOW_WITH_WARNING"
            ? "info"
            : "neutral",
    });
  }

  const transferAdvisorySeverity = asStringOrNull(
    detail.transferAdvisorySeverity,
  );
  if (transferAdvisorySeverity) {
    signals.push({
      label: "Transfer advisory",
      value: toTitleCase(transferAdvisorySeverity),
      tone:
        transferAdvisorySeverity === "blocked"
          ? "warn"
          : transferAdvisorySeverity === "warning"
            ? "info"
            : "neutral",
    });
  }

  const accountSegment = asStringOrNull(detail.accountSegment);
  if (accountSegment) {
    signals.push({
      label: "Segment",
      value: toTitleCase(accountSegment),
      tone: "neutral",
    });
  }

  if (type === "login") {
    const ipAddress = asStringOrNull(detail.ipAddress);
    const country = asStringOrNull(detail.country);
    const region = asStringOrNull(detail.region);
    const city = asStringOrNull(detail.city);
    if (ipAddress) {
      signals.push({ label: "IP address", value: ipAddress, tone: "warn" });
    }
    const location = [city, region, country].filter(Boolean).join(", ");
    if (location) {
      signals.push({ label: "Location", value: location, tone: "info" });
    }
  } else {
    const amount = asNumberOrNull(detail.amount);
    const currency = asStringOrNull(detail.currency) ?? "USD";
    const country = asStringOrNull(detail.country);
    const paymentMethod = asStringOrNull(detail.paymentMethod);
    const merchantCategory = asStringOrNull(detail.merchantCategory);
    const rapidCashOutRiskScore =
      asNumberOrNull(detail.rapidCashOutRiskScore) ??
      asNumberOrNull(detail.rapid_cash_out_risk_score);
    const recentInboundAmount24h =
      asNumberOrNull(detail.recentInboundAmount24h) ??
      asNumberOrNull(detail.recent_inbound_amount_24h);
    const recentAdminTopUpAmount24h =
      asNumberOrNull(detail.recentAdminTopUpAmount24h) ??
      asNumberOrNull(detail.recent_admin_topup_amount_24h);
    if (amount !== null) {
      signals.push({
        label: "Amount",
        value: `${amount.toLocaleString("en-US", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        })} ${currency}`,
        tone: amount >= 1000 ? "warn" : "info",
      });
    }
    if (country) {
      signals.push({ label: "Country", value: country, tone: "info" });
    }
    if (paymentMethod) {
      signals.push({
        label: "Payment method",
        value: paymentMethod,
        tone: "neutral",
      });
    }
    if (merchantCategory) {
      signals.push({
        label: "Merchant category",
        value: merchantCategory,
        tone: "neutral",
      });
    }
    if (rapidCashOutRiskScore !== null && rapidCashOutRiskScore >= 0.45) {
      signals.push({
        label: "AML pattern",
        value: "Rapid cash-out after fresh funding",
        tone: "warn",
      });
    }
    if (recentInboundAmount24h !== null && recentInboundAmount24h > 0) {
      signals.push({
        label: "Fresh inflow 24h",
        value: `${recentInboundAmount24h.toLocaleString("en-US", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        })} ${currency}`,
        tone: recentInboundAmount24h >= 1000 ? "warn" : "info",
      });
    }
    if (recentAdminTopUpAmount24h !== null && recentAdminTopUpAmount24h > 0) {
      signals.push({
        label: "Admin top-up 24h",
        value: `${recentAdminTopUpAmount24h.toLocaleString("en-US", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        })} ${currency}`,
        tone: "warn",
      });
    }
  }

  return signals;
};

const buildAdminAlertResponse = (log: {
  id: string;
  userId: string | null;
  actor: string;
  action: string;
  details: unknown;
  ipAddress: string | null;
  createdAt: Date;
  metadata: unknown;
}): AdminAlertResponse => {
  const detail = normalizeRecord(log.details);
  const metadata = normalizeRecord(log.metadata);
  const aiMonitoring = normalizeRecord(metadata.aiMonitoring);
  const transferAdvisory = normalizeTransferSafetyAdvisory(
    metadata.transferAdvisory ?? detail.transferAdvisory,
  );
  const analysisSignals = normalizeRecord(aiMonitoring.analysisSignals);
  const warning = normalizeRecord(aiMonitoring.warning);
  const ruleHits = Array.isArray(aiMonitoring.ruleHits)
    ? aiMonitoring.ruleHits
        .filter(
          (item): item is Record<string, unknown> =>
            Boolean(item) && typeof item === "object" && !Array.isArray(item),
        )
        .map((item) => ({
          ruleId: asStringOrNull(item.ruleId) || undefined,
          title: asStringOrNull(item.title) || undefined,
          reason: asStringOrNull(item.reason) || undefined,
          userWarning: asStringOrNull(item.userWarning) || undefined,
          riskLevel: asStringOrNull(item.riskLevel) || undefined,
        }))
        .filter(
          (item) =>
            item.ruleId ||
            item.title ||
            item.reason ||
            item.userWarning ||
            item.riskLevel,
        )
    : [];
  const mergedDetail: Record<string, unknown> = {
    ...aiMonitoring,
    ...(transferAdvisory
      ? {
          transferAdvisorySeverity: transferAdvisory.severity,
          transferAdvisoryTitle: transferAdvisory.title,
          transferAdvisoryMessage: transferAdvisory.message,
          transferBlockedUntil: transferAdvisory.blockedUntil ?? null,
          amount:
            asNumberOrNull(detail.amount) ??
            asNumberOrNull(aiMonitoring.amount) ??
            transferAdvisory.amount,
          currency:
            asStringOrNull(detail.currency) ??
            asStringOrNull(aiMonitoring.currency) ??
            transferAdvisory.currency,
          archetype: transferAdvisory.archetype ?? aiMonitoring.archetype,
          timeline:
            Array.isArray(aiMonitoring.timeline) &&
            aiMonitoring.timeline.length > 0
              ? aiMonitoring.timeline
              : transferAdvisory.timeline,
          recommendedActions:
            Array.isArray(aiMonitoring.recommendedActions) &&
            aiMonitoring.recommendedActions.length > 0
              ? aiMonitoring.recommendedActions
              : transferAdvisory.recommendedActions,
          reasons:
            Array.isArray(aiMonitoring.reasons) &&
            aiMonitoring.reasons.length > 0
              ? aiMonitoring.reasons
              : transferAdvisory.reasons,
          headline:
            typeof aiMonitoring.headline === "string" &&
            aiMonitoring.headline.trim()
              ? aiMonitoring.headline
              : transferAdvisory.title,
          summary:
            typeof aiMonitoring.summary === "string" &&
            aiMonitoring.summary.trim()
              ? aiMonitoring.summary
              : transferAdvisory.message,
        }
      : {}),
    ...detail,
    ...analysisSignals,
  };
  const type =
    log.action === "AI_LOGIN_ALERT" &&
    !transferAdvisory &&
    asNumberOrNull(mergedDetail.amount) === null
      ? "login"
      : "transaction";
  const reasons = Array.from(
    new Set(
      [
        ...toStringList(transferAdvisory?.reasons),
        ...toStringList(mergedDetail.reasons),
        ...ruleHits.flatMap((item) =>
          [item.userWarning, item.reason, item.title].filter(
            (value): value is string => Boolean(value),
          ),
        ),
      ]
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
  const riskLevel = normalizeRiskLevel(
    mergedDetail.riskLevel ?? metadata.riskLevel ?? "low",
  );
  const monitoringOnly = Boolean(
    mergedDetail.monitoringOnly ?? metadata.monitoringOnly ?? true,
  );
  const explanation = buildAdminAlertExplanation({
    type,
    riskLevel,
    reasons,
    monitoringOnly,
    aiDecision: asStringOrNull(mergedDetail.aiDecision),
  });
  const country = asStringOrNull(mergedDetail.country);
  const region = asStringOrNull(mergedDetail.region);
  const city = asStringOrNull(mergedDetail.city);
  const location =
    [city, region, country].filter(Boolean).join(", ") || country;
  const timeline = Array.from(
    new Set(
      [
        ...toStringList(transferAdvisory?.timeline),
        ...toStringList(mergedDetail.timeline),
      ]
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
  const recommendedActions = Array.from(
    new Set(
      [
        ...toStringList(transferAdvisory?.recommendedActions),
        ...toStringList(mergedDetail.recommendedActions),
      ]
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
  const warningMustDo = toStringList(warning.mustDo).map((item) => item.trim());
  const warningDoNot = toStringList(warning.doNot).map((item) => item.trim());
  const finalAction = asStringOrNull(mergedDetail.finalAction);
  const transferAdvisorySeverity =
    transferAdvisory?.severity ??
    (asStringOrNull(mergedDetail.transferAdvisorySeverity) as
      | TransferSafetyAdvisory["severity"]
      | null);

  return {
    id: log.id,
    type,
    sourceAction: log.action,
    actor: log.actor,
    userId: log.userId,
    createdAt: log.createdAt.toISOString(),
    ipAddress: log.ipAddress ?? asStringOrNull(mergedDetail.ipAddress),
    riskLevel,
    anomalyScore: toAnomalyScore(
      mergedDetail.anomalyScore ?? mergedDetail.score,
    ),
    reasons,
    summary:
      transferAdvisory?.title ??
      asStringOrNull(mergedDetail.headline) ??
      explanation.summary,
    explanation:
      transferAdvisory?.message ??
      asStringOrNull(mergedDetail.summary) ??
      explanation.explanation,
    keySignals: buildAdminAlertSignals(type, mergedDetail, riskLevel),
    adminStatus: normalizeAdminAlertStatus(
      mergedDetail.adminStatus ?? metadata.adminStatus,
    ),
    adminNote: asStringOrNull(mergedDetail.adminNote ?? metadata.adminNote),
    reviewedAt: asStringOrNull(mergedDetail.reviewedAt ?? metadata.reviewedAt),
    reviewedBy: asStringOrNull(mergedDetail.reviewedBy ?? metadata.reviewedBy),
    monitoringOnly,
    aiDecision: asStringOrNull(mergedDetail.aiDecision),
    modelVersion:
      asStringOrNull(mergedDetail.modelVersion) ??
      asStringOrNull(metadata.modelVersion),
    modelSource:
      asStringOrNull(mergedDetail.modelSource) ??
      asStringOrNull(metadata.modelSource),
    eventId:
      asStringOrNull(mergedDetail.loginEventId) ??
      asStringOrNull(mergedDetail.transactionEventId) ??
      asStringOrNull(metadata.loginEventId) ??
      asStringOrNull(metadata.transactionEventId),
    transactionId:
      asStringOrNull(mergedDetail.transactionId) ??
      asStringOrNull(metadata.transactionId),
    amount: asNumberOrNull(mergedDetail.amount),
    currency: asStringOrNull(mergedDetail.currency),
    location,
    paymentMethod: asStringOrNull(mergedDetail.paymentMethod),
    merchantCategory: asStringOrNull(mergedDetail.merchantCategory),
    baseScore: asNumberOrNull(mergedDetail.baseScore),
    finalScore: asNumberOrNull(mergedDetail.finalScore),
    mitigationScore: asNumberOrNull(mergedDetail.mitigationScore),
    mitigationReasons: toStringList(mergedDetail.mitigationReasons),
    counterArguments: toStringList(mergedDetail.counterArguments),
    accountSegment: asStringOrNull(mergedDetail.accountSegment)
      ? normalizeAccountSegmentValue(mergedDetail.accountSegment)
      : null,
    adminSummary:
      asStringOrNull(mergedDetail.adminSummary) ??
      asStringOrNull(aiMonitoring.adminSummary),
    decisionComponents:
      mergedDetail.decisionComponents &&
      typeof mergedDetail.decisionComponents === "object" &&
      !Array.isArray(mergedDetail.decisionComponents)
        ? Object.fromEntries(
            Object.entries(
              mergedDetail.decisionComponents as Record<string, unknown>,
            ).flatMap(([key, value]) =>
              typeof value === "number" && Number.isFinite(value)
                ? ([[key, value]] as const)
                : [],
            ),
          )
        : null,
    segmentHistoryCount30d: asNumberOrNull(
      analysisSignals.segment_history_count_30d,
    ),
    segmentAmountP90_30d: asNumberOrNull(
      analysisSignals.segment_amount_p90_30d,
    ),
    segmentAmountMedian30d: asNumberOrNull(
      analysisSignals.segment_amount_median_30d,
    ),
    smallProbeCount24h: asNumberOrNull(analysisSignals.small_probe_count_24h),
    distinctSmallProbeRecipients24h: asNumberOrNull(
      analysisSignals.distinct_small_probe_recipients_24h,
    ),
    sameRecipientSmallProbeCount24h: asNumberOrNull(
      analysisSignals.same_recipient_small_probe_count_24h,
    ),
    newRecipientSmallProbeCount24h: asNumberOrNull(
      analysisSignals.new_recipient_small_probe_count_24h,
    ),
    probeThenLargeRiskScore: asNumberOrNull(
      analysisSignals.probe_then_large_risk_score,
    ),
    recentInboundAmount24h: asNumberOrNull(
      analysisSignals.recent_inbound_amount_24h,
    ),
    recentAdminTopUpAmount24h: asNumberOrNull(
      analysisSignals.recent_admin_topup_amount_24h,
    ),
    recentSelfDepositAmount24h: asNumberOrNull(
      analysisSignals.recent_self_deposit_amount_24h,
    ),
    rapidCashOutRiskScore: asNumberOrNull(
      analysisSignals.rapid_cash_out_risk_score,
    ),
    transferAdvisorySeverity,
    transferAdvisoryTitle: transferAdvisory?.title ?? null,
    transferAdvisoryMessage: transferAdvisory?.message ?? null,
    transferBlockedUntil: transferAdvisory?.blockedUntil ?? null,
    finalAction:
      finalAction === "ALLOW" ||
      finalAction === "ALLOW_WITH_WARNING" ||
      finalAction === "REQUIRE_OTP" ||
      finalAction === "REQUIRE_OTP_FACE_ID" ||
      finalAction === "HOLD_REVIEW"
        ? finalAction
        : null,
    stepUpLevel: asStringOrNull(mergedDetail.stepUpLevel),
    nextStep: asStringOrNull(mergedDetail.nextStep),
    archetype: asStringOrNull(mergedDetail.archetype),
    timeline,
    recommendedActions,
    ruleHits,
    warningTitle: asStringOrNull(warning.title),
    warningMessage: asStringOrNull(warning.message),
    warningMustDo,
    warningDoNot,
    analysisSignals:
      Object.keys(analysisSignals).length > 0 ? analysisSignals : null,
  };
};

const buildSessionSecurityState = (
  riskLevel: AnomalyResponse["riskLevel"],
  options?: {
    reviewReason?: string;
    verificationMethod?: "password" | "email_otp" | "sms_otp";
    restrictLargeTransfers?: boolean;
    maxTransferAmount?: number;
  },
): SessionSecurityState => {
  const restrictLargeTransfers =
    options?.restrictLargeTransfers ?? riskLevel === "medium";
  return {
    riskLevel,
    reviewReason: options?.reviewReason,
    verificationMethod: options?.verificationMethod ?? "password",
    restrictLargeTransfers,
    maxTransferAmount: restrictLargeTransfers
      ? (options?.maxTransferAmount ?? MEDIUM_RISK_TRANSFER_LIMIT)
      : undefined,
  };
};

const isTransferBlockedBySessionSecurity = (input: {
  amount: number;
  sessionSecurity?: SessionSecurityState;
}) => {
  const sessionSecurity = input.sessionSecurity;
  if (
    !sessionSecurity?.restrictLargeTransfers ||
    typeof sessionSecurity.maxTransferAmount !== "number"
  ) {
    return false;
  }

  return input.amount > sessionSecurity.maxTransferAmount;
};

const LOCATION_PLACEHOLDER_VALUES = new Set([
  "UNK",
  "UNKNOWN",
  "UNKNOWN LOCATION",
  "XX",
  "ZZ",
  "T1",
  "N/A",
]);

const countryDisplayNames =
  typeof Intl !== "undefined" && "DisplayNames" in Intl
    ? new Intl.DisplayNames(["en"], { type: "region" })
    : null;

const readRequestHeaderString = (value: unknown) => {
  if (Array.isArray(value)) {
    const firstString = value.find(
      (item): item is string =>
        typeof item === "string" && item.trim().length > 0,
    );
    return firstString?.trim();
  }

  return typeof value === "string" && value.trim() ? value.trim() : undefined;
};

const normalizeLocationLabelValue = (value: unknown) => {
  const raw = readRequestHeaderString(value);
  if (!raw) return undefined;
  const upper = raw.toUpperCase();
  if (LOCATION_PLACEHOLDER_VALUES.has(upper)) return undefined;

  if (/^[A-Z]{2}$/.test(upper)) {
    try {
      return countryDisplayNames?.of(upper) || upper;
    } catch {
      return upper;
    }
  }

  return raw;
};

const normalizeClientDeviceContext = (
  value: unknown,
): ClientDeviceContext | undefined => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }

  const raw = value as Record<string, unknown>;
  const readString = (input: unknown) =>
    typeof input === "string" && input.trim() ? input.trim() : undefined;

  const deviceContext: ClientDeviceContext = {
    browser: readString(raw.browser),
    browserVersion: readString(raw.browserVersion),
    platform: readString(raw.platform),
    platformVersion: readString(raw.platformVersion),
    deviceType: readString(raw.deviceType),
    mobile: typeof raw.mobile === "boolean" ? raw.mobile : undefined,
    deviceTitle: readString(raw.deviceTitle),
    deviceDetail: readString(raw.deviceDetail),
  };

  return Object.values(deviceContext).some((entry) => entry !== undefined)
    ? deviceContext
    : undefined;
};

const readClientDeviceContext = (payload: unknown) => {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return undefined;
  }

  const body = payload as Record<string, unknown>;
  return normalizeClientDeviceContext(body.deviceContext);
};

const buildUserAgentDeviceSummary = (
  userAgent?: string,
  deviceContext?: ClientDeviceContext,
) => {
  if (deviceContext?.deviceTitle || deviceContext?.deviceDetail) {
    return {
      title: deviceContext.deviceTitle || "Unknown device",
      detail:
        deviceContext.deviceDetail ||
        [deviceContext.browser, deviceContext.browserVersion]
          .filter(Boolean)
          .join(" ") ||
        "Browser and device details unavailable",
    };
  }

  const agent = userAgent?.trim() || "";
  if (!agent) {
    return {
      title: "Unknown device",
      detail: "Browser and device details unavailable",
    };
  }

  let browserLabel = "";
  const browserMatchers: Array<[RegExp, string]> = [
    [/Edg\/(\d+)/, "Edge"],
    [/Chrome\/(\d+)/, "Chrome"],
    [/Firefox\/(\d+)/, "Firefox"],
    [/Version\/(\d+).+Safari\//, "Safari"],
  ];
  for (const [pattern, label] of browserMatchers) {
    const match = agent.match(pattern);
    if (match) {
      browserLabel = `${label}${match[1] ? ` ${match[1]}` : ""}`;
      break;
    }
  }

  if (/Windows/i.test(agent)) {
    return {
      title: "Windows PC",
      detail: [browserLabel, "Windows"].filter(Boolean).join(" | "),
    };
  }
  if (/Mac OS X/i.test(agent)) {
    return {
      title: "Mac device",
      detail: [browserLabel, "macOS"].filter(Boolean).join(" | "),
    };
  }
  if (/iPhone/i.test(agent)) {
    return {
      title: "iPhone",
      detail: [browserLabel, "iOS"].filter(Boolean).join(" | "),
    };
  }
  if (/iPad/i.test(agent)) {
    return {
      title: "iPad",
      detail: [browserLabel, "iPadOS"].filter(Boolean).join(" | "),
    };
  }
  if (/Android/i.test(agent)) {
    return {
      title: /Mobile/i.test(agent) ? "Android phone" : "Android device",
      detail: [browserLabel, "Android"].filter(Boolean).join(" | "),
    };
  }
  if (/Linux/i.test(agent)) {
    return {
      title: "Linux device",
      detail: [browserLabel, "Linux"].filter(Boolean).join(" | "),
    };
  }

  return {
    title: "Unknown device",
    detail:
      browserLabel || (agent.length > 64 ? `${agent.slice(0, 64)}...` : agent),
  };
};

const buildAuditClientMetadata = (req: Request, payload?: unknown) => {
  const userAgent = readRequestHeaderString(req.headers["user-agent"]);
  const deviceContext = readClientDeviceContext(payload);
  const location = getRequestLocation(req);
  const hasDeviceSignal = Boolean(userAgent || deviceContext);
  const deviceSummary = hasDeviceSignal
    ? buildUserAgentDeviceSummary(userAgent, deviceContext)
    : null;

  return {
    ...(location ? { location } : {}),
    ...(userAgent ? { userAgent } : {}),
    ...(deviceContext ? { deviceContext } : {}),
    ...(deviceSummary?.title ? { deviceTitle: deviceSummary.title } : {}),
    ...(deviceSummary?.detail ? { deviceDetail: deviceSummary.detail } : {}),
  };
};

const isPrivateOrLoopbackIpAddress = (value?: string | null) => {
  const normalized = normalizeIpAddress(value);
  if (!normalized) return false;
  if (normalized === "127.0.0.1" || normalized === "::1") return true;

  if (normalized.includes(".")) {
    const parts = normalized.split(".").map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
      return false;
    }
    const [a, b] = parts;
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
    );
  }

  const lower = normalized.toLowerCase();
  return (
    lower === "::1" ||
    lower.startsWith("fc") ||
    lower.startsWith("fd") ||
    lower.startsWith("fe80:")
  );
};

const getRequestLocation = (req: Request) => {
  const city = normalizeLocationLabelValue(
    req.headers["x-vercel-ip-city"] ?? req.headers["cf-ipcity"],
  );
  const region = normalizeLocationLabelValue(
    req.headers["x-vercel-ip-country-region"] ?? req.headers["cf-region-code"],
  );
  const country = normalizeLocationLabelValue(
    req.headers["cf-ipcountry"] ??
      req.headers["x-vercel-ip-country"] ??
      req.headers["cloudfront-viewer-country"],
  );

  const locationParts = [city, region, country].filter(
    (part, index, parts): part is string =>
      Boolean(part) &&
      parts.findIndex((candidate) => candidate === part) === index,
  );
  if (locationParts.length) {
    return locationParts.join(", ");
  }

  const ipAddress = getRequestIp(req);
  if (!ipAddress) return undefined;
  if (ipAddress === "127.0.0.1") return "Local device";
  if (isPrivateOrLoopbackIpAddress(ipAddress)) return "Private network";
  return undefined;
};

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
  budgetPlan?: PublicBudgetPlanSummary | null;
};

type StoredBudgetPlanCategory = {
  key: string;
  label: string;
  share: number;
  amount: number;
  trackingKeys?: SpendingCategoryKey[];
  thresholdAlertsSent?: string[];
};

type StoredBudgetPlan = {
  planId: string;
  status: "ACTIVE" | "EXPIRED";
  period: "MONTHLY";
  currency: string;
  planningMode: "spend_cap" | "savings_goal";
  targetAmount: number;
  savingsGoalAmount: number | null;
  incomeBaselineAmount: number | null;
  spentAmount: number;
  remainingAmount: number;
  utilizationRatio: number;
  warningThreshold: number;
  criticalThreshold: number;
  thresholdAlertsSent: string[];
  startAt: string;
  endAt: string;
  createdAt: string;
  updatedAt: string;
  lastEvaluatedAt: string;
  sourcePrompt: string;
  dailyCapRemaining: number | null;
  weeklyCapRemaining: number | null;
  categories: StoredBudgetPlanCategory[];
  emailAlertsEnabled: boolean;
};

type PublicBudgetPlanSummary = {
  planId: string;
  status: "ACTIVE" | "EXPIRED";
  period: "MONTHLY";
  currency: string;
  planningMode: "spend_cap" | "savings_goal";
  targetAmount: number;
  savingsGoalAmount: number | null;
  incomeBaselineAmount: number | null;
  spentAmount: number;
  remainingAmount: number;
  utilizationRatio: number;
  warningThreshold: number;
  criticalThreshold: number;
  startAt: string;
  endAt: string;
  createdAt: string;
  updatedAt: string;
  lastEvaluatedAt: string;
  dailyCapRemaining: number | null;
  weeklyCapRemaining: number | null;
  categories: StoredBudgetPlanCategory[];
  emailAlertsEnabled: boolean;
};

type StoredBudgetAssistantPreferences = {
  proactiveRemindersEnabled: boolean;
  dailyDigestEnabled: boolean;
  weeklyDigestEnabled: boolean;
  monthlyDigestEnabled: boolean;
  digestDeliveryChannel: "email";
};

type StoredBudgetAssistantAutomationState = {
  lastDailyDigestKey: string | null;
  lastWeeklyDigestKey: string | null;
  lastMonthlyDigestKey: string | null;
  lastPacingReminderKey: string | null;
};

type SpendingCategoryKey =
  | "food"
  | "transport"
  | "bills"
  | "shopping"
  | "transfers"
  | "education_health"
  | "other";

type SpendingCategorySummary = {
  key: SpendingCategoryKey;
  label: string;
  amount: number;
  count: number;
  shareOfSpend: number;
  capAmount: number | null;
  utilizationRatio: number | null;
  warningState: "ok" | "warning" | "over";
};

type CopilotIntent =
  | "finance_education"
  | "market_data"
  | "portfolio_analysis"
  | "spending_analysis"
  | "budgeting_help"
  | "transaction_review"
  | "anomaly_check"
  | "unsupported";

type CopilotIntentTool =
  | "wallet_summary"
  | "wallet_transactions"
  | "market_quote"
  | "security_signals";

type CopilotIntentClassification = {
  intent: CopilotIntent;
  needs_tools: boolean;
  required_tools: CopilotIntentTool[];
  reason: string;
};

type StoredCopilotSessionState = {
  messages: CopilotMessagePayload[];
  insight: {
    topic: string;
    suggestedActions: string[];
    suggestedDepositAmount: number | null;
    riskLevel: string;
    confidence: number;
    followUpQuestion: string | null;
  };
};

type StoredCopilotConversation = StoredCopilotSessionState & {
  id: string;
  title: string;
  pinned: boolean;
  createdAt: string;
  updatedAt: string;
};

type StoredCopilotWorkspaceState = {
  activeSessionId: string;
  sessions: StoredCopilotConversation[];
};

type MarketQuoteSnapshot = {
  symbol: string;
  label: string;
  assetClass: MarketIntent["assetClass"];
  price: number;
  currency: string;
  previousClose: number | null;
  change: number | null;
  changePercent: number | null;
  exchangeName: string | null;
  marketState: string | null;
  asOf: Date;
  source: string;
};

type MarketAnalysisSnapshot = MarketQuoteSnapshot & {
  oneYearStartPrice: number | null;
  oneYearChange: number | null;
  oneYearChangePercent: number | null;
};

const openaiClient = OPENAI_API_KEY
  ? new OpenAI({ apiKey: OPENAI_API_KEY })
  : null;

type OpenAiCopilotResult =
  | { status: "disabled" }
  | { status: "ok"; payload: CopilotResponsePayload }
  | {
      status: "error";
      code: string;
      message: string;
    };

type OllamaCopilotResult =
  | { status: "disabled" }
  | { status: "ok"; payload: CopilotResponsePayload }
  | {
      status: "error";
      code: string;
      message: string;
    };

type OpenAiCopilotClassificationResult =
  | { status: "disabled" }
  | { status: "ok"; payload: CopilotIntentClassification }
  | {
      status: "error";
      code: string;
      message: string;
    };

type OllamaCopilotClassificationResult =
  | { status: "disabled" }
  | { status: "ok"; payload: CopilotIntentClassification }
  | {
      status: "error";
      code: string;
      message: string;
    };

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const buildDefaultStoredCopilotSession = (): StoredCopilotSessionState => ({
  messages: [
    {
      role: "assistant",
      content:
        "Ask me anything about spending, savings, transfers, statements, scams, or market decisions. I will use your wallet context when it helps.",
    },
  ],
  insight: {
    topic: "",
    suggestedActions: [],
    suggestedDepositAmount: null,
    riskLevel: "low",
    confidence: 0,
    followUpQuestion: null,
  },
});

const buildDefaultStoredCopilotConversation = (): StoredCopilotConversation => {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    title: "New Conversation",
    pinned: false,
    createdAt: now,
    updatedAt: now,
    ...buildDefaultStoredCopilotSession(),
  };
};

const buildDefaultStoredCopilotWorkspace = (): StoredCopilotWorkspaceState => {
  const session = buildDefaultStoredCopilotConversation();
  return {
    activeSessionId: session.id,
    sessions: [session],
  };
};

const sanitizeStoredCopilotMessages = (value: unknown) => {
  const messages = Array.isArray(value)
    ? value.filter(
        (item): item is CopilotMessagePayload =>
          isPlainObject(item) &&
          (item.role === "user" ||
            item.role === "assistant" ||
            item.role === "system") &&
          typeof item.content === "string" &&
          item.content.trim().length > 0,
      )
    : [];

  return messages.slice(-40).map((message) => ({
    role: message.role,
    content: message.content.trim().slice(0, 8000),
  }));
};

const sanitizeStoredCopilotInsight = (
  value: unknown,
): StoredCopilotSessionState["insight"] => {
  const raw = isPlainObject(value) ? value : {};
  const suggestedActions = Array.isArray(raw.suggestedActions)
    ? raw.suggestedActions
        .filter((item): item is string => typeof item === "string")
        .map((item) => item.trim())
        .filter(Boolean)
        .slice(0, 6)
    : [];

  return {
    topic: typeof raw.topic === "string" ? raw.topic.trim().slice(0, 120) : "",
    suggestedActions,
    suggestedDepositAmount:
      typeof raw.suggestedDepositAmount === "number" &&
      Number.isFinite(raw.suggestedDepositAmount)
        ? raw.suggestedDepositAmount
        : null,
    riskLevel: normalizeCopilotRiskLevel(raw.riskLevel),
    confidence: clamp(Number(raw.confidence || 0), 0, 1),
    followUpQuestion:
      typeof raw.followUpQuestion === "string" && raw.followUpQuestion.trim()
        ? raw.followUpQuestion.trim().slice(0, 240)
        : null,
  };
};

const sanitizeStoredCopilotSession = (
  value: unknown,
): StoredCopilotSessionState => {
  const defaults = buildDefaultStoredCopilotSession();
  const raw = isPlainObject(value) ? value : {};
  const messages = sanitizeStoredCopilotMessages(raw.messages);

  return {
    messages: messages.length ? messages : defaults.messages,
    insight: sanitizeStoredCopilotInsight(raw.insight),
  };
};

const sanitizeStoredCopilotConversation = (
  value: unknown,
): StoredCopilotConversation | null => {
  const raw = isPlainObject(value) ? value : null;
  if (!raw) return null;
  const base = sanitizeStoredCopilotSession(raw);
  const now = new Date().toISOString();
  const id =
    typeof raw.id === "string" && raw.id.trim()
      ? raw.id.trim().slice(0, 80)
      : crypto.randomUUID();
  const title =
    typeof raw.title === "string" && raw.title.trim()
      ? raw.title.trim().slice(0, 120)
      : "New Conversation";
  const pinned = Boolean(raw.pinned);
  const createdAt =
    typeof raw.createdAt === "string" && raw.createdAt.trim()
      ? raw.createdAt
      : now;
  const updatedAt =
    typeof raw.updatedAt === "string" && raw.updatedAt.trim()
      ? raw.updatedAt
      : now;

  return {
    id,
    title,
    pinned,
    createdAt,
    updatedAt,
    ...base,
  };
};

const sanitizeStoredCopilotWorkspace = (
  value: unknown,
): StoredCopilotWorkspaceState => {
  const defaults = buildDefaultStoredCopilotWorkspace();
  const raw = isPlainObject(value) ? value : {};

  if (
    Array.isArray(raw.messages) ||
    isPlainObject(raw.insight) ||
    typeof raw.topic === "string"
  ) {
    const legacySession = sanitizeStoredCopilotConversation({
      id: crypto.randomUUID(),
      title: "Recovered Conversation",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      messages: raw.messages,
      insight: raw.insight ?? raw,
    });

    return legacySession
      ? {
          activeSessionId: legacySession.id,
          sessions: [legacySession],
        }
      : defaults;
  }

  const sessions = Array.isArray(raw.sessions)
    ? raw.sessions
        .map((session) => sanitizeStoredCopilotConversation(session))
        .filter((session): session is StoredCopilotConversation =>
          Boolean(session),
        )
        .slice(0, 20)
    : [];

  const nextSessions = sessions.length ? sessions : defaults.sessions;
  const activeSessionId =
    typeof raw.activeSessionId === "string" &&
    nextSessions.some((session) => session.id === raw.activeSessionId)
      ? raw.activeSessionId
      : nextSessions[0].id;

  return {
    activeSessionId,
    sessions: nextSessions,
  };
};

const readStoredCopilotWorkspaceFromMetadata = (
  metadata: unknown,
): StoredCopilotWorkspaceState => {
  if (!isPlainObject(metadata)) {
    return buildDefaultStoredCopilotWorkspace();
  }
  return sanitizeStoredCopilotWorkspace(
    metadata.copilotWorkspace ?? metadata.copilotSession,
  );
};

type CopilotLanguage = "vi" | "en";

type AiOverviewResponse = {
  status: {
    modelLoaded: boolean;
    modelVersion?: string | null;
    modelSource?: string | null;
    txModelLoaded: boolean;
    txModelVersion?: string | null;
    txModelSource?: string | null;
    mongoConnected: boolean;
    authMode?: string | null;
  };
  stats: {
    windowHours: number;
    loginRiskCounts: Record<string, number>;
    txRiskCounts: Record<string, number>;
    combinedRiskCounts: Record<string, number>;
  };
};

const DEFAULT_SECURITY_POLICY = getDefaultSecurityPolicy();

const buildAiServiceHeaders = (extra?: Record<string, string>) => ({
  "Content-Type": "application/json",
  "X-AI-API-KEY": AI_API_KEY,
  ...(extra || {}),
});

const buildStoredAiMonitoring = (input: AnomalyResponse) => ({
  score: input.score,
  riskLevel: input.riskLevel,
  reasons: input.reasons,
  monitoringOnly: input.monitoringOnly,
  action: input.action ?? null,
  requireOtp: input.requireOtp,
  otpChannel: input.otpChannel ?? null,
  otpReason: input.otpReason ?? null,
  modelSource: input.modelSource ?? null,
  modelVersion: input.modelVersion ?? null,
  requestKey: input.requestKey ?? null,
  baseScore: input.baseScore ?? null,
  finalScore: input.finalScore ?? null,
  mitigationScore: input.mitigationScore ?? null,
  mitigationReasons: input.mitigationReasons ?? [],
  counterArguments: input.counterArguments ?? [],
  accountSegment: input.accountSegment ?? null,
  accountCategory: input.accountCategory ?? null,
  accountTier: input.accountTier ?? null,
  accountProfileCode: input.accountProfileCode ?? null,
  accountProfileStatus: input.accountProfileStatus ?? null,
  accountProfileConfidence: input.accountProfileConfidence ?? null,
  decisionComponents: input.decisionComponents ?? null,
  adminSummary: input.adminSummary ?? null,
  analysisSignals: input.analysisSignals ?? null,
  inputContract: input.inputContract ?? null,
  mlAnalysis: input.mlAnalysis ?? null,
  llmAnalysis: input.llmAnalysis ?? null,
  finalDecision: input.finalDecision ?? null,
  scoredAt: new Date().toISOString(),
});

type FundsFlowLifecycle =
  | "STARTED"
  | "PENDING_OTP"
  | "REVIEW_REQUIRED"
  | "BLOCKED"
  | "CANCELLED"
  | "OTP_VERIFIED"
  | "COMPLETED";

type FundsFlowDirection = "INFLOW" | "OUTFLOW";

type FundsFlowChannel = "WALLET_TRANSFER" | "WALLET_DEPOSIT" | "ADMIN_TOPUP";

type FundsFlowDatasetRow = {
  id: string;
  createdAt: string;
  actor: string;
  userId: string | null;
  ipAddress: string | null;
  channel: FundsFlowChannel;
  lifecycle: FundsFlowLifecycle;
  direction: FundsFlowDirection;
  amount: number;
  currency: string;
  fromAccount: string | null;
  toAccount: string | null;
  fromUserId: string | null;
  toUserId: string | null;
  transactionId: string | null;
  reconciliationId: string | null;
  requestKey: string | null;
  note: string | null;
  sourceLabel: string | null;
  recipientKnown: boolean | null;
  riskLevel: string | null;
  riskScore: number | null;
  balanceBefore: number | null;
  balanceAfter: number | null;
};

const FUNDS_FLOW_DATASET_LIMIT_MAX = 5000;

const logFundsFlowEvent = async (input: {
  actor?: string;
  userId?: string;
  ipAddress?: string;
  channel: FundsFlowChannel;
  lifecycle: FundsFlowLifecycle;
  direction: FundsFlowDirection;
  amount: number;
  currency: string;
  fromAccount?: string | null;
  toAccount?: string | null;
  fromUserId?: string | null;
  toUserId?: string | null;
  transactionId?: string | null;
  reconciliationId?: string | null;
  challengeId?: string | null;
  requestKey?: string | null;
  note?: string | null;
  sourceLabel?: string | null;
  recipientKnown?: boolean | null;
  riskLevel?: string | null;
  riskScore?: number | null;
  transferAdvisory?: TransferSafetyAdvisory | null;
  aiMonitoring?: AnomalyResponse | null;
  balanceBefore?: number | null;
  balanceAfter?: number | null;
}) => {
  await logAuditEvent({
    actor: input.actor,
    userId: input.userId,
    ipAddress: input.ipAddress,
    action: "FUNDS_FLOW_EVENT",
    details: {
      channel: input.channel,
      lifecycle: input.lifecycle,
      direction: input.direction,
      amount: roundMoney(input.amount),
      currency: input.currency,
      fromAccount: input.fromAccount || null,
      toAccount: input.toAccount || null,
      sourceLabel: input.sourceLabel || null,
    },
    metadata: {
      category: "funds_flow_training",
      channel: input.channel,
      lifecycle: input.lifecycle,
      direction: input.direction,
      amount: roundMoney(input.amount),
      currency: input.currency,
      fromAccount: input.fromAccount || null,
      toAccount: input.toAccount || null,
      fromUserId: input.fromUserId || null,
      toUserId: input.toUserId || null,
      transactionId: input.transactionId || null,
      reconciliationId: input.reconciliationId || null,
      challengeId: input.challengeId || null,
      requestKey: input.requestKey || null,
      note: input.note || null,
      sourceLabel: input.sourceLabel || null,
      recipientKnown: input.recipientKnown ?? null,
      riskLevel: input.riskLevel || null,
      riskScore:
        typeof input.riskScore === "number"
          ? clamp(input.riskScore, 0, 1)
          : null,
      balanceBefore:
        typeof input.balanceBefore === "number"
          ? roundMoney(input.balanceBefore)
          : null,
      balanceAfter:
        typeof input.balanceAfter === "number"
          ? roundMoney(input.balanceAfter)
          : null,
      transferAdvisory: input.transferAdvisory || undefined,
      aiMonitoring: input.aiMonitoring
        ? buildStoredAiMonitoring(input.aiMonitoring)
        : undefined,
      observedAt: new Date().toISOString(),
    },
  });
};

const parseFundsFlowListFilter = (value: unknown) =>
  typeof value === "string"
    ? value
        .split(",")
        .map((item) => item.trim().toUpperCase())
        .filter(Boolean)
    : [];

const formatCsvValue = (value: unknown) => {
  if (value === null || value === undefined) return "";
  const text =
    typeof value === "string"
      ? value
      : typeof value === "number" || typeof value === "boolean"
        ? String(value)
        : JSON.stringify(value);
  const escaped = text.replace(/"/g, '""');
  return /[",\n]/.test(escaped) ? `"${escaped}"` : escaped;
};

const toFundsFlowDatasetRow = (log: {
  id: string;
  actor: string;
  userId: string | null;
  ipAddress: string | null;
  createdAt: Date;
  metadata: unknown;
}): FundsFlowDatasetRow | null => {
  const metadata = normalizeMetadataRecord(log.metadata);
  const channel = metadata.channel;
  const lifecycle = metadata.lifecycle;
  const direction = metadata.direction;
  const amount = typeof metadata.amount === "number" ? metadata.amount : null;
  const currency =
    typeof metadata.currency === "string" ? metadata.currency : null;

  if (
    (channel !== "WALLET_TRANSFER" &&
      channel !== "WALLET_DEPOSIT" &&
      channel !== "ADMIN_TOPUP") ||
    (lifecycle !== "PENDING_OTP" &&
      lifecycle !== "REVIEW_REQUIRED" &&
      lifecycle !== "BLOCKED" &&
      lifecycle !== "OTP_VERIFIED" &&
      lifecycle !== "COMPLETED") ||
    (direction !== "INFLOW" && direction !== "OUTFLOW") ||
    amount === null ||
    currency === null
  ) {
    return null;
  }

  return {
    id: log.id,
    createdAt: log.createdAt.toISOString(),
    actor: log.actor,
    userId: log.userId,
    ipAddress: log.ipAddress,
    channel,
    lifecycle,
    direction,
    amount: roundMoney(amount),
    currency,
    fromAccount:
      typeof metadata.fromAccount === "string" ? metadata.fromAccount : null,
    toAccount:
      typeof metadata.toAccount === "string" ? metadata.toAccount : null,
    fromUserId:
      typeof metadata.fromUserId === "string" ? metadata.fromUserId : null,
    toUserId: typeof metadata.toUserId === "string" ? metadata.toUserId : null,
    transactionId:
      typeof metadata.transactionId === "string"
        ? metadata.transactionId
        : null,
    reconciliationId:
      typeof metadata.reconciliationId === "string"
        ? metadata.reconciliationId
        : null,
    requestKey:
      typeof metadata.requestKey === "string" ? metadata.requestKey : null,
    note: typeof metadata.note === "string" ? metadata.note : null,
    sourceLabel:
      typeof metadata.sourceLabel === "string" ? metadata.sourceLabel : null,
    recipientKnown:
      typeof metadata.recipientKnown === "boolean"
        ? metadata.recipientKnown
        : null,
    riskLevel:
      typeof metadata.riskLevel === "string" ? metadata.riskLevel : null,
    riskScore:
      typeof metadata.riskScore === "number"
        ? clamp(metadata.riskScore, 0, 1)
        : null,
    balanceBefore:
      typeof metadata.balanceBefore === "number"
        ? roundMoney(metadata.balanceBefore)
        : null,
    balanceAfter:
      typeof metadata.balanceAfter === "number"
        ? roundMoney(metadata.balanceAfter)
        : null,
  };
};

const buildTxTrainingEventFromFundsFlowLog = (log: {
  id: string;
  userId: string | null;
  createdAt: Date;
  metadata: unknown;
}) => {
  const metadata = normalizeMetadataRecord(log.metadata);
  if (
    metadata.channel !== "WALLET_TRANSFER" ||
    metadata.direction !== "OUTFLOW" ||
    metadata.lifecycle !== "COMPLETED"
  ) {
    return null;
  }

  const aiMonitoring = normalizeRecord(metadata.aiMonitoring);
  const analysisSignals = normalizeRecord(aiMonitoring.analysisSignals);
  const amount =
    (typeof metadata.amount === "number" ? metadata.amount : null) ??
    asNumberOrNull(analysisSignals.amount);
  const currency =
    (typeof metadata.currency === "string" ? metadata.currency : null) ??
    asStringOrNull(analysisSignals.currency);
  const userId =
    (typeof metadata.fromUserId === "string" ? metadata.fromUserId : null) ??
    log.userId;
  if (!userId || amount === null || !currency) return null;

  return {
    userId,
    transactionId:
      (typeof metadata.transactionId === "string"
        ? metadata.transactionId
        : null) || log.id,
    requestId:
      typeof metadata.requestKey === "string" ? metadata.requestKey : log.id,
    timestamp:
      (typeof metadata.observedAt === "string" ? metadata.observedAt : null) ??
      log.createdAt.toISOString(),
    amount,
    currency,
    location:
      asStringOrNull(analysisSignals.country) ??
      asStringOrNull(analysisSignals.location) ??
      "UNK",
    paymentMethod:
      asStringOrNull(analysisSignals.payment_method) ?? "wallet_balance",
    merchantCategory:
      asStringOrNull(analysisSignals.merchant_category) ?? "p2p_transfer",
    accountSegment:
      asStringOrNull(analysisSignals.account_segment) ?? "PERSONAL",
    accountCategory:
      asStringOrNull(analysisSignals.account_category) ?? "PERSONAL",
    accountTier: asStringOrNull(analysisSignals.account_tier) ?? "STANDARD",
    accountProfileStatus:
      asStringOrNull(analysisSignals.account_profile_status) ??
      asStringOrNull(aiMonitoring.accountProfileStatus) ??
      "SYSTEM_ASSIGNED",
    accountProfileConfidence:
      asNumberOrNull(analysisSignals.account_profile_confidence) ??
      asNumberOrNull(aiMonitoring.accountProfileConfidence) ??
      0.6,
    device: "",
    channel: "web",
    failedTx24h: asNumberOrNull(analysisSignals.failed_tx_24h) ?? 0,
    velocity1h: asNumberOrNull(analysisSignals.velocity_1h) ?? 0,
    dailySpendAvg30d: asNumberOrNull(analysisSignals.daily_spend_avg_30d) ?? 0,
    todaySpendBefore: asNumberOrNull(analysisSignals.today_spend_before) ?? 0,
    projectedDailySpend:
      asNumberOrNull(analysisSignals.projected_daily_spend) ?? amount,
    balanceBefore:
      (typeof metadata.balanceBefore === "number"
        ? metadata.balanceBefore
        : null) ??
      asNumberOrNull(analysisSignals.balance_before) ??
      amount,
    remainingBalance:
      (typeof metadata.balanceAfter === "number"
        ? metadata.balanceAfter
        : null) ??
      asNumberOrNull(analysisSignals.remaining_balance) ??
      0,
    recipientKnown:
      typeof metadata.recipientKnown === "boolean"
        ? metadata.recipientKnown
        : Boolean(analysisSignals.recipient_known),
    suspiciousNoteCount:
      asNumberOrNull(analysisSignals.suspicious_note_count) ?? 0,
    rollingOutflowAmount:
      asNumberOrNull(analysisSignals.rolling_outflow_amount) ?? amount,
    faceIdRequired: Boolean(analysisSignals.face_id_required),
    sessionRestrictLargeTransfers: Boolean(
      analysisSignals.session_restrict_large_transfers,
    ),
    recentReviewCount30d:
      asNumberOrNull(analysisSignals.recent_review_count_30d) ?? 0,
    recentBlockedCount30d:
      asNumberOrNull(analysisSignals.recent_blocked_count_30d) ?? 0,
    recentPendingOtpCount7d:
      asNumberOrNull(analysisSignals.recent_pending_otp_count_7d) ?? 0,
    smallProbeCount24h:
      asNumberOrNull(analysisSignals.small_probe_count_24h) ?? 0,
    smallProbeTotal24h:
      asNumberOrNull(analysisSignals.small_probe_total_24h) ?? 0,
    distinctSmallProbeRecipients24h:
      asNumberOrNull(analysisSignals.distinct_small_probe_recipients_24h) ?? 0,
    sameRecipientSmallProbeCount24h:
      asNumberOrNull(analysisSignals.same_recipient_small_probe_count_24h) ?? 0,
    newRecipientSmallProbeCount24h:
      asNumberOrNull(analysisSignals.new_recipient_small_probe_count_24h) ?? 0,
    probeThenLargeRiskScore:
      asNumberOrNull(analysisSignals.probe_then_large_risk_score) ?? 0,
    llmNoteRiskLevel: "LOW",
    llmSignalCount: 0,
    llmRuleTags: [],
    sessionRiskLevel:
      asStringOrNull(analysisSignals.session_risk_level) ?? "LOW",
  };
};

const buildCompletedTransferReplayResponseFromLog = (log: {
  id: string;
  createdAt: Date;
  metadata: unknown;
}) => {
  const metadata = normalizeMetadataRecord(log.metadata);
  const aiMonitoring = normalizeAiResponse(metadata.aiMonitoring);
  const amount = typeof metadata.amount === "number" ? metadata.amount : 0;
  const toAccount =
    typeof metadata.toAccount === "string" ? metadata.toAccount : "";
  const transactionId =
    typeof metadata.transactionId === "string"
      ? metadata.transactionId
      : log.id;
  const note = typeof metadata.note === "string" ? metadata.note : "";
  const reconciliationId =
    typeof metadata.reconciliationId === "string"
      ? metadata.reconciliationId
      : null;

  return {
    status: "ok" as const,
    otpRequired: false,
    transferPinVerified: true,
    idempotentReplay: true,
    reconciliationId,
    anomaly: aiMonitoring,
    transaction: {
      id: transactionId,
      amount,
      type: "TRANSFER" as const,
      description: note || `Transfer to ${toAccount}`,
      createdAt: log.createdAt.toISOString(),
      toAccount,
    },
  };
};

const findCompletedTransferReplayResponse = async (input: {
  userId: string;
  challengeId?: string | null;
  requestKey?: string | null;
}) => {
  const identityFilters: Array<Record<string, unknown>> = [];
  if (input.challengeId) {
    identityFilters.push({
      metadata: {
        path: ["challengeId"],
        equals: input.challengeId,
      },
    });
  }
  if (input.requestKey) {
    identityFilters.push({
      metadata: {
        path: ["requestKey"],
        equals: input.requestKey,
      },
    });
  }
  if (identityFilters.length === 0) return null;

  const completedEvent = await prisma.auditLog.findFirst({
    where: {
      userId: input.userId,
      action: "FUNDS_FLOW_EVENT",
      AND: [
        {
          metadata: {
            path: ["channel"],
            equals: "WALLET_TRANSFER",
          },
        },
        {
          metadata: {
            path: ["direction"],
            equals: "OUTFLOW",
          },
        },
        {
          metadata: {
            path: ["lifecycle"],
            equals: "COMPLETED",
          },
        },
        {
          metadata: {
            path: ["sourceLabel"],
            equals: "TRANSFER_CONFIRMED",
          },
        },
        identityFilters.length === 1
          ? identityFilters[0]
          : { OR: identityFilters },
      ],
    },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      createdAt: true,
      metadata: true,
    },
  });

  return completedEvent
    ? buildCompletedTransferReplayResponseFromLog(completedEvent)
    : null;
};

const findCompletedTransferReplayResponseByChallenge = async (input: {
  userId: string;
  challengeId: string;
}) => {
  const challenge = await prisma.otpChallenge.findFirst({
    where: {
      id: input.challengeId,
      userId: input.userId,
      purpose: "TRANSFER",
      channel: "EMAIL",
    },
    select: {
      metadata: true,
    },
  });
  const challengeMetadata = normalizeMetadataRecord(challenge?.metadata);
  const requestKey =
    typeof challengeMetadata.requestKey === "string"
      ? challengeMetadata.requestKey
      : null;

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const replayResponse = await findCompletedTransferReplayResponse({
      userId: input.userId,
      challengeId: input.challengeId,
      requestKey,
    });
    if (replayResponse) {
      return replayResponse;
    }
    if (attempt < 3) {
      await sleep(150);
    }
  }

  return null;
};

const buildTxRetrainDataset = async (limit: number) => {
  const suspiciousAlerts = await prisma.auditLog.findMany({
    where: {
      action: "AI_TRANSACTION_ALERT",
    },
    orderBy: { createdAt: "desc" },
    take: Math.max(limit * 2, 400),
    select: {
      details: true,
      metadata: true,
    },
  });
  const excludedTransactionIds = new Set<string>();
  for (const alert of suspiciousAlerts) {
    const details = normalizeRecord(alert.details);
    const metadata = normalizeRecord(alert.metadata);
    const adminStatus = normalizeAdminAlertStatus(
      details.adminStatus ?? metadata.adminStatus,
    );
    if (adminStatus !== "confirmed_risk" && adminStatus !== "escalated") {
      continue;
    }
    const transactionId =
      asStringOrNull(details.transactionId) ??
      asStringOrNull(metadata.transactionId);
    if (transactionId) {
      excludedTransactionIds.add(transactionId);
    }
  }

  const logs = await prisma.auditLog.findMany({
    where: {
      action: "FUNDS_FLOW_EVENT",
    },
    orderBy: { createdAt: "desc" },
    take: Math.max(limit * 3, 600),
    select: {
      id: true,
      userId: true,
      createdAt: true,
      metadata: true,
    },
  });

  const events = logs
    .map(buildTxTrainingEventFromFundsFlowLog)
    .filter((event): event is NonNullable<typeof event> => Boolean(event))
    .filter((event) => !excludedTransactionIds.has(event.transactionId))
    .slice(0, limit);

  return {
    events,
    excludedFlaggedCount: excludedTransactionIds.size,
    rawCount: logs.length,
  };
};

const clamp = (value: number, min: number, max: number) =>
  Math.min(max, Math.max(min, value));

const roundMoney = (value: number) => Math.round(value * 100) / 100;

const formatRetryWait = (seconds: number) => {
  const safeSeconds = Math.max(1, Math.ceil(seconds));
  const minutes = Math.floor(safeSeconds / 60);
  const remainingSeconds = safeSeconds % 60;
  if (minutes <= 0) {
    return `${remainingSeconds} second${remainingSeconds === 1 ? "" : "s"}`;
  }
  if (remainingSeconds === 0) {
    return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  }
  return `${minutes} minute${minutes === 1 ? "" : "s"} ${remainingSeconds} second${remainingSeconds === 1 ? "" : "s"}`;
};

const formatMoneyAmount = (currency: string, amount: number) =>
  `${currency} ${roundMoney(Math.max(0, amount)).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;

const normalizeMetadataRecord = (value: unknown) =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const suspiciousTransferNotePatterns: Array<{
  pattern: RegExp;
  reason: string;
}> = [
  {
    pattern:
      /\b(urgent|immediately|right now|act now|safe account|security team|unlock|verify|verification fee|release funds|refund|customs|tax|penalty)\b/i,
    reason:
      "Transfer note contains urgency or account-verification wording often used in scams.",
  },
  {
    pattern:
      /\b(invest|investment|profit|guaranteed return|crypto signal|forex|broker|loan fee|commission)\b/i,
    reason:
      "Transfer note references high-pressure investing or fee collection language.",
  },
  {
    pattern:
      /\b(khan cap|gap|chuyen ngay|tai khoan an toan|tai khoan bao mat|xac minh|phi mo khoa|hoan tien|hai quan|thue|phat)\b/i,
    reason:
      "Transfer note contains urgent or account-verification terms commonly seen in scams.",
  },
  {
    pattern:
      /\b(chuyen tien dieu tra|phuc vu dieu tra|co quan dieu tra|cong an dieu tra|vien kiem sat|toa an|ho so vu an|vu an|phong toa tai khoan|tai khoan bi phong toa|tai khoan lien quan dieu tra|tai khoan lien quan vu an|kiem tra dong tien|ra soat dong tien|xac minh nguon tien|chuyen tien xac minh|chuyen tien chung minh trong sach)\b/i,
    reason:
      "Transfer note references investigation, account-freeze, or law-enforcement wording often used in impersonation scams.",
  },
  {
    pattern:
      /\b(dau tu|loi nhuan|bao lai|tin hieu|san forex|phi vay|hoa hong)\b/i,
    reason:
      "Transfer note references investment or fee-collection language often used in fraud.",
  },
];

const transferNoteLlmAnalysisSchema = z.object({
  riskLevel: z.enum(["low", "medium", "high"]).default("low"),
  signals: z.array(z.string().min(1).max(180)).max(6).default([]),
  ruleTags: z.array(z.string().min(1).max(48)).max(6).default([]),
  summary: z.string().max(240).nullable().optional(),
  purposeTags: z.array(z.string().min(1).max(48)).max(4).default([]),
  purposeConfidence: z.number().min(0).max(1).default(0),
});

const transferNoteLlmCache = new Map<
  string,
  { expiresAt: number; value: TransferNoteLlmAnalysis }
>();

const normalizeTransferNoteForPatternMatch = (value: string) =>
  value
    .trim()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[đĐ]/g, "d")
    .toLowerCase();

const legitimateHighValueTransferPurposePatterns = [
  {
    pattern:
      /\b(mua nha|mua can ho|mua chung cu|mua dat|mua bat dong san|mua bds|chuyen tien mua nha|chuyen tien mua dat)\b/i,
    tag: "home_purchase",
  },
  {
    pattern:
      /\b(home purchase|house purchase|property purchase|real estate purchase|buying a house|buying a home|buy home|buy house|buy property|buy apartment|buy condo)\b/i,
    tag: "home_purchase",
  },
  {
    pattern:
      /\b(coc nha|dat coc nha|tien coc nha|coc can ho|dat coc can ho|tien coc can ho|coc dat|dat coc dat|tien coc dat|giu cho can ho|giu cho nha)\b/i,
    tag: "property_deposit",
  },
  {
    pattern:
      /\b(down payment|house deposit|home deposit|property deposit|apartment deposit|condo deposit|earnest money|reservation fee|booking fee)\b/i,
    tag: "property_deposit",
  },
  {
    pattern:
      /\b(escrow|closing payment|mortgage closing|settlement statement|title company)\b/i,
    tag: "mortgage_closing",
  },
];

const normalizeTransferNotePurposeTag = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_\s-]/g, "")
    .replace(/[\s-]+/g, "_")
    .replace(/^_+|_+$/g, "");

const getLegitimateTransferPurposeTags = (note: string) => {
  const normalizedNote = normalizeTransferNoteForPatternMatch(note);
  if (!normalizedNote) return [] as string[];
  return dedupeStringList(
    legitimateHighValueTransferPurposePatterns
      .filter((entry) => entry.pattern.test(normalizedNote))
      .map((entry) => entry.tag),
  );
};

const buildTransferNoteHeuristicAnalysis = (input: {
  note: string;
  suspiciousReasons: string[];
}): TransferNoteLlmAnalysis => {
  const signals = dedupeStringList(input.suspiciousReasons).slice(0, 6);
  const purposeTags = getLegitimateTransferPurposeTags(input.note).slice(0, 4);
  const riskLevel =
    signals.length >= 2 ? "high" : signals.length >= 1 ? "medium" : "low";
  return {
    riskLevel,
    signals,
    ruleTags: signals.length ? ["regex_suspicious_note"] : [],
    summary: signals[0] || null,
    purposeTags,
    purposeConfidence:
      purposeTags.length > 0 && signals.length === 0 ? 0.82 : 0,
    source: "heuristic",
    model: null,
  };
};

const getSuspiciousTransferNoteReasons = (note: string) => {
  const normalizedNote = normalizeTransferNoteForPatternMatch(note);
  if (!normalizedNote) return [];
  return suspiciousTransferNotePatterns
    .filter((entry) => entry.pattern.test(normalizedNote))
    .map((entry) => entry.reason);
};

const buildTransferNoteLlmCacheKey = (input: {
  note: string;
  amount: number;
  currency: string;
  accountCategory: "personal" | "business";
  accountSegment: "personal" | "sme" | "enterprise";
  recipientKnown: boolean;
  balanceImpactRatio: number;
  sessionRiskLevel: "low" | "medium" | "high";
  velocity1h: number;
  recentReviewCount30d: number;
  recentBlockedCount30d: number;
  spendSurgeRatio: number | null;
}) =>
  crypto
    .createHash("sha256")
    .update(
      JSON.stringify({
        note: input.note.trim().toLowerCase(),
        amountBucket: roundMoney(Math.max(0, input.amount)),
        currency: input.currency.trim().toUpperCase(),
        accountCategory: input.accountCategory,
        accountSegment: input.accountSegment,
        recipientKnown: input.recipientKnown,
        balanceImpactBucket: roundMoney(
          clamp(input.balanceImpactRatio, 0, 1.5),
        ),
        sessionRiskLevel: input.sessionRiskLevel,
        velocity1h: Math.max(0, Math.round(input.velocity1h)),
        recentReviewCount30d: Math.max(
          0,
          Math.round(input.recentReviewCount30d),
        ),
        recentBlockedCount30d: Math.max(
          0,
          Math.round(input.recentBlockedCount30d),
        ),
        spendSurgeBucket:
          input.spendSurgeRatio === null
            ? null
            : roundMoney(Math.max(0, input.spendSurgeRatio)),
      }),
    )
    .digest("hex");

const extractJsonObject = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const fencedMatch = trimmed.match(/```(?:json)?\s*([\s\S]+?)```/i);
  const candidate = fencedMatch?.[1]?.trim() || trimmed;
  const firstBrace = candidate.indexOf("{");
  const lastBrace = candidate.lastIndexOf("}");
  if (firstBrace < 0 || lastBrace <= firstBrace) return null;
  return candidate.slice(firstBrace, lastBrace + 1);
};

const normalizeTransferNoteRuleTag = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_\s-]/g, "")
    .replace(/[\s-]+/g, "_")
    .replace(/^_+|_+$/g, "");

const analyzeTransferNoteWithLlm = async (
  input: TransferRiskLlmContextInput,
): Promise<TransferNoteLlmAnalysis> => {
  const note = input.note.trim();
  const suspiciousReasons = getSuspiciousTransferNoteReasons(note);
  const heuristic = buildTransferNoteHeuristicAnalysis({
    note,
    suspiciousReasons,
  });

  if (!note || isGenericTransferNote(note)) {
    return heuristic;
  }
  if (
    !ENABLE_TRANSFER_LLM_RULES ||
    !openaiClient ||
    !ALLOW_EXTERNAL_FINANCIAL_CONTEXT
  ) {
    return { ...heuristic, source: "disabled" };
  }

  const cacheKey = buildTransferNoteLlmCacheKey(input);
  const cached = transferNoteLlmCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value;
  }

  try {
    const response = await openaiClient.responses.create({
      model: OPENAI_MODEL,
      reasoning: {
        effort: OPENAI_REASONING_EFFORT as "low" | "medium" | "high",
      },
      instructions:
        "You are a banking transfer safety analyst. Review only the sanitized transfer context and note text. Infer scam-related risk hints and explain why the note/context is suspicious or benign. Also identify clearly legitimate high-value purposes when the note strongly supports them, such as home_purchase, property_deposit, mortgage_closing, real_estate_settlement, tuition_payment, medical_bill, vehicle_purchase, salary_payroll, supplier_payment. Return JSON only with keys riskLevel, signals, ruleTags, summary, purposeTags, purposeConfidence. Do not decide allow or block. Be conservative and avoid false positives for ordinary personal or business payments.",
      input: JSON.stringify({
        note,
        amount: roundMoney(Math.max(0, input.amount)),
        currency: input.currency.trim().toUpperCase(),
        accountCategory: input.accountCategory,
        accountSegment: input.accountSegment,
        recipientKnown: input.recipientKnown,
        balanceImpactRatio: roundMoney(clamp(input.balanceImpactRatio, 0, 1.5)),
        sessionRiskLevel: input.sessionRiskLevel,
        velocity1h: Math.max(0, Math.round(input.velocity1h)),
        recentReviewCount30d: Math.max(
          0,
          Math.round(input.recentReviewCount30d),
        ),
        recentBlockedCount30d: Math.max(
          0,
          Math.round(input.recentBlockedCount30d),
        ),
        spendSurgeRatio:
          input.spendSurgeRatio === null
            ? null
            : roundMoney(Math.max(0, input.spendSurgeRatio)),
        heuristicSignals: suspiciousReasons,
      }),
    });

    const outputText =
      typeof response.output_text === "string" ? response.output_text : "";
    const parsedJson = extractJsonObject(outputText);
    if (!parsedJson) {
      throw new Error("OpenAI returned no JSON for transfer note analysis");
    }

    const safeParsed = transferNoteLlmAnalysisSchema.safeParse(
      JSON.parse(parsedJson),
    );
    if (!safeParsed.success) {
      throw new Error("Transfer note LLM payload failed schema validation");
    }

    const result: TransferNoteLlmAnalysis = {
      riskLevel: normalizeRiskLevel(safeParsed.data.riskLevel),
      signals: dedupeStringList([
        ...suspiciousReasons,
        ...safeParsed.data.signals,
      ]).slice(0, 6),
      ruleTags: dedupeStringList([
        ...safeParsed.data.ruleTags.map(normalizeTransferNoteRuleTag),
        ...(suspiciousReasons.length ? ["regex_suspicious_note"] : []),
      ])
        .filter(Boolean)
        .slice(0, 6),
      summary:
        typeof safeParsed.data.summary === "string" &&
        safeParsed.data.summary.trim()
          ? safeParsed.data.summary.trim()
          : heuristic.summary,
      purposeTags: dedupeStringList([
        ...heuristic.purposeTags,
        ...safeParsed.data.purposeTags.map(normalizeTransferNotePurposeTag),
      ])
        .filter(Boolean)
        .slice(0, 4),
      purposeConfidence: clamp(
        Math.max(
          heuristic.purposeConfidence,
          typeof safeParsed.data.purposeConfidence === "number"
            ? safeParsed.data.purposeConfidence
            : 0,
        ),
        0,
        1,
      ),
      source: "openai",
      model: OPENAI_MODEL,
    };
    const normalized: TransferNoteLlmAnalysis = {
      ...result,
      riskLevel:
        heuristic.riskLevel === "high" ||
        (heuristic.riskLevel === "medium" && result.riskLevel === "low")
          ? heuristic.riskLevel
          : result.riskLevel,
    };
    transferNoteLlmCache.set(cacheKey, {
      value: normalized,
      expiresAt: Date.now() + TRANSFER_LLM_RULES_CACHE_TTL_MS,
    });
    return normalized;
  } catch (error) {
    console.warn("Transfer note LLM analysis failed; falling back", error);
    const fallback = { ...heuristic, source: "fallback" as const };
    transferNoteLlmCache.set(cacheKey, {
      value: fallback,
      expiresAt: Date.now() + Math.min(TRANSFER_LLM_RULES_CACHE_TTL_MS, 60000),
    });
    return fallback;
  }
};

const buildTransferAiScoringPayload = (input: {
  senderUserId: string;
  req: Request;
  amount: number;
  currency: string;
  note: string;
  accountProfile: {
    segment: string;
    category: string;
    tier: string;
    status: string;
    confidence: number;
  };
  failedTx24h: number;
  velocity1h: number;
  spendProfile: TransferSpendProfile;
  senderBalance: number;
  recipientProfile: TransferRecipientProfile;
  behaviorProfile: TransferBehaviorProfile;
  transferStepUpPolicy: TransferStepUpPolicy;
  transferNoteLlm: TransferNoteLlmAnalysis;
}) => {
  const sessionRiskLevel = normalizeRiskLevel(
    input.req.sessionSecurity?.riskLevel || "low",
  );
  const senderBalance = Math.max(0, Number(input.senderBalance) || 0);
  const remainingBalance = Math.max(0, senderBalance - input.amount);

  return {
    userId: input.senderUserId,
    transactionId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    amount: input.amount,
    currency: input.currency,
    location: getRequestLocation(input.req),
    paymentMethod: "wallet_balance",
    merchantCategory: "p2p_transfer",
    device:
      typeof input.req.headers["user-agent"] === "string"
        ? input.req.headers["user-agent"]
        : "unknown",
    accountProfile: {
      segment: input.accountProfile.segment,
      category: input.accountProfile.category,
      tier: input.accountProfile.tier,
      status: input.accountProfile.status,
      confidence: input.accountProfile.confidence,
    },
    transferContext: {
      channel: "web",
      balanceBefore: senderBalance,
      remainingBalance,
      recipientKnown: input.recipientProfile.isKnownRecipient,
      rollingOutflowAmount: input.transferStepUpPolicy.rollingOutflowAmount,
      faceIdRequired: input.transferStepUpPolicy.faceIdRequired,
      sessionRiskLevel,
      sessionRestrictLargeTransfers: Boolean(
        input.req.sessionSecurity?.restrictLargeTransfers,
      ),
    },
    behaviorSnapshot: {
      failedTx24h: input.failedTx24h,
      velocity1h: input.velocity1h,
      dailySpendAvg30d: input.spendProfile.dailySpendAvg30d,
      todaySpendBefore: input.spendProfile.todaySpendBefore,
      projectedDailySpend: input.spendProfile.projectedDailySpend,
      recentReviewCount30d: input.behaviorProfile.recentReviewCount30d,
      recentBlockedCount30d: input.behaviorProfile.recentBlockedCount30d,
      recentPendingOtpCount7d: input.behaviorProfile.recentPendingOtpCount7d,
      recentInboundAmount24h: input.behaviorProfile.recentInboundAmount24h,
      recentAdminTopUpAmount24h:
        input.behaviorProfile.recentAdminTopUpAmount24h,
      recentSelfDepositAmount24h:
        input.behaviorProfile.recentSelfDepositAmount24h,
      smallProbeCount24h: input.behaviorProfile.smallProbeCount24h,
      smallProbeTotal24h: input.behaviorProfile.smallProbeTotal24h,
      distinctSmallProbeRecipients24h:
        input.behaviorProfile.distinctSmallProbeRecipients24h,
      sameRecipientSmallProbeCount24h:
        input.behaviorProfile.sameRecipientSmallProbeCount24h,
      newRecipientSmallProbeCount24h:
        input.behaviorProfile.newRecipientSmallProbeCount24h,
      probeThenLargeRiskScore: input.behaviorProfile.probeThenLargeRiskScore,
      rapidCashOutRiskScore: input.behaviorProfile.rapidCashOutRiskScore,
    },
    llmContext: {
      riskLevel: input.transferNoteLlm.riskLevel,
      signalCount: input.transferNoteLlm.signals.length,
      signals: input.transferNoteLlm.signals,
      ruleTags: input.transferNoteLlm.ruleTags,
      summary: input.transferNoteLlm.summary,
      purposeTags: input.transferNoteLlm.purposeTags,
      purposeConfidence: input.transferNoteLlm.purposeConfidence,
      source: input.transferNoteLlm.source,
      model: input.transferNoteLlm.model || null,
    },
    // Legacy flat fields remain for backward compatibility while ai-service
    // migrates to the grouped contract above.
    accountSegment: input.accountProfile.segment,
    accountCategory: input.accountProfile.category,
    accountTier: input.accountProfile.tier,
    accountProfileStatus: input.accountProfile.status,
    accountProfileConfidence: input.accountProfile.confidence,
    channel: "web",
    failedTx24h: input.failedTx24h,
    velocity1h: input.velocity1h,
    dailySpendAvg30d: input.spendProfile.dailySpendAvg30d,
    todaySpendBefore: input.spendProfile.todaySpendBefore,
    projectedDailySpend: input.spendProfile.projectedDailySpend,
    balanceBefore: senderBalance,
    remainingBalance,
    recipientKnown: input.recipientProfile.isKnownRecipient,
    suspiciousNoteCount: getSuspiciousTransferNoteReasons(input.note).length,
    llmNoteRiskLevel: input.transferNoteLlm.riskLevel,
    llmSignalCount: input.transferNoteLlm.signals.length,
    llmRuleTags: input.transferNoteLlm.ruleTags,
    llmPurposeTags: input.transferNoteLlm.purposeTags,
    llmPurposeConfidence: input.transferNoteLlm.purposeConfidence,
    sessionRiskLevel,
    rollingOutflowAmount: input.transferStepUpPolicy.rollingOutflowAmount,
    faceIdRequired: input.transferStepUpPolicy.faceIdRequired,
    sessionRestrictLargeTransfers: Boolean(
      input.req.sessionSecurity?.restrictLargeTransfers,
    ),
    recentReviewCount30d: input.behaviorProfile.recentReviewCount30d,
    recentBlockedCount30d: input.behaviorProfile.recentBlockedCount30d,
    recentPendingOtpCount7d: input.behaviorProfile.recentPendingOtpCount7d,
    recentInboundAmount24h: input.behaviorProfile.recentInboundAmount24h,
    recentAdminTopUpAmount24h: input.behaviorProfile.recentAdminTopUpAmount24h,
    recentSelfDepositAmount24h:
      input.behaviorProfile.recentSelfDepositAmount24h,
    smallProbeCount24h: input.behaviorProfile.smallProbeCount24h,
    smallProbeTotal24h: input.behaviorProfile.smallProbeTotal24h,
    distinctSmallProbeRecipients24h:
      input.behaviorProfile.distinctSmallProbeRecipients24h,
    sameRecipientSmallProbeCount24h:
      input.behaviorProfile.sameRecipientSmallProbeCount24h,
    newRecipientSmallProbeCount24h:
      input.behaviorProfile.newRecipientSmallProbeCount24h,
    probeThenLargeRiskScore: input.behaviorProfile.probeThenLargeRiskScore,
    rapidCashOutRiskScore: input.behaviorProfile.rapidCashOutRiskScore,
    llmSignals: input.transferNoteLlm.signals,
    llmSummary: input.transferNoteLlm.summary,
    llmPurposeTags: input.transferNoteLlm.purposeTags,
    llmPurposeConfidence: input.transferNoteLlm.purposeConfidence,
    llmSource: input.transferNoteLlm.source,
    llmModel: input.transferNoteLlm.model || null,
  };
};

const isGenericTransferNote = (note: string) => {
  const normalizedNote = normalizeTransferNoteForPatternMatch(note);
  if (!normalizedNote) return true;
  if (normalizedNote.length < 10) return true;
  return /^(transfer|payment|banking|send money|test|gift|invoice|payment for services|wallet transfer)$/i.test(
    normalizedNote,
  );
};

const getTransferSafetyHold = (
  metadata: unknown,
): TransferSafetyHold | null => {
  const root = normalizeMetadataRecord(metadata);
  const hold = normalizeMetadataRecord(root.transferSafetyHold);
  if (
    typeof hold.blockedUntil !== "string" ||
    Number.isNaN(Date.parse(hold.blockedUntil))
  ) {
    return null;
  }
  return {
    toAccount: typeof hold.toAccount === "string" ? hold.toAccount : "",
    toUserId: typeof hold.toUserId === "string" ? hold.toUserId : "",
    amount: typeof hold.amount === "number" ? hold.amount : 0,
    requestKey: typeof hold.requestKey === "string" ? hold.requestKey : null,
    reason:
      typeof hold.reason === "string"
        ? hold.reason
        : "This transfer is temporarily blocked for safety review.",
    blockedUntil: hold.blockedUntil,
    createdAt:
      typeof hold.createdAt === "string"
        ? hold.createdAt
        : new Date().toISOString(),
  };
};

const setTransferSafetyHold = (
  metadata: unknown,
  hold: TransferSafetyHold | null,
) => {
  const root = { ...normalizeMetadataRecord(metadata) };
  if (!hold) {
    delete root.transferSafetyHold;
    return root;
  }
  root.transferSafetyHold = hold;
  return root;
};

const matchesTransferSafetyHold = (
  hold: TransferSafetyHold,
  input: { toAccount: string; toUserId: string },
) =>
  Boolean(
    (hold.toAccount && input.toAccount && hold.toAccount === input.toAccount) ||
    (hold.toUserId && input.toUserId && hold.toUserId === input.toUserId),
  );

const buildBlockedTransferAdvisory = (input: {
  requestKey?: string | null;
  amount: number;
  currency: string;
  senderBalance: number;
  reasons: string[];
  archetype?: string | null;
  timeline?: string[];
  recommendedActions?: string[];
  blockedUntil: string;
  title?: string;
  message?: string;
}) => {
  const senderBalance = Math.max(0, Number(input.senderBalance) || 0);
  const amount = Math.max(0, Number(input.amount) || 0);
  const remainingBalance = Math.max(0, roundMoney(senderBalance - amount));
  return {
    requestKey: input.requestKey || null,
    severity: "blocked" as const,
    title: input.title || "Transfer temporarily blocked for safety review",
    message:
      input.message ||
      `This transfer is paused until ${new Date(
        input.blockedUntil,
      ).toLocaleString(
        "en-US",
      )} so you have time to verify the recipient through a trusted channel.`,
    archetype: input.archetype || "Known Scam Pattern",
    timeline: dedupeStringList([
      ...(input.timeline || []),
      "The transfer entered a temporary safety hold while high-risk signals are reviewed.",
    ]).slice(0, 4),
    recommendedActions: dedupeStringList([
      ...(input.recommendedActions || []),
      "Verify the recipient through a trusted channel you initiate yourself.",
      "Do not continue if anyone is pressuring you to act urgently.",
      "Retry only after you confirm the payment purpose and recipient identity.",
    ]).slice(0, 4),
    confirmationLabel: "Blocked for safety review",
    reasons: input.reasons,
    requiresAcknowledgement: false,
    transferRatio: senderBalance > 0 ? amount / senderBalance : 0,
    remainingBalance,
    remainingBalanceRatio:
      senderBalance > 0 ? remainingBalance / senderBalance : 0,
    amount,
    currency: input.currency,
    blockedUntil: input.blockedUntil,
  } satisfies TransferSafetyAdvisory;
};

const buildTransferSafetyAdvisory = (input: {
  amount: number;
  senderBalance: number;
  currency: string;
  aiResult: AnomalyResponse;
  transferNoteLlm: TransferNoteLlmAnalysis;
  spendProfile: TransferSpendProfile;
  recipientProfile: TransferRecipientProfile;
  behaviorProfile: TransferBehaviorProfile;
  recipientAccount: string;
  note: string;
  requestKey?: string | null;
}) => {
  const senderBalance = Math.max(0, Number(input.senderBalance) || 0);
  const amount = Math.max(0, Number(input.amount) || 0);
  if (!senderBalance || !amount) return null;

  const remainingBalance = Math.max(0, roundMoney(senderBalance - amount));
  const transferRatio = amount / senderBalance;
  const remainingBalanceRatio =
    senderBalance > 0 ? remainingBalance / senderBalance : 0;
  const qualifiesForRedWarning = amount >= TRANSFER_FACE_ID_THRESHOLD;
  const hasMaterialDrainAmount = amount >= BALANCE_DRAIN_ADVISORY_MIN_AMOUNT;
  const hasWarningDrainAmount = amount >= BALANCE_DRAIN_WARNING_MIN_AMOUNT;
  const hasMeaningfulHistoricalRiskAmount =
    amount >= Math.max(50, TRANSFER_PROBE_SMALL_AMOUNT_MAX);
  const hasProbeEscalationAmount =
    amount >= Math.max(300, TRANSFER_PROBE_SMALL_AMOUNT_MAX * 2);
  const noteRiskReasons = getSuspiciousTransferNoteReasons(input.note);
  const noteIsGeneric = isGenericTransferNote(input.note);
  const hasHousingPurposeTag = input.transferNoteLlm.purposeTags.some((tag) =>
    [
      "home_purchase",
      "property_deposit",
      "mortgage_closing",
      "real_estate_settlement",
    ].includes(tag),
  );
  const hasLegitimateHighValuePurpose =
    hasHousingPurposeTag &&
    input.transferNoteLlm.purposeConfidence >= 0.72 &&
    input.transferNoteLlm.riskLevel === "low" &&
    noteRiskReasons.length === 0;
  const reasons: string[] = [];
  const addReason = (reason: string) => {
    if (
      !reasons.some((entry) => entry.toLowerCase() === reason.toLowerCase())
    ) {
      reasons.push(reason);
    }
  };
  let severity: TransferSafetyAdvisory["severity"] = "caution";
  const recipientAverage =
    input.recipientProfile.completedTransfers > 0
      ? input.recipientProfile.totalSent /
        input.recipientProfile.completedTransfers
      : 0;
  const amountVsRecipientAverage =
    recipientAverage > 0 ? amount / recipientAverage : null;
  const amountVsUserAverage =
    input.behaviorProfile.averageCompletedOutflow90d > 0
      ? amount / input.behaviorProfile.averageCompletedOutflow90d
      : null;
  const recipientLabel = input.recipientAccount
    ? `account ending ${input.recipientAccount.slice(-4)}`
    : "this recipient";
  const accountSegmentLabel =
    input.aiResult.accountSegment === "enterprise"
      ? "enterprise"
      : input.aiResult.accountSegment === "sme"
        ? "SME"
        : "consumer";
  const hasStrongWarningSignal =
    amount >= HIGH_TRANSFER_ADVISORY_AMOUNT ||
    (hasWarningDrainAmount && transferRatio >= BALANCE_DRAIN_WARNING_RATIO) ||
    (input.spendProfile.dailySpendAvg30d > 0 &&
      input.spendProfile.spendSurgeRatio !== null &&
      input.spendProfile.spendSurgeRatio >= 8) ||
    (noteRiskReasons.length > 0 &&
      amount >= Math.max(500, LARGE_TRANSFER_ADVISORY_AMOUNT * 0.5));
  let archetype: string | null = null;
  const recommendedActions: string[] = [];
  const addRecommendedAction = (action: string) => {
    if (
      !recommendedActions.some(
        (entry) => entry.toLowerCase() === action.toLowerCase(),
      )
    ) {
      recommendedActions.push(action);
    }
  };

  if (hasMaterialDrainAmount && transferRatio >= BALANCE_DRAIN_ADVISORY_RATIO) {
    archetype = archetype || "Balance Drain Risk";
    addReason(
      `This transfer uses ${Math.round(transferRatio * 100)}% of your available wallet balance.`,
    );
  }
  if (
    qualifiesForRedWarning &&
    hasWarningDrainAmount &&
    transferRatio >= BALANCE_DRAIN_WARNING_RATIO
  ) {
    severity = "warning";
  }

  if (
    hasMaterialDrainAmount &&
    remainingBalance <= LOW_REMAINING_BALANCE_ADVISORY
  ) {
    addReason(
      `You would keep only ${formatMoneyAmount(input.currency, remainingBalance)} after this transfer.`,
    );
  }

  if (amount >= LARGE_TRANSFER_ADVISORY_AMOUNT) {
    addReason(
      `This is a high-value transfer for a ${accountSegmentLabel} wallet (${formatMoneyAmount(input.currency, amount)}).`,
    );
  }
  if (qualifiesForRedWarning) {
    severity = "warning";
  }

  if (!input.recipientProfile.isKnownRecipient) {
    archetype = archetype || "New Recipient Risk";
    addReason(
      `${recipientLabel} has not appeared in your completed transfer history yet.`,
    );
    addRecommendedAction(
      "Confirm the recipient using a trusted phone number or verified channel before sending.",
    );
    if (qualifiesForRedWarning) {
      severity = "warning";
    }
  }

  if (
    amountVsRecipientAverage !== null &&
    input.recipientProfile.completedTransfers >= 2 &&
    amountVsRecipientAverage >= 3
  ) {
    addReason(
      `This amount is ${amountVsRecipientAverage.toFixed(1)}x larger than your usual completed transfer to ${recipientLabel}.`,
    );
    if (qualifiesForRedWarning) {
      severity = "warning";
    }
  }

  if (
    amountVsUserAverage !== null &&
    input.behaviorProfile.averageCompletedOutflow90d > 0 &&
    amountVsUserAverage >= 4
  ) {
    addReason(
      `This amount is ${amountVsUserAverage.toFixed(1)}x above your average completed outgoing transfer in the last 90 days.`,
    );
  }

  if (
    input.behaviorProfile.maxCompletedOutflow90d > 0 &&
    amount > input.behaviorProfile.maxCompletedOutflow90d
  ) {
    addReason(
      `This exceeds your largest completed outgoing transfer in the last 90 days (${formatMoneyAmount(
        input.currency,
        input.behaviorProfile.maxCompletedOutflow90d,
      )}).`,
    );
  }

  if (
    hasMeaningfulHistoricalRiskAmount &&
    input.behaviorProfile.similarFlaggedAmountCount90d > 0
  ) {
    addReason(
      `You had ${input.behaviorProfile.similarFlaggedAmountCount90d} recent transfer attempt${
        input.behaviorProfile.similarFlaggedAmountCount90d === 1 ? "" : "s"
      } near this amount that were reviewed or blocked before completion.`,
    );
    if (qualifiesForRedWarning) {
      severity = "warning";
    }
  }

  if (
    hasProbeEscalationAmount &&
    input.behaviorProfile.sameRecipientFlaggedCount90d > 0
  ) {
    addReason(
      `${recipientLabel} was already involved in ${input.behaviorProfile.sameRecipientFlaggedCount90d} reviewed or blocked transfer attempt${
        input.behaviorProfile.sameRecipientFlaggedCount90d === 1 ? "" : "s"
      } recently.`,
    );
    if (qualifiesForRedWarning) {
      severity = "warning";
    }
  }

  if (
    hasMeaningfulHistoricalRiskAmount &&
    input.behaviorProfile.recentReviewCount30d +
      input.behaviorProfile.recentBlockedCount30d >=
      3
  ) {
    addReason(
      `Recent outbound transfer behavior has triggered ${input.behaviorProfile.recentReviewCount30d + input.behaviorProfile.recentBlockedCount30d} AI reviews or blocks in the last 30 days.`,
    );
  }

  if (
    hasMeaningfulHistoricalRiskAmount &&
    input.behaviorProfile.recentPendingOtpCount7d >= 4
  ) {
    addReason(
      `You started ${input.behaviorProfile.recentPendingOtpCount7d} outbound transfer verification flows in the last 7 days, which is faster than your usual pace.`,
    );
  }

  if (
    hasProbeEscalationAmount &&
    input.behaviorProfile.smallProbeCount24h >= TRANSFER_PROBE_BURST_COUNT_24H
  ) {
    archetype = archetype || "Probe Then Escalate Pattern";
    addReason(
      `The account initiated ${input.behaviorProfile.smallProbeCount24h} small transfer attempt${
        input.behaviorProfile.smallProbeCount24h === 1 ? "" : "s"
      } in the last 24 hours, which can indicate recipient or account probing before a larger payment.`,
    );
    addRecommendedAction(
      "Pause and confirm why several small outbound transfers were attempted before this payment.",
    );
  }

  if (
    hasProbeEscalationAmount &&
    input.behaviorProfile.distinctSmallProbeRecipients24h >= 2
  ) {
    addReason(
      `Small outbound transfers touched ${input.behaviorProfile.distinctSmallProbeRecipients24h} recipient accounts in the last 24 hours.`,
    );
  }

  if (
    hasProbeEscalationAmount &&
    input.behaviorProfile.sameRecipientSmallProbeCount24h >= 2
  ) {
    addReason(
      `${recipientLabel} already received ${input.behaviorProfile.sameRecipientSmallProbeCount24h} recent small transfer attempt${
        input.behaviorProfile.sameRecipientSmallProbeCount24h === 1 ? "" : "s"
      }, which may indicate account validation before a larger payout.`,
    );
  }

  if (
    hasProbeEscalationAmount &&
    input.behaviorProfile.newRecipientSmallProbeCount24h >= 2 &&
    !input.recipientProfile.isKnownRecipient
  ) {
    addReason(
      "Several recent small transfers targeted new recipients, increasing the chance of mule-account testing or scam escalation.",
    );
  }

  if (
    hasProbeEscalationAmount &&
    input.behaviorProfile.probeThenLargeRiskScore >= 0.65
  ) {
    severity = "warning";
    addReason(
      "Behavior shows a probe-then-escalate pattern: repeated small transfers followed by a materially larger payout request.",
    );
  }

  for (const noteReason of noteRiskReasons) {
    archetype = archetype || "Scam Script Language";
    addReason(noteReason);
  }
  if (noteRiskReasons.length > 0) {
    addRecommendedAction(
      "Pause if this transfer was requested over chat, phone, or a link you did not verify independently.",
    );
  }
  if (
    noteRiskReasons.length > 0 &&
    amount >= Math.max(500, LARGE_TRANSFER_ADVISORY_AMOUNT * 0.5)
  ) {
    if (qualifiesForRedWarning) {
      severity = "warning";
    }
  }
  if (noteIsGeneric && amount >= LARGE_TRANSFER_ADVISORY_AMOUNT) {
    addReason(
      `The transfer note is too generic for a payment of ${formatMoneyAmount(input.currency, amount)}.`,
    );
    addRecommendedAction(
      "Add a specific payment purpose before continuing so the transfer is easier to verify later.",
    );
  }

  if (
    input.spendProfile.dailySpendAvg30d > 0 &&
    input.spendProfile.spendSurgeRatio !== null &&
    input.spendProfile.spendSurgeRatio >= 4
  ) {
    addReason(
      `Today's projected transfer spend is ${input.spendProfile.spendSurgeRatio.toFixed(
        1,
      )}x above your recent daily average.`,
    );
  }
  if (
    input.spendProfile.dailySpendAvg30d > 0 &&
    input.spendProfile.spendSurgeRatio !== null &&
    input.spendProfile.spendSurgeRatio >= 8
  ) {
    if (qualifiesForRedWarning) {
      severity = "warning";
    }
  }

  if (input.aiResult.riskLevel === "medium") {
    archetype = archetype || "Behavior Drift";
    addReason(
      "AI sees this transfer as less typical than your recent completed behavior.",
    );
    addRecommendedAction(
      "Review the amount, recipient, and purpose once more before approving OTP.",
    );
  }
  if (input.aiResult.riskLevel === "high") {
    archetype = archetype || "Known Scam Pattern";
    if (qualifiesForRedWarning && hasStrongWarningSignal) {
      severity = "warning";
    }
    addReason(
      "AI found multiple scam-like signals around this recipient, amount, and transfer pattern.",
    );
    addRecommendedAction(
      "Do not approve this transfer until you independently verify the request is legitimate.",
    );
  }
  if (input.aiResult.finalAction === "REQUIRE_OTP_FACE_ID") {
    severity = "warning";
    addReason(
      "The hybrid risk engine requires OTP plus biometric verification for this transfer.",
    );
  } else if (input.aiResult.finalAction === "REQUIRE_OTP") {
    addReason(
      "The hybrid risk engine requires OTP verification before this transfer can continue.",
    );
  } else if (input.aiResult.finalAction === "ALLOW_WITH_WARNING") {
    addReason(
      "The hybrid risk engine suggests continuing only after reviewing the warning details.",
    );
  }
  if (hasLegitimateHighValuePurpose) {
    severity = "warning";
    addReason(
      "AI recognized a plausible high-value life-event purpose in the note, so this transfer can continue only with enhanced verification instead of an automatic pause.",
    );
    addRecommendedAction(
      "Verify that the destination account belongs to your escrow agent, seller, or title company before approving.",
    );
  }

  for (const aiReason of input.aiResult.reasons) {
    const cleaned = aiReason.replace(/\s+/g, " ").trim();
    if (!cleaned || /no clear anomaly/i.test(cleaned)) continue;
    addReason(cleaned);
    if (reasons.length >= 6) break;
  }

  const advisoryReasons = reasons;
  if (!advisoryReasons.length) return null;

  const hasBlockSizedAmount = amount > TRANSFER_SCAM_BLOCK_MIN_AMOUNT;
  const hasNearZeroRemainingBalance =
    remainingBalance <= TRANSFER_SCAM_BLOCK_MAX_REMAINING_BALANCE;
  const hasSuspiciousNoteSignal = noteRiskReasons.length > 0;
  const hasRecipientFraudHistory =
    (hasProbeEscalationAmount &&
      input.behaviorProfile.sameRecipientFlaggedCount90d > 0) ||
    (hasMeaningfulHistoricalRiskAmount &&
      input.behaviorProfile.similarFlaggedAmountCount90d > 0);
  const hasHighRiskAiSignal = input.aiResult.riskLevel === "high";
  const hasProbeEscalationSignal =
    hasProbeEscalationAmount &&
    input.behaviorProfile.probeThenLargeRiskScore >= 0.75 &&
    amount >= TRANSFER_PROBE_LARGE_ESCALATION_MIN_AMOUNT;
  const shouldBlock =
    (!hasLegitimateHighValuePurpose &&
      input.aiResult.finalAction === "HOLD_REVIEW") ||
    (hasBlockSizedAmount &&
      ((hasSuspiciousNoteSignal &&
        (!input.recipientProfile.isKnownRecipient ||
          hasNearZeroRemainingBalance)) ||
        (hasNearZeroRemainingBalance &&
          hasRecipientFraudHistory &&
          hasHighRiskAiSignal))) ||
    (hasProbeEscalationSignal &&
      hasHighRiskAiSignal &&
      !input.recipientProfile.isKnownRecipient);

  if (shouldBlock) {
    const blockedUntil = new Date(
      Date.now() + TRANSFER_SCAM_HOLD_MS,
    ).toISOString();
    const timeline = dedupeStringList([
      !input.recipientProfile.isKnownRecipient
        ? "The recipient was not found in your completed transfer history."
        : null,
      noteRiskReasons.length > 0
        ? "The payment note matched language often used in scam instructions."
        : null,
      hasMaterialDrainAmount && transferRatio >= BALANCE_DRAIN_ADVISORY_RATIO
        ? `The amount would consume ${Math.round(transferRatio * 100)}% of your current balance.`
        : null,
      "The risk engine combined these signals and placed the transfer on hold.",
    ]).slice(0, 4);
    return buildBlockedTransferAdvisory({
      requestKey: input.requestKey,
      amount,
      currency: input.currency,
      senderBalance,
      blockedUntil,
      archetype: archetype || "Known Scam Pattern",
      timeline,
      reasons: advisoryReasons,
      recommendedActions,
      message: `This transfer is temporarily blocked until ${new Date(
        blockedUntil,
      ).toLocaleString(
        "en-US",
      )}. AI sees a high-risk combination here: ${advisoryReasons
        .slice(0, 2)
        .join(" ")}`,
    });
  }

  let title =
    severity === "warning"
      ? "High-risk transfer needs confirmation"
      : "AI review: light transfer check";
  if (
    !input.recipientProfile.isKnownRecipient &&
    amountVsUserAverage !== null
  ) {
    title = `First transfer to ${recipientLabel} is ${amountVsUserAverage.toFixed(1)}x above your recent norm`;
  } else if (
    amountVsRecipientAverage !== null &&
    input.recipientProfile.completedTransfers >= 2 &&
    amountVsRecipientAverage >= 3
  ) {
    title = `This payment is much larger than your past transfers to ${recipientLabel}`;
  } else if (input.behaviorProfile.similarFlaggedAmountCount90d > 0) {
    title =
      "This amount resembles recently reviewed or blocked transfer attempts";
  } else if (
    hasMaterialDrainAmount &&
    transferRatio >= BALANCE_DRAIN_ADVISORY_RATIO
  ) {
    title = "This transfer would drain most of your wallet balance";
  } else if (noteIsGeneric && amount >= LARGE_TRANSFER_ADVISORY_AMOUNT) {
    title =
      "Generic payment note on a large transfer needs stronger verification";
  }

  const messageLead = !input.recipientProfile.isKnownRecipient
    ? `You are about to send ${formatMoneyAmount(input.currency, amount)} to ${recipientLabel} for the first time.`
    : hasMaterialDrainAmount && transferRatio >= BALANCE_DRAIN_ADVISORY_RATIO
      ? `You are about to transfer ${Math.round(
          transferRatio * 100,
        )}% of your balance and keep ${formatMoneyAmount(
          input.currency,
          remainingBalance,
        )}.`
      : `You are about to send ${formatMoneyAmount(
          input.currency,
          amount,
        )} to ${recipientLabel}.`;

  const messageTail =
    severity === "warning"
      ? `AI wants you to verify this payment because ${advisoryReasons
          .slice(0, 2)
          .join(" ")}`
      : `AI recorded only light advisory signals for this transfer: ${advisoryReasons
          .slice(0, 1)
          .join(" ")}`;

  const requiresAcknowledgement = severity === "warning";
  const timeline = dedupeStringList([
    !input.recipientProfile.isKnownRecipient
      ? "The recipient is new relative to your completed transfer history."
      : null,
    hasMaterialDrainAmount && transferRatio >= BALANCE_DRAIN_ADVISORY_RATIO
      ? `The amount would use ${Math.round(transferRatio * 100)}% of your balance.`
      : null,
    noteRiskReasons.length > 0
      ? "The payment note contains language commonly seen in scam or pressure-based requests."
      : null,
    input.aiResult.riskLevel === "high"
      ? "AI combined recipient, amount, and behavior signals into a high-risk pattern."
      : input.aiResult.riskLevel === "medium"
        ? "AI found this transfer less typical than your recent completed behavior."
        : "AI recorded only light advisory signals for this transfer.",
    severity === "warning"
      ? "The transfer can continue only after you actively review and acknowledge the warning."
      : "The transfer can continue, but the system recommends a manual check first.",
  ]).slice(0, 5);

  return {
    requestKey: input.requestKey || null,
    severity,
    title,
    message: `${messageLead} ${messageTail}`,
    archetype:
      archetype ||
      (severity === "warning" ? "Step-Up Review" : "Light Advisory Signal"),
    timeline,
    recommendedActions: dedupeStringList([
      ...recommendedActions,
      severity === "warning"
        ? "Verify the recipient and purpose before you continue to OTP."
        : "Continue only if the recipient, amount, and note all match your intent.",
      qualifiesForRedWarning
        ? "Expect stronger verification on larger transfers."
        : null,
    ]).slice(0, 4),
    confirmationLabel:
      severity === "warning"
        ? "I reviewed the warning, continue to OTP"
        : "Continue to OTP",
    reasons: advisoryReasons,
    requiresAcknowledgement,
    transferRatio,
    remainingBalance,
    remainingBalanceRatio,
    amount,
    currency: input.currency,
    blockedUntil: null,
  } satisfies TransferSafetyAdvisory;
};

const normalizeTransferSafetyAdvisory = (value: unknown) => {
  if (!value || typeof value !== "object") return null;
  const data = value as Record<string, unknown>;
  const severity =
    data.severity === "warning" ||
    data.severity === "caution" ||
    data.severity === "blocked"
      ? data.severity
      : null;
  if (
    (data.requestKey !== null && typeof data.requestKey !== "string") ||
    !severity ||
    typeof data.title !== "string" ||
    typeof data.message !== "string" ||
    typeof data.confirmationLabel !== "string" ||
    typeof data.requiresAcknowledgement !== "boolean" ||
    typeof data.transferRatio !== "number" ||
    typeof data.remainingBalance !== "number" ||
    typeof data.remainingBalanceRatio !== "number" ||
    typeof data.amount !== "number" ||
    typeof data.currency !== "string" ||
    (data.blockedUntil !== undefined &&
      data.blockedUntil !== null &&
      typeof data.blockedUntil !== "string")
  ) {
    return null;
  }

  return {
    requestKey: typeof data.requestKey === "string" ? data.requestKey : null,
    severity,
    title: data.title,
    message: data.message,
    archetype: typeof data.archetype === "string" ? data.archetype : null,
    timeline: Array.isArray(data.timeline)
      ? data.timeline.filter((item): item is string => typeof item === "string")
      : [],
    recommendedActions: Array.isArray(data.recommendedActions)
      ? data.recommendedActions.filter(
          (item): item is string => typeof item === "string",
        )
      : [],
    confirmationLabel: data.confirmationLabel,
    reasons: Array.isArray(data.reasons)
      ? data.reasons.filter((item): item is string => typeof item === "string")
      : [],
    requiresAcknowledgement: data.requiresAcknowledgement,
    transferRatio: data.transferRatio,
    remainingBalance: data.remainingBalance,
    remainingBalanceRatio: data.remainingBalanceRatio,
    amount: data.amount,
    currency: data.currency,
    blockedUntil:
      typeof data.blockedUntil === "string" ? data.blockedUntil : null,
  } satisfies TransferSafetyAdvisory;
};

const summarizeRecentTransactions = (
  transactions: CopilotTransactionPayload[],
) => transactions.slice(0, 12);

const formatCopilotMoney = (currency: string, amount: number) =>
  `${currency} ${roundMoney(Math.max(0, amount)).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;

const formatCopilotSignedMoney = (currency: string, amount: number) =>
  `${amount >= 0 ? "+" : "-"}${formatCopilotMoney(currency, Math.abs(amount))}`;

const dedupeStringList = (items: Array<string | null | undefined>) => {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const item of items) {
    const cleaned = String(item || "")
      .replace(/\s+/g, " ")
      .trim();
    if (!cleaned) continue;
    const key = cleaned.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(cleaned);
  }
  return result;
};

const BUDGET_WARNING_THRESHOLD = 0.85;
const BUDGET_CRITICAL_THRESHOLD = 1;
const SPENDING_CATEGORY_SHARES: Record<SpendingCategoryKey, number> = {
  food: 0.22,
  transport: 0.1,
  bills: 0.16,
  shopping: 0.18,
  transfers: 0.16,
  education_health: 0.1,
  other: 0.08,
};
const SPENDING_CATEGORY_ORDER: SpendingCategoryKey[] = [
  "food",
  "transport",
  "bills",
  "shopping",
  "transfers",
  "education_health",
  "other",
];
const SPENDING_CATEGORY_ALIASES: Record<SpendingCategoryKey, string[]> = {
  food: ["an uong", "food", "dining", "meal", "meals", "cafe", "coffee"],
  transport: ["di lai", "transport", "travel", "xang", "taxi", "commute"],
  bills: [
    "hoa don",
    "bill",
    "bills",
    "utilities",
    "dien nuoc",
    "internet",
    "rent",
  ],
  shopping: ["mua sam", "shopping", "lifestyle", "giai tri", "entertainment"],
  transfers: ["chuyen tien", "transfer", "transfers", "rut tien", "cash out"],
  education_health: [
    "hoc tap",
    "suc khoe",
    "education",
    "health",
    "medical",
    "y te",
  ],
  other: ["khac", "other", "misc", "miscellaneous"],
};
const DEFAULT_BUDGET_ASSISTANT_PREFERENCES: StoredBudgetAssistantPreferences = {
  proactiveRemindersEnabled: true,
  dailyDigestEnabled: false,
  weeklyDigestEnabled: false,
  monthlyDigestEnabled: false,
  digestDeliveryChannel: "email",
};
const DEFAULT_BUDGET_ASSISTANT_AUTOMATION_STATE: StoredBudgetAssistantAutomationState =
  {
    lastDailyDigestKey: null,
    lastWeeklyDigestKey: null,
    lastMonthlyDigestKey: null,
    lastPacingReminderKey: null,
  };

const normalizeBudgetAmountToken = (value: string) => {
  const trimmed = value.replace(/\s+/g, "");
  if (/^\d{1,3}(\.\d{3})+$/.test(trimmed)) {
    return trimmed.replace(/\./g, "");
  }
  if (/^\d{1,3}(,\d{3})+$/.test(trimmed)) {
    return trimmed.replace(/,/g, "");
  }
  return trimmed.replace(/,/g, "");
};

const parseBudgetAmountCandidate = (raw: string, unit?: string | null) => {
  const numeric = Number.parseFloat(normalizeBudgetAmountToken(raw));
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  const normalizedUnit = String(unit || "")
    .trim()
    .toLowerCase();
  const multiplier =
    normalizedUnit === "k" ||
    normalizedUnit === "nghin" ||
    normalizedUnit === "ngan"
      ? 1_000
      : normalizedUnit === "m" || normalizedUnit === "trieu"
        ? 1_000_000
        : 1;
  return roundMoney(numeric * multiplier);
};

const escapeRegex = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const extractBudgetTargetAmount = (message: string) => {
  const normalized = normalizeCopilotText(message);
  if (
    !/\b(budget|ngan sach|chi tieu|tieu|spend|spending|expense|cash flow|dong tien|ke hoach|kinh phi|du tru|allowance)\b/.test(
      normalized,
    )
  ) {
    return null;
  }

  const explicitCurrencyPatterns = [
    /(?:\$|usd|do|dollars?)\s*(\d[\d.,]*)(?:\s*(k|m))?\b/i,
    /(\d[\d.,]*)(?:\s*(k|m|nghin|ngan|trieu))?\s*(usd|do|dollars?|\$|vnd|dong)\b/i,
    /(\d[\d.,]*)(?:\s*(k|m|nghin|ngan|trieu))?\s*(do|dollars?)\b/i,
  ];

  for (const pattern of explicitCurrencyPatterns) {
    const match = message.match(pattern);
    if (!match) continue;
    const parsed = parseBudgetAmountCandidate(match[1], match[2]);
    if (parsed !== null) return parsed;
  }

  const contextualMatch = normalized.match(
    /\b(?:budget|ngan sach|chi tieu|tieu|spending|spend|expense|muc tieu|kinh phi|du tru|allowance)\b[\s\S]{0,30}?(\d[\d.,]*)(?:\s*(k|m|nghin|ngan|trieu))?\b/,
  );
  if (contextualMatch) {
    const parsed = parseBudgetAmountCandidate(
      contextualMatch[1],
      contextualMatch[2],
    );
    if (parsed !== null && parsed >= 10) return parsed;
  }

  const relaxedMatch = normalized.match(
    /\b(?:la|khoang|tam|about|around)\s*(\d[\d.,]*)(?:\s*(k|m|nghin|ngan|trieu))?\b/,
  );
  if (relaxedMatch) {
    const parsed = parseBudgetAmountCandidate(relaxedMatch[1], relaxedMatch[2]);
    if (parsed !== null && parsed >= 10) return parsed;
  }

  return null;
};

const extractSavingsGoalAmount = (message: string) => {
  const normalized = normalizeCopilotText(message);
  if (
    !/\b(save|saving|savings|tiet kiem|tich kiem|de danh|de duoc|bo ra|muc tieu tiet kiem|save up)\b/.test(
      normalized,
    )
  ) {
    return null;
  }

  const explicitCurrencyPatterns = [
    /(?:\$|usd|do|dollars?)\s*(\d[\d.,]*)(?:\s*(k|m))?\b/i,
    /(\d[\d.,]*)(?:\s*(k|m|nghin|ngan|trieu))?\s*(usd|do|dollars?|\$|vnd|dong)\b/i,
    /(\d[\d.,]*)(?:\s*(k|m|nghin|ngan|trieu))?\s*(do|dollars?)\b/i,
  ];

  for (const pattern of explicitCurrencyPatterns) {
    const match = message.match(pattern);
    if (!match) continue;
    const parsed = parseBudgetAmountCandidate(match[1], match[2]);
    if (parsed !== null) return parsed;
  }

  const contextualMatch = normalized.match(
    /\b(?:save|saving|savings|tiet kiem|tich kiem|de danh|de duoc|save up)\b[\s\S]{0,30}?(\d[\d.,]*)(?:\s*(k|m|nghin|ngan|trieu))?\b/,
  );
  if (contextualMatch) {
    const parsed = parseBudgetAmountCandidate(
      contextualMatch[1],
      contextualMatch[2],
    );
    if (parsed !== null && parsed >= 10) return parsed;
  }

  return null;
};

const isBudgetPlanSetupIntent = (message: string) =>
  /\b(lap|tao|dat|set|create|build|ke hoach|muc tieu|toi se|du dinh|gioi han|han muc|phan bo|toi da|toi muon|giu duoi|toi da|toi muon tieu|tieu toi da|tiet kiem|tich kiem|de danh|save|saving)\b/.test(
    normalizeCopilotText(message),
  );

const isBudgetPlanStatusIntent = (message: string) =>
  /\b(hien tai|current|con lai|remaining|con bao nhieu|used|da dung|vuot|over budget|tinh hinh|status|kiem tra)\b/.test(
    normalizeCopilotText(message),
  );

const isBudgetGoalPlanningIntent = (message: string) => {
  const normalized = normalizeCopilotText(message);
  const hasBudgetAmount = extractBudgetTargetAmount(message) !== null;
  const hasSavingsGoal = extractSavingsGoalAmount(message) !== null;
  const hasPlanningLanguage =
    /\b(siet|giam|kiem soat|lap|tao|dat|ke hoach|muc tieu|de co the|muon|can|gioi han|han muc|kinh phi|budget|tiet kiem|tich kiem|de danh)\b/.test(
      normalized,
    );

  return (hasBudgetAmount || hasSavingsGoal) && hasPlanningLanguage;
};

const extractBudgetPlanningScope = (
  message: string,
): "weekly" | "monthly" | null => {
  const normalized = normalizeCopilotText(message);
  if (
    /\b(tuan toi|tuan tiep theo|next week|weekly|1 tuan|mot tuan|7 ngay toi)\b/.test(
      normalized,
    )
  ) {
    return "weekly";
  }
  if (
    /\b(thang nay|thang toi|monthly|month|30 ngay|1 thang|mot thang)\b/.test(
      normalized,
    )
  ) {
    return "monthly";
  }
  return null;
};

const getStoredBudgetCategoryLabel = (key: SpendingCategoryKey) =>
  getSpendingCategoryLabel("en", key);

const normalizeBudgetCategoryShares = (input?: {
  customShares?: Partial<Record<SpendingCategoryKey, number>> | null;
  baseShares?: Partial<Record<SpendingCategoryKey, number>> | null;
}) => {
  const baseShares = input?.baseShares || SPENDING_CATEGORY_SHARES;
  const customShares = input?.customShares || {};
  const normalizedCustomEntries = Object.entries(customShares).filter(
    ([key, value]): value is number =>
      SPENDING_CATEGORY_ORDER.includes(key as SpendingCategoryKey) &&
      typeof value === "number" &&
      Number.isFinite(value) &&
      value >= 0,
  ) as Array<[SpendingCategoryKey, number]>;

  if (!normalizedCustomEntries.length) {
    return {
      shares: { ...SPENDING_CATEGORY_SHARES },
      providedKeys: [] as SpendingCategoryKey[],
      remainderDistributed: false,
    };
  }

  const providedTotal = normalizedCustomEntries.reduce(
    (sum, [, value]) => sum + value,
    0,
  );
  if (providedTotal > 1.001) {
    return null;
  }

  const providedKeys = normalizedCustomEntries.map(([key]) => key);
  const missingKeys = SPENDING_CATEGORY_ORDER.filter(
    (key) => !providedKeys.includes(key),
  );
  const remainingShare = Math.max(0, 1 - providedTotal);
  const baseMissingTotal = missingKeys.reduce(
    (sum, key) => sum + Math.max(0, baseShares[key] || 0),
    0,
  );
  const shares = {} as Record<SpendingCategoryKey, number>;

  for (const [key, value] of normalizedCustomEntries) {
    shares[key] = value;
  }

  for (const key of missingKeys) {
    const baseShare = Math.max(0, baseShares[key] || 0);
    shares[key] =
      remainingShare <= 0
        ? 0
        : baseMissingTotal > 0
          ? remainingShare * (baseShare / baseMissingTotal)
          : remainingShare / Math.max(missingKeys.length, 1);
  }

  return {
    shares,
    providedKeys,
    remainderDistributed: missingKeys.length > 0 && remainingShare > 0,
  };
};

const extractBudgetCategoryAllocationShares = (message: string) => {
  const normalized = normalizeCopilotText(message);
  if (!/\d{1,3}(?:[.,]\d+)?\s*%/.test(normalized)) return null;

  const allocations: Partial<Record<SpendingCategoryKey, number>> = {};
  for (const key of SPENDING_CATEGORY_ORDER) {
    for (const alias of SPENDING_CATEGORY_ALIASES[key]) {
      const escapedAlias = escapeRegex(alias);
      const patterns = [
        new RegExp(
          `\\b${escapedAlias}\\b\\s*(?:la|=|:|khoang|about|tam)?\\s*(\\d{1,3}(?:[.,]\\d+)?)\\s*%`,
          "i",
        ),
        new RegExp(
          `(\\d{1,3}(?:[.,]\\d+)?)\\s*%\\s*(?:cho|for|danh cho)?\\s*\\b${escapedAlias}\\b`,
          "i",
        ),
      ];

      let matchedShare: number | null = null;
      for (const pattern of patterns) {
        const match = normalized.match(pattern);
        if (!match) continue;
        const value = Number.parseFloat(match[1].replace(",", "."));
        if (Number.isFinite(value) && value >= 0 && value <= 100) {
          matchedShare = value / 100;
          break;
        }
      }

      if (matchedShare !== null) {
        allocations[key] = matchedShare;
        break;
      }
    }
  }

  return Object.keys(allocations).length ? allocations : null;
};

const extractBudgetAssistantPreferenceUpdates = (
  message: string,
): Partial<StoredBudgetAssistantPreferences> | null => {
  const normalized = normalizeCopilotText(message);
  const updates: Partial<StoredBudgetAssistantPreferences> = {};
  const enable =
    /\b(bat|mo|enable|turn on|kich hoat|gui)\b/.test(normalized) &&
    !/\b(tat|disable|turn off|stop|dung|ngung|huy)\b/.test(normalized);
  const disable = /\b(tat|disable|turn off|stop|dung|ngung|huy)\b/.test(
    normalized,
  );
  if (!enable && !disable) return null;

  const nextValue = enable && !disable;
  if (
    /\b(nhac nho|reminder|reminders|canh bao chu dong|proactive)\b/.test(
      normalized,
    )
  ) {
    updates.proactiveRemindersEnabled = nextValue;
  }
  if (
    /\b(bao cao|digest|brief|tom tat|summary)\b/.test(normalized) &&
    /\b(hang ngay|moi ngay|daily|hom nay)\b/.test(normalized)
  ) {
    updates.dailyDigestEnabled = nextValue;
  }
  if (
    /\b(bao cao|digest|brief|tom tat|summary)\b/.test(normalized) &&
    /\b(hang tuan|moi tuan|weekly|tuan)\b/.test(normalized)
  ) {
    updates.weeklyDigestEnabled = nextValue;
  }
  if (
    /\b(bao cao|digest|brief|tom tat|summary)\b/.test(normalized) &&
    /\b(hang thang|moi thang|monthly|thang)\b/.test(normalized)
  ) {
    updates.monthlyDigestEnabled = nextValue;
  }

  return Object.keys(updates).length ? updates : null;
};

type BudgetDigestPeriod = "daily" | "weekly" | "monthly";

const extractBudgetDigestRequestPeriod = (
  message: string,
): BudgetDigestPeriod | null => {
  const normalized = normalizeCopilotText(message);
  if (!/\b(bao cao|digest|brief|tom tat|summary)\b/.test(normalized)) {
    return null;
  }
  if (/\b(hang ngay|moi ngay|daily|hom nay)\b/.test(normalized)) return "daily";
  if (/\b(hang tuan|moi tuan|weekly|tuan nay)\b/.test(normalized))
    return "weekly";
  if (/\b(hang thang|moi thang|monthly|thang nay)\b/.test(normalized))
    return "monthly";
  return null;
};

const buildBudgetPlanCategories = (
  targetAmount: number,
  _planningMode: "spend_cap" | "savings_goal" = "spend_cap",
  options?: {
    customShares?: Partial<Record<SpendingCategoryKey, number>> | null;
    baseShares?: Partial<Record<SpendingCategoryKey, number>> | null;
  },
) => {
  const normalized = normalizeBudgetCategoryShares({
    customShares: options?.customShares,
    baseShares: options?.baseShares,
  }) || {
    shares: { ...SPENDING_CATEGORY_SHARES },
  };
  let allocated = 0;
  return SPENDING_CATEGORY_ORDER.map((key, index) => {
    const share = normalized.shares[key] || 0;
    const amount =
      index === SPENDING_CATEGORY_ORDER.length - 1
        ? roundMoney(Math.max(0, targetAmount - allocated))
        : roundMoney(targetAmount * share);
    allocated += amount;
    return {
      key,
      label: getStoredBudgetCategoryLabel(key),
      share,
      amount,
      trackingKeys: [key],
      thresholdAlertsSent: [],
    } satisfies StoredBudgetPlanCategory;
  });
};

const getStoredBudgetPlan = (metadata: unknown): StoredBudgetPlan | null => {
  const root = normalizeRecord(metadata);
  const budgetAssistant = normalizeRecord(root.budgetAssistant);
  const activePlan = normalizeRecord(budgetAssistant.activePlan);
  if (
    typeof activePlan.planId !== "string" ||
    typeof activePlan.currency !== "string" ||
    typeof activePlan.targetAmount !== "number" ||
    typeof activePlan.startAt !== "string" ||
    typeof activePlan.endAt !== "string"
  ) {
    return null;
  }

  const categories = Array.isArray(activePlan.categories)
    ? activePlan.categories
        .map((category) => normalizeRecord(category))
        .filter(
          (category) =>
            typeof category.key === "string" &&
            typeof category.label === "string" &&
            typeof category.share === "number" &&
            typeof category.amount === "number",
        )
        .map(
          (category) =>
            ({
              key: category.key as string,
              label: category.label as string,
              share: category.share as number,
              amount: category.amount as number,
              trackingKeys: Array.isArray(category.trackingKeys)
                ? category.trackingKeys.filter(
                    (entry): entry is SpendingCategoryKey =>
                      typeof entry === "string" &&
                      SPENDING_CATEGORY_ORDER.includes(
                        entry as SpendingCategoryKey,
                      ),
                  )
                : undefined,
              thresholdAlertsSent: Array.isArray(category.thresholdAlertsSent)
                ? category.thresholdAlertsSent
                    .filter(
                      (entry): entry is string =>
                        entry === "warning" || entry === "critical",
                    )
                    .slice(0, 4)
                : [],
            }) satisfies StoredBudgetPlanCategory,
        )
    : [];

  return {
    planId: activePlan.planId,
    status: activePlan.status === "EXPIRED" ? "EXPIRED" : "ACTIVE",
    period: "MONTHLY",
    currency: activePlan.currency,
    planningMode:
      activePlan.planningMode === "savings_goal" ? "savings_goal" : "spend_cap",
    targetAmount: roundMoney(activePlan.targetAmount),
    savingsGoalAmount:
      typeof activePlan.savingsGoalAmount === "number"
        ? roundMoney(activePlan.savingsGoalAmount)
        : null,
    incomeBaselineAmount:
      typeof activePlan.incomeBaselineAmount === "number"
        ? roundMoney(activePlan.incomeBaselineAmount)
        : null,
    spentAmount:
      typeof activePlan.spentAmount === "number"
        ? roundMoney(activePlan.spentAmount)
        : 0,
    remainingAmount:
      typeof activePlan.remainingAmount === "number"
        ? roundMoney(activePlan.remainingAmount)
        : roundMoney(activePlan.targetAmount),
    utilizationRatio:
      typeof activePlan.utilizationRatio === "number"
        ? activePlan.utilizationRatio
        : 0,
    warningThreshold:
      typeof activePlan.warningThreshold === "number"
        ? activePlan.warningThreshold
        : BUDGET_WARNING_THRESHOLD,
    criticalThreshold:
      typeof activePlan.criticalThreshold === "number"
        ? activePlan.criticalThreshold
        : BUDGET_CRITICAL_THRESHOLD,
    thresholdAlertsSent: Array.isArray(activePlan.thresholdAlertsSent)
      ? activePlan.thresholdAlertsSent
          .filter((entry): entry is string => typeof entry === "string")
          .slice(0, 4)
      : [],
    startAt: activePlan.startAt,
    endAt: activePlan.endAt,
    createdAt:
      typeof activePlan.createdAt === "string"
        ? activePlan.createdAt
        : activePlan.startAt,
    updatedAt:
      typeof activePlan.updatedAt === "string"
        ? activePlan.updatedAt
        : activePlan.startAt,
    lastEvaluatedAt:
      typeof activePlan.lastEvaluatedAt === "string"
        ? activePlan.lastEvaluatedAt
        : typeof activePlan.updatedAt === "string"
          ? activePlan.updatedAt
          : activePlan.startAt,
    sourcePrompt:
      typeof activePlan.sourcePrompt === "string"
        ? activePlan.sourcePrompt
        : "",
    dailyCapRemaining:
      typeof activePlan.dailyCapRemaining === "number"
        ? roundMoney(activePlan.dailyCapRemaining)
        : null,
    weeklyCapRemaining:
      typeof activePlan.weeklyCapRemaining === "number"
        ? roundMoney(activePlan.weeklyCapRemaining)
        : null,
    categories:
      categories.length > 0
        ? categories
        : buildBudgetPlanCategories(
            roundMoney(activePlan.targetAmount),
            activePlan.planningMode === "savings_goal"
              ? "savings_goal"
              : "spend_cap",
          ),
    emailAlertsEnabled: activePlan.emailAlertsEnabled !== false,
  };
};

const getBudgetAssistantPreferences = (
  metadata: unknown,
): StoredBudgetAssistantPreferences => {
  const root = normalizeRecord(metadata);
  const budgetAssistant = normalizeRecord(root.budgetAssistant);
  const raw = normalizeRecord(budgetAssistant.preferences);
  return {
    proactiveRemindersEnabled: raw.proactiveRemindersEnabled !== false,
    dailyDigestEnabled: raw.dailyDigestEnabled === true,
    weeklyDigestEnabled: raw.weeklyDigestEnabled === true,
    monthlyDigestEnabled: raw.monthlyDigestEnabled === true,
    digestDeliveryChannel: "email",
  };
};

const getBudgetAssistantAutomationState = (
  metadata: unknown,
): StoredBudgetAssistantAutomationState => {
  const root = normalizeRecord(metadata);
  const budgetAssistant = normalizeRecord(root.budgetAssistant);
  const raw = normalizeRecord(budgetAssistant.automationState);
  return {
    lastDailyDigestKey:
      typeof raw.lastDailyDigestKey === "string"
        ? raw.lastDailyDigestKey
        : null,
    lastWeeklyDigestKey:
      typeof raw.lastWeeklyDigestKey === "string"
        ? raw.lastWeeklyDigestKey
        : null,
    lastMonthlyDigestKey:
      typeof raw.lastMonthlyDigestKey === "string"
        ? raw.lastMonthlyDigestKey
        : null,
    lastPacingReminderKey:
      typeof raw.lastPacingReminderKey === "string"
        ? raw.lastPacingReminderKey
        : null,
  };
};

const setStoredBudgetPlan = (
  metadata: unknown,
  plan: StoredBudgetPlan | null,
): Record<string, unknown> => {
  const root = normalizeRecord(metadata);
  const budgetAssistant = normalizeRecord(root.budgetAssistant);
  if (!plan) {
    return {
      ...root,
      budgetAssistant: {
        ...budgetAssistant,
        activePlan: null,
      },
    };
  }

  return {
    ...root,
    budgetAssistant: {
      ...budgetAssistant,
      activePlan: plan,
    },
  };
};

const setBudgetAssistantPreferences = (
  metadata: unknown,
  preferences: StoredBudgetAssistantPreferences,
): Record<string, unknown> => {
  const root = normalizeRecord(metadata);
  const budgetAssistant = normalizeRecord(root.budgetAssistant);
  return {
    ...root,
    budgetAssistant: {
      ...budgetAssistant,
      preferences,
    },
  };
};

const setBudgetAssistantAutomationState = (
  metadata: unknown,
  automationState: StoredBudgetAssistantAutomationState,
): Record<string, unknown> => {
  const root = normalizeRecord(metadata);
  const budgetAssistant = normalizeRecord(root.budgetAssistant);
  return {
    ...root,
    budgetAssistant: {
      ...budgetAssistant,
      automationState,
    },
  };
};

const recalculateBudgetPlanProgress = (
  plan: StoredBudgetPlan,
  spentAmount: number,
  now: Date,
) => {
  const endAt = new Date(plan.endAt);
  const remainingAmount = roundMoney(plan.targetAmount - spentAmount);
  const utilizationRatio =
    plan.targetAmount > 0 ? spentAmount / Math.max(plan.targetAmount, 1) : 0;
  const msRemaining = Math.max(0, endAt.getTime() - now.getTime());
  const daysRemaining = Math.max(1, Math.ceil(msRemaining / 86400000));
  const weeksRemaining = Math.max(1, Math.ceil(daysRemaining / 7));

  return {
    ...plan,
    status: now <= endAt ? "ACTIVE" : "EXPIRED",
    spentAmount: roundMoney(spentAmount),
    remainingAmount,
    utilizationRatio,
    dailyCapRemaining:
      remainingAmount > 0 ? roundMoney(remainingAmount / daysRemaining) : 0,
    weeklyCapRemaining:
      remainingAmount > 0 ? roundMoney(remainingAmount / weeksRemaining) : 0,
    updatedAt: now.toISOString(),
    lastEvaluatedAt: now.toISOString(),
  } satisfies StoredBudgetPlan;
};

const buildPublicBudgetPlanSummary = (
  plan: StoredBudgetPlan | null,
): PublicBudgetPlanSummary | null => {
  if (!plan) return null;
  return {
    planId: plan.planId,
    status: plan.status,
    period: plan.period,
    currency: plan.currency,
    planningMode: plan.planningMode,
    targetAmount: plan.targetAmount,
    savingsGoalAmount: plan.savingsGoalAmount,
    incomeBaselineAmount: plan.incomeBaselineAmount,
    spentAmount: plan.spentAmount,
    remainingAmount: plan.remainingAmount,
    utilizationRatio: plan.utilizationRatio,
    warningThreshold: plan.warningThreshold,
    criticalThreshold: plan.criticalThreshold,
    startAt: plan.startAt,
    endAt: plan.endAt,
    createdAt: plan.createdAt,
    updatedAt: plan.updatedAt,
    lastEvaluatedAt: plan.lastEvaluatedAt,
    dailyCapRemaining: plan.dailyCapRemaining,
    weeklyCapRemaining: plan.weeklyCapRemaining,
    categories: plan.categories,
    emailAlertsEnabled: plan.emailAlertsEnabled,
  };
};

const getSpendingCategoryLabel = (
  language: CopilotLanguage,
  key: SpendingCategoryKey,
) => {
  const labels: Record<SpendingCategoryKey, { vi: string; en: string }> = {
    food: { vi: "Ăn uống", en: "Food & dining" },
    transport: { vi: "Đi lại", en: "Transport" },
    bills: { vi: "Hóa đơn", en: "Bills & utilities" },
    shopping: { vi: "Mua sắm", en: "Shopping & lifestyle" },
    transfers: { vi: "Chuyển tiền", en: "Transfers & cash-out" },
    education_health: { vi: "Học tập / sức khỏe", en: "Education / health" },
    other: { vi: "Khác", en: "Other" },
  };
  return language === "vi" ? labels[key].vi : labels[key].en;
};

const categorizeDebitTransaction = (input: {
  type: string;
  description?: string;
}): SpendingCategoryKey => {
  const normalized = normalizeCopilotText(
    `${input.type || ""} ${input.description || ""}`,
  );

  if (
    /\b(com|pho|bun|an uong|ca phe|cafe|coffee|tea|tra sua|restaurant|nha hang|grabfood|breakfast|lunch|dinner|grocery|sieu thi|mart|food)\b/.test(
      normalized,
    )
  ) {
    return "food";
  }
  if (
    /\b(xang|fuel|taxi|grab|uber|be bike|be car|bus|metro|parking|gui xe|di lai|transport)\b/.test(
      normalized,
    )
  ) {
    return "transport";
  }
  if (
    /\b(hoa don|bill|dien|nuoc|internet|wifi|phone|dien thoai|utility|subscription|rent|thue nha|tra gop|installment)\b/.test(
      normalized,
    )
  ) {
    return "bills";
  }
  if (
    /\b(shopee|lazada|tiktok shop|mua sam|shopping|fashion|clothes|quan ao|quanao|my pham|cosmetic|movie|cinema|netflix|spotify|game|giai tri|entertainment)\b/.test(
      normalized,
    )
  ) {
    return "shopping";
  }
  if (
    /\b(hoc phi|tuition|school|course|khoa hoc|book|sach|benh vien|hospital|clinic|pharmacy|thuoc|medicine|health|medical|bao hiem)\b/.test(
      normalized,
    )
  ) {
    return "education_health";
  }
  if (
    input.type === "TRANSFER" ||
    input.type === "WITHDRAW" ||
    /\b(transfer|chuyen tien|gui tien|rut tien|cash out|family|gia dinh)\b/.test(
      normalized,
    )
  ) {
    return "transfers";
  }
  return "other";
};

const buildBudgetPlanBaseShares = (plan: StoredBudgetPlan | null) => {
  if (!plan?.categories?.length) return { ...SPENDING_CATEGORY_SHARES };
  const shares = {} as Partial<Record<SpendingCategoryKey, number>>;
  for (const category of plan.categories) {
    if (
      SPENDING_CATEGORY_ORDER.includes(category.key as SpendingCategoryKey) &&
      typeof category.share === "number" &&
      Number.isFinite(category.share) &&
      category.share >= 0
    ) {
      shares[category.key as SpendingCategoryKey] = category.share;
    }
  }
  return Object.keys(shares).length
    ? (shares as Record<SpendingCategoryKey, number>)
    : { ...SPENDING_CATEGORY_SHARES };
};

const buildBudgetCategoryCapMap = (plan: StoredBudgetPlan | null) => {
  const caps: Partial<Record<SpendingCategoryKey, number>> = {};
  for (const category of plan?.categories || []) {
    if (
      SPENDING_CATEGORY_ORDER.includes(category.key as SpendingCategoryKey) &&
      typeof category.amount === "number" &&
      Number.isFinite(category.amount)
    ) {
      caps[category.key as SpendingCategoryKey] = roundMoney(category.amount);
    }
  }
  return caps;
};

const summarizeBudgetPlanCategoryUsage = (input: {
  transactions: CopilotTransactionPayload[];
  plan: StoredBudgetPlan;
  language: CopilotLanguage;
}) => {
  const rawSummary = summarizeSpendingCategories({
    transactions: input.transactions,
    language: input.language,
    warningThreshold: input.plan.warningThreshold,
    categoryCapMap: buildBudgetCategoryCapMap(input.plan),
  });
  const byKey = new Map(
    rawSummary.map((category) => [category.key, category] as const),
  );

  return input.plan.categories
    .map((category) => {
      const key = SPENDING_CATEGORY_ORDER.includes(
        category.key as SpendingCategoryKey,
      )
        ? (category.key as SpendingCategoryKey)
        : null;
      if (!key) return null;
      const summary = byKey.get(key);
      const spentAmount = roundMoney(summary?.amount || 0);
      const utilizationRatio =
        category.amount > 0 ? spentAmount / category.amount : null;
      return {
        key,
        label: category.label,
        capAmount: roundMoney(category.amount),
        spentAmount,
        utilizationRatio,
        warningState:
          utilizationRatio !== null && utilizationRatio >= 1
            ? "over"
            : utilizationRatio !== null &&
                utilizationRatio >= input.plan.warningThreshold
              ? "warning"
              : "ok",
      };
    })
    .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry));
};

const buildBudgetDigestSnapshot = (input: {
  language: CopilotLanguage;
  currency: string;
  period: BudgetDigestPeriod;
  transactions: CopilotTransactionPayload[];
  previousTransactions: CopilotTransactionPayload[];
  budgetPlan: StoredBudgetPlan | null;
  now: Date;
}) => {
  const debitTransactions = input.transactions.filter(
    (transaction) => transaction.direction === "debit",
  );
  const previousDebitTransactions = input.previousTransactions.filter(
    (transaction) => transaction.direction === "debit",
  );
  const spentAmount = roundMoney(
    debitTransactions.reduce((sum, transaction) => sum + transaction.amount, 0),
  );
  const previousSpentAmount = roundMoney(
    previousDebitTransactions.reduce(
      (sum, transaction) => sum + transaction.amount,
      0,
    ),
  );
  const inflowAmount = roundMoney(
    input.transactions.reduce(
      (sum, transaction) =>
        sum + (transaction.direction === "credit" ? transaction.amount : 0),
      0,
    ),
  );
  const topCategory = summarizeSpendingCategories({
    transactions: debitTransactions,
    language: input.language,
    categoryCapMap: buildBudgetCategoryCapMap(input.budgetPlan),
    warningThreshold: input.budgetPlan?.warningThreshold,
  })[0];

  const periodLabel =
    input.period === "daily"
      ? localizeCopilotText(input.language, "Hôm nay", "Today")
      : input.period === "weekly"
        ? localizeCopilotText(input.language, "Tuần này", "This week")
        : localizeCopilotText(input.language, "Tháng này", "This month");
  const previousLabel =
    input.period === "daily"
      ? localizeCopilotText(input.language, "hôm qua", "yesterday")
      : input.period === "weekly"
        ? localizeCopilotText(input.language, "tuần trước", "last week")
        : localizeCopilotText(input.language, "tháng trước", "last month");
  const deltaAmount = roundMoney(spentAmount - previousSpentAmount);
  const budgetLine = input.budgetPlan
    ? localizeCopilotText(
        input.language,
        `Bạn đã dùng ${Math.round(input.budgetPlan.utilizationRatio * 100)}% mức chi hiện tại, còn lại ${formatCopilotMoney(input.currency, Math.max(0, input.budgetPlan.remainingAmount))}.`,
        `You have used ${Math.round(input.budgetPlan.utilizationRatio * 100)}% of the active budget, with ${formatCopilotMoney(input.currency, Math.max(0, input.budgetPlan.remainingAmount))} left.`,
      )
    : localizeCopilotText(
        input.language,
        "Chưa có budget plan đang hoạt động, nên đây là tóm tắt chi tiêu thuần.",
        "No active budget plan is stored yet, so this is a pure spending summary.",
      );
  const topCategoryLine = topCategory
    ? localizeCopilotText(
        input.language,
        `Danh mục chi lớn nhất là ${topCategory.label} với ${formatCopilotMoney(input.currency, topCategory.amount)}.`,
        `Top spend category was ${topCategory.label} at ${formatCopilotMoney(input.currency, topCategory.amount)}.`,
      )
    : localizeCopilotText(
        input.language,
        "Không có giao dịch chi ra đáng kể trong kỳ này.",
        "There were no meaningful debit transactions in this period.",
      );
  const comparisonLine = localizeCopilotText(
    input.language,
    `${periodLabel} bạn đã chi ${formatCopilotMoney(input.currency, spentAmount)}, ${deltaAmount >= 0 ? "chênh +" : "chênh -"}${formatCopilotMoney(input.currency, Math.abs(deltaAmount))} so với ${previousLabel}.`,
    `${periodLabel} spend was ${formatCopilotMoney(input.currency, spentAmount)}, ${deltaAmount >= 0 ? "+" : "-"}${formatCopilotMoney(input.currency, Math.abs(deltaAmount))} versus ${previousLabel}.`,
  );
  const headline = localizeCopilotText(
    input.language,
    `Tóm tắt VaultAI ${periodLabel.toLowerCase()}`,
    `VaultAI ${periodLabel.toLowerCase()} brief`,
  );
  const metricsTable = buildCopilotMarkdownTable(
    input.language === "vi" ? ["Chỉ số", "Giá trị"] : ["Metric", "Value"],
    [
      [
        input.language === "vi" ? "Tiền vào" : "Inflow",
        formatCopilotMoney(input.currency, inflowAmount),
      ],
      [
        input.language === "vi" ? "Tiền ra" : "Outflow",
        formatCopilotMoney(input.currency, spentAmount),
      ],
      [
        input.language === "vi" ? "So sánh kỳ trước" : "Vs previous period",
        `${deltaAmount >= 0 ? "+" : "-"}${formatCopilotMoney(
          input.currency,
          Math.abs(deltaAmount),
        )}`,
      ],
      [
        input.language === "vi" ? "Số giao dịch" : "Transactions",
        input.transactions.length,
      ],
    ],
  );

  return {
    headline,
    spentAmount,
    inflowAmount,
    topCategoryLabel: topCategory?.label || null,
    topCategoryAmount: topCategory?.amount || 0,
    deltaAmount,
    periodLabel,
    comparisonLine,
    budgetLine,
    topCategoryLine,
    metricsTable,
  };
};

const buildBudgetDigestCopilotResponse = async (input: {
  userId: string;
  currency: string;
  language: CopilotLanguage;
  period: BudgetDigestPeriod;
}): Promise<CopilotResponsePayload> => {
  const now = new Date();
  const range = getBudgetDigestPeriodRange(input.period, now);
  const [transactions, previousTransactions, userDoc] = await Promise.all([
    fetchCopilotTransactionsForUser({
      userId: input.userId,
      startInclusive: range.startInclusive,
      endExclusive: range.endExclusive,
      limit: 1500,
      context: "/ai/copilot-chat:digest-current",
    }),
    fetchCopilotTransactionsForUser({
      userId: input.userId,
      startInclusive: range.previousStartInclusive,
      endExclusive: range.previousEndExclusive,
      limit: 1500,
      context: "/ai/copilot-chat:digest-previous",
    }),
    createUserRepository().findValidatedById(input.userId),
  ]);

  const plan = getStoredBudgetPlan(userDoc?.metadata);
  const digestBudgetPlan =
    plan && new Date(plan.startAt) <= now && new Date(plan.endAt) > now
      ? recalculateBudgetPlanProgress(
          plan,
          await sumCompletedDebitTransactionsForUser({
            userId: input.userId,
            startInclusive: new Date(plan.startAt),
            endExclusive: new Date(plan.endAt),
            context: "/ai/copilot-chat:digest-budget-refresh",
          }),
          now,
        )
      : plan;
  const snapshot = buildBudgetDigestSnapshot({
    language: input.language,
    currency: input.currency,
    period: input.period,
    transactions,
    previousTransactions,
    budgetPlan: digestBudgetPlan,
    now,
  });

  return {
    reply: [
      snapshot.headline,
      "",
      snapshot.metricsTable,
      "",
      snapshot.comparisonLine,
      snapshot.topCategoryLine,
      snapshot.budgetLine,
    ].join("\n"),
    topic: `budget-digest-${input.period}`,
    suggestedActions:
      input.language === "vi"
        ? [
            "Neu muon doi muc chi, chat lai ke hoach chi tieu moi.",
            "Bat bao cao ngay, tuan, hoac thang neu ban muon nhan brief qua email.",
            "Hoi toi danh muc nao dang tieu nhanh nhat neu ban muon cat giam som.",
          ]
        : [
            "Send a new spending target if you want to reshape the active plan.",
            "Turn daily, weekly, or monthly briefs on if you want these emailed automatically.",
            "Ask which category is accelerating fastest if you want an early cutback signal.",
          ],
    suggestedDepositAmount: null,
    riskLevel:
      digestBudgetPlan &&
      digestBudgetPlan.utilizationRatio >= digestBudgetPlan.warningThreshold
        ? "medium"
        : "low",
    confidence: 0.97,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Ban co muon toi bat gui brief tu dong cho ky nay khong?",
      "Do you want me to turn on automatic briefs for this period?",
    ),
    budgetPlan: buildPublicBudgetPlanSummary(digestBudgetPlan),
  };
};

const runBudgetAssistantAutomation = async (input: {
  userId: string;
  actor?: string;
  ipAddress?: string;
  trigger: "auth_me" | "debit";
}) => {
  const userRepository = createUserRepository();
  const userDoc = await userRepository.findValidatedById(input.userId);
  if (!userDoc) return;

  const preferences = getBudgetAssistantPreferences(userDoc.metadata);
  const automationState = getBudgetAssistantAutomationState(userDoc.metadata);
  const now = new Date();
  const activePlan = getStoredBudgetPlan(userDoc.metadata);
  let nextAutomationState = { ...automationState };
  let metadataChanged = false;

  const maybeSendDigest = async (
    period: BudgetDigestPeriod,
    enabled: boolean,
  ) => {
    if (!enabled) return;
    const key = getBudgetDigestPeriodKey(period, now);
    const stateKey =
      period === "daily"
        ? "lastDailyDigestKey"
        : period === "weekly"
          ? "lastWeeklyDigestKey"
          : "lastMonthlyDigestKey";
    if (nextAutomationState[stateKey] === key) return;

    const range = getBudgetDigestPeriodRange(period, now);
    const [transactions, previousTransactions] = await Promise.all([
      fetchCopilotTransactionsForUser({
        userId: input.userId,
        startInclusive: range.startInclusive,
        endExclusive: range.endExclusive,
        limit: 1500,
        context: "/budget-assistant:automation-current",
      }),
      fetchCopilotTransactionsForUser({
        userId: input.userId,
        startInclusive: range.previousStartInclusive,
        endExclusive: range.previousEndExclusive,
        limit: 1500,
        context: "/budget-assistant:automation-previous",
      }),
    ]);

    const snapshot = buildBudgetDigestSnapshot({
      language: "en",
      currency:
        activePlan?.currency ||
        (typeof userDoc.metadata === "object" &&
        typeof (userDoc.metadata as Record<string, unknown>).currency ===
          "string"
          ? String((userDoc.metadata as Record<string, unknown>).currency)
          : "USD"),
      period,
      transactions,
      previousTransactions,
      budgetPlan: activePlan,
      now,
    });

    await sendBudgetDigestEmail({
      to: userDoc.email,
      recipientName: getRecipientName(userDoc),
      periodLabel: snapshot.periodLabel,
      headline: snapshot.headline,
      currency:
        activePlan?.currency ||
        (typeof userDoc.metadata === "object" &&
        typeof (userDoc.metadata as Record<string, unknown>).currency ===
          "string"
          ? String((userDoc.metadata as Record<string, unknown>).currency)
          : "USD"),
      inflowAmount: snapshot.inflowAmount,
      spentAmount: snapshot.spentAmount,
      deltaAmount: snapshot.deltaAmount,
      topCategoryLabel: snapshot.topCategoryLabel,
      topCategoryAmount: snapshot.topCategoryAmount,
      budgetLine: snapshot.budgetLine,
      comparisonLine: snapshot.comparisonLine,
    });
    await logAuditEvent({
      actor: "vaultai-assistant",
      userId: input.userId,
      action: "BUDGET_ASSISTANT_DIGEST_SENT",
      details: {
        period,
        periodLabel: snapshot.periodLabel,
        headline: snapshot.headline,
        spentAmount: snapshot.spentAmount,
        inflowAmount: snapshot.inflowAmount,
        deltaAmount: snapshot.deltaAmount,
        topCategoryLabel: snapshot.topCategoryLabel,
        topCategoryAmount: snapshot.topCategoryAmount,
      },
      ipAddress: input.ipAddress,
    });
    nextAutomationState[stateKey] = key;
    metadataChanged = true;
  };

  if (preferences.dailyDigestEnabled) {
    await maybeSendDigest("daily", true);
  }
  if (preferences.weeklyDigestEnabled) {
    await maybeSendDigest("weekly", true);
  }
  if (preferences.monthlyDigestEnabled) {
    await maybeSendDigest("monthly", true);
  }

  if (
    preferences.proactiveRemindersEnabled &&
    activePlan &&
    new Date(activePlan.startAt) <= now &&
    new Date(activePlan.endAt) > now
  ) {
    const startAt = new Date(activePlan.startAt);
    const endAt = new Date(activePlan.endAt);
    const spentAmount = await sumCompletedDebitTransactionsForUser({
      userId: input.userId,
      startInclusive: startAt,
      endExclusive: endAt,
      context: "/budget-assistant:pacing-refresh",
    });
    const refreshedPlan = recalculateBudgetPlanProgress(
      activePlan,
      spentAmount,
      now,
    );
    const elapsedDays = Math.max(
      1,
      Math.ceil((now.getTime() - startAt.getTime()) / 86400000),
    );
    const totalDays = Math.max(
      1,
      Math.ceil((endAt.getTime() - startAt.getTime()) / 86400000),
    );
    const projectedSpendAmount = roundMoney(
      (refreshedPlan.spentAmount / elapsedDays) * totalDays,
    );
    const pacingKey = `${getBudgetDigestPeriodKey("daily", now)}:${projectedSpendAmount > refreshedPlan.targetAmount ? "over" : "ok"}`;
    if (
      projectedSpendAmount > refreshedPlan.targetAmount &&
      nextAutomationState.lastPacingReminderKey !== pacingKey
    ) {
      await sendBudgetPacingReminderEmail({
        to: userDoc.email,
        recipientName: getRecipientName(userDoc),
        currency: refreshedPlan.currency,
        projectedSpendAmount,
        targetAmount: refreshedPlan.targetAmount,
        currentSpentAmount: refreshedPlan.spentAmount,
        periodLabel: formatCopilotCalendarDate("en", startAt),
      });
      await logAuditEvent({
        actor: "vaultai-assistant",
        userId: input.userId,
        action: "BUDGET_ASSISTANT_PACING_REMINDER_SENT",
        details: {
          projectedSpendAmount,
          targetAmount: refreshedPlan.targetAmount,
          currentSpentAmount: refreshedPlan.spentAmount,
          currency: refreshedPlan.currency,
          periodLabel: formatCopilotCalendarDate("en", startAt),
        },
        ipAddress: input.ipAddress,
      });
      nextAutomationState.lastPacingReminderKey = pacingKey;
      metadataChanged = true;
    }
  }

  if (metadataChanged) {
    await userRepository.updateMetadata(
      input.userId,
      setBudgetAssistantAutomationState(userDoc.metadata, nextAutomationState),
    );
    invalidateUserResponseCache(input.userId, ["auth"]);
  }
};

const summarizeSpendingCategories = (input: {
  transactions: CopilotTransactionPayload[];
  language: CopilotLanguage;
  targetAmount?: number | null;
  warningThreshold?: number;
  categoryCapMap?: Partial<Record<SpendingCategoryKey, number>>;
}): SpendingCategorySummary[] => {
  const debitTransactions = input.transactions.filter(
    (transaction) => transaction.direction === "debit",
  );
  const totalSpend = roundMoney(
    debitTransactions.reduce((sum, transaction) => sum + transaction.amount, 0),
  );

  const grouped = new Map<
    SpendingCategoryKey,
    { amount: number; count: number }
  >();
  for (const transaction of debitTransactions) {
    const categoryKey = categorizeDebitTransaction({
      type: transaction.type,
      description: transaction.description,
    });
    const current = grouped.get(categoryKey) || { amount: 0, count: 0 };
    grouped.set(categoryKey, {
      amount: roundMoney(current.amount + transaction.amount),
      count: current.count + 1,
    });
  }

  return (Object.keys(SPENDING_CATEGORY_SHARES) as SpendingCategoryKey[])
    .map((key) => {
      const current = grouped.get(key) || { amount: 0, count: 0 };
      const capAmount =
        typeof input.categoryCapMap?.[key] === "number"
          ? roundMoney(Number(input.categoryCapMap[key] || 0))
          : typeof input.targetAmount === "number" && input.targetAmount > 0
            ? roundMoney(input.targetAmount * SPENDING_CATEGORY_SHARES[key])
            : null;
      const utilizationRatio =
        capAmount && capAmount > 0 ? current.amount / capAmount : null;
      const warningThreshold =
        typeof input.warningThreshold === "number"
          ? input.warningThreshold
          : BUDGET_WARNING_THRESHOLD;

      return {
        key,
        label: getSpendingCategoryLabel(input.language, key),
        amount: roundMoney(current.amount),
        count: current.count,
        shareOfSpend:
          totalSpend > 0 ? roundMoney(current.amount / totalSpend) : 0,
        capAmount,
        utilizationRatio,
        warningState:
          utilizationRatio !== null && utilizationRatio >= 1
            ? "over"
            : utilizationRatio !== null && utilizationRatio >= warningThreshold
              ? "warning"
              : "ok",
      } satisfies SpendingCategorySummary;
    })
    .filter((category) => category.amount > 0)
    .sort((left, right) => right.amount - left.amount);
};

const buildSpendingAdjustmentSuggestions = (input: {
  language: CopilotLanguage;
  categories: SpendingCategorySummary[];
  hasBudgetPlan: boolean;
}) => {
  const top = input.categories[0];
  const suggestions: string[] = [];
  if (top) {
    if (top.key === "shopping") {
      suggestions.push(
        localizeCopilotText(
          input.language,
          "Tạm dừng mua sắm tùy ý trong vài ngày tới và gom các món cần mua vào một danh sách duy nhất trước khi thanh toán.",
          "Pause discretionary shopping for the next few days and batch non-essential purchases into one reviewed list before paying.",
        ),
      );
    } else if (top.key === "food") {
      suggestions.push(
        localizeCopilotText(
          input.language,
          "Đặt trần ăn uống theo ngày và ưu tiên gom đồ ăn, cà phê vào một khung ngân sách cố định.",
          "Set a daily food cap and fold meals and coffee into one fixed dining budget.",
        ),
      );
    } else if (top.key === "transfers") {
      suggestions.push(
        localizeCopilotText(
          input.language,
          "Đặt hạn mức chuyển tiền theo tuần để tránh dòng tiền rời ví quá nhanh trong nửa sau của tháng.",
          "Set a weekly transfer limit so money does not leave the wallet too quickly in the second half of the month.",
        ),
      );
    } else if (top.key === "bills") {
      suggestions.push(
        localizeCopilotText(
          input.language,
          "Rà soát các khoản hóa đơn và subscription định kỳ để cắt những dịch vụ ít dùng nhất.",
          "Review recurring bills and subscriptions first, then cut the least-used services.",
        ),
      );
    }
  }

  if (input.hasBudgetPlan) {
    suggestions.push(
      localizeCopilotText(
        input.language,
        "Theo sát trần chi theo ngày và theo tuần còn lại để giữ mục tiêu tháng không bị vỡ.",
        "Use the remaining daily and weekly caps to keep the monthly target intact.",
      ),
    );
  } else {
    suggestions.push(
      localizeCopilotText(
        input.language,
        "Nếu bạn muốn theo dõi chặt hơn, hãy đặt một trần chi tiêu tháng trong chat để tôi đối chiếu tự động.",
        "If you want tighter control, set a monthly budget cap in chat so I can compare actual spending automatically.",
      ),
    );
  }

  suggestions.push(
    localizeCopilotText(
      input.language,
      "Tập trung cắt nhóm chi lớn nhất trước, vì đó là nơi tạo ra tác động tiết kiệm nhanh nhất.",
      "Reduce the largest category first, because that is where savings will move fastest.",
    ),
  );
  return dedupeStringList(suggestions).slice(0, 4);
};

const buildBudgetCategoryAllocationPromptResponse = (input: {
  language: CopilotLanguage;
  currency: string;
}): CopilotResponsePayload => ({
  reply: localizeCopilotText(
    input.language,
    `Toi co the cho ban tu chinh ty trong tung danh muc ngay trong chat, nhung toi can mot ke hoach ngan sach dang hoat dong truoc. Hay dat tran chi tieu, vi du: "thang nay toi muon chi toi da ${input.currency} 2,000", roi chat tiep "an uong 30%, di lai 10%, hoa don 20%".`,
    `I can let you tune category weights directly in chat, but I need an active budget plan first. Set a cap first, for example "this month I want to spend at most ${input.currency} 2,000", then follow with "food 30%, transport 10%, bills 20%".`,
  ),
  topic: "budget-plan-category-amount-needed",
  suggestedActions:
    input.language === "vi"
      ? [
          "Dat tran chi tieu hoac muc tieu tiet kiem truoc.",
          "Sau do gui ty trong theo % cho cac danh muc muon uu tien.",
          "He thong se tu can phan con lai vao cac danh muc chua nhap.",
        ]
      : [
          "Set a spending cap or savings goal first.",
          "Then send category percentages for the buckets you want to control.",
          "The system will rebalance the remaining share across untouched categories.",
        ],
  suggestedDepositAmount: null,
  riskLevel: "low",
  confidence: 0.94,
  followUpQuestion: localizeCopilotText(
    input.language,
    "Ban muon dat tran chi tieu hoac muc tieu tiet kiem truoc khong?",
    "Do you want to set a spending cap or savings goal first?",
  ),
  budgetPlan: null,
});

const buildBudgetCategoryAllocationInvalidResponse = (input: {
  language: CopilotLanguage;
}): CopilotResponsePayload => ({
  reply: localizeCopilotText(
    input.language,
    "Tong ty trong danh muc ban vua nhap dang vuot 100%, nen toi khong the luu ke hoach nay. Hay giam mot vai nhom hoac chi nhap cac nhom quan trong, toi se tu can phan con lai.",
    "The category percentages you sent add up to more than 100%, so I cannot save that plan. Reduce a few buckets or send only the most important ones and I will rebalance the rest.",
  ),
  topic: "budget-plan-category-invalid",
  suggestedActions:
    input.language === "vi"
      ? [
          "Dam bao tong cac % khong vuot 100.",
          "Ban co the chi nhap mot vai danh muc, he thong se tu chia phan con lai.",
          "Vi du: an uong 30%, di lai 10%, hoa don 20%.",
        ]
      : [
          "Keep the total percentage at or below 100.",
          "You can send only a few categories and let the system balance the remainder.",
          "Example: food 30%, transport 10%, bills 20%.",
        ],
  suggestedDepositAmount: null,
  riskLevel: "low",
  confidence: 0.95,
  followUpQuestion: localizeCopilotText(
    input.language,
    "Ban muon toi can lai ty trong neu ban gui lai danh muc khong?",
    "Do you want me to rebalance the mix once you resend the category weights?",
  ),
  budgetPlan: null,
});

const buildBudgetAssistantPreferenceResponse = (input: {
  language: CopilotLanguage;
  preferences: StoredBudgetAssistantPreferences;
}): CopilotResponsePayload => {
  const enabledLines = [
    input.preferences.proactiveRemindersEnabled
      ? localizeCopilotText(
          input.language,
          "Nhac nho chu dong: bat",
          "Proactive reminders: on",
        )
      : localizeCopilotText(
          input.language,
          "Nhac nho chu dong: tat",
          "Proactive reminders: off",
        ),
    input.preferences.dailyDigestEnabled
      ? localizeCopilotText(
          input.language,
          "Bao cao ngay: bat",
          "Daily brief: on",
        )
      : localizeCopilotText(
          input.language,
          "Bao cao ngay: tat",
          "Daily brief: off",
        ),
    input.preferences.weeklyDigestEnabled
      ? localizeCopilotText(
          input.language,
          "Bao cao tuan: bat",
          "Weekly brief: on",
        )
      : localizeCopilotText(
          input.language,
          "Bao cao tuan: tat",
          "Weekly brief: off",
        ),
    input.preferences.monthlyDigestEnabled
      ? localizeCopilotText(
          input.language,
          "Bao cao thang: bat",
          "Monthly brief: on",
        )
      : localizeCopilotText(
          input.language,
          "Bao cao thang: tat",
          "Monthly brief: off",
        ),
  ];

  return {
    reply: [
      localizeCopilotText(
        input.language,
        "Toi da cap nhat che do tro ly tai chinh cho ban.",
        "I updated your VaultAI assistant settings.",
      ),
      "",
      ...enabledLines.map((line) => `- ${line}`),
    ].join("\n"),
    topic: "budget-assistant-preferences-updated",
    suggestedActions:
      input.language === "vi"
        ? [
            "Ban co the bao toi bat hoac tat bao cao ngay, tuan, thang bat cu luc nao.",
            "Hoi toi 'tom tat hom nay' neu muon xem brief ngay lap tuc trong chat.",
            "Chat lai muc tieu chi tieu moi neu muon doi plan hien tai.",
          ]
        : [
            "You can ask me to turn daily, weekly, or monthly briefs on or off anytime.",
            "Ask for 'today summary' if you want the brief immediately in chat.",
            "Send a new spending target anytime if you want to change the active plan.",
          ],
    suggestedDepositAmount: null,
    riskLevel: "low",
    confidence: 0.96,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Ban co muon toi gui brief ngay hoac brief tuan cho ban khong?",
      "Do you want me to enable daily or weekly briefs for you?",
    ),
    budgetPlan: null,
  };
};

const escapeCopilotMarkdownCell = (value: string | number) =>
  String(value).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

const buildCopilotMarkdownTable = (
  headers: string[],
  rows: Array<Array<string | number>>,
) => {
  const normalizedHeaders = headers.map(escapeCopilotMarkdownCell);
  const separator = headers.map(() => "---");
  const normalizedRows = rows.map((row) =>
    row.map((cell) => escapeCopilotMarkdownCell(cell)),
  );

  return [
    `| ${normalizedHeaders.join(" | ")} |`,
    `| ${separator.join(" | ")} |`,
    ...normalizedRows.map((row) => `| ${row.join(" | ")} |`),
  ].join("\n");
};

const formatCopilotTransactionTimestamp = (
  language: CopilotLanguage,
  value: Date,
  mode: "time" | "datetime" = "time",
) =>
  value.toLocaleString(language === "vi" ? "vi-VN" : "en-US", {
    timeZone: APP_TIMEZONE,
    year: mode === "datetime" ? "numeric" : undefined,
    month: mode === "datetime" ? "2-digit" : undefined,
    day: mode === "datetime" ? "2-digit" : undefined,
    hour: "2-digit",
    minute: "2-digit",
    hour12: language !== "vi",
  });

const formatCopilotCalendarDate = (language: CopilotLanguage, value: Date) =>
  value.toLocaleDateString(language === "vi" ? "vi-VN" : "en-US", {
    timeZone: APP_TIMEZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });

const normalizeCopilotRiskLevel = (value: unknown) => {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  return normalized === "high" || normalized === "medium" ? normalized : "low";
};

const buildAnomalyGuidance = (input: {
  riskLevel: "low" | "medium" | "high";
  reasons: string[];
  requireOtp: boolean;
  otpChannel?: string | null;
  otpReason?: string | null;
  warning?: AnomalyResponse["warning"];
}) => {
  const joinedSignals = [
    ...input.reasons,
    input.otpReason || "",
    input.warning?.title || "",
    input.warning?.message || "",
  ]
    .join(" ")
    .toLowerCase();
  const primaryReason =
    dedupeStringList([
      input.warning?.message,
      ...input.reasons,
      input.otpReason,
    ])[0] || "The activity differs from your normal pattern.";

  const archetype = /credential|failed attempt|password/i.test(joinedSignals)
    ? "Credential Abuse Pattern"
    : /new or untrusted ip|different ip|different device|new device|vpn/i.test(
          joinedSignals,
        ) || input.requireOtp
      ? "New Device / Network Shift"
      : input.riskLevel === "high"
        ? "High-Risk Session Change"
        : input.riskLevel === "medium"
          ? "Behavior Drift"
          : "Low-Severity Deviation";

  const headline =
    input.warning?.title ||
    (input.requireOtp
      ? input.riskLevel === "high"
        ? "AI security review escalated this activity"
        : "AI requested an extra identity check"
      : input.riskLevel === "high"
        ? "AI detected a high-risk security pattern"
        : input.riskLevel === "medium"
          ? "AI detected an unusual security pattern"
          : "AI observed a low-severity deviation");

  const summary = input.requireOtp
    ? `${primaryReason} Extra verification was triggered${input.otpChannel ? ` via ${input.otpChannel}` : ""}${input.otpReason ? ` because ${input.otpReason.toLowerCase()}` : ""}.`
    : input.riskLevel === "high"
      ? `${primaryReason} Treat this as a high-risk event until you verify it was expected.`
      : input.riskLevel === "medium"
        ? `${primaryReason} The behavior is unusual enough to justify a closer review.`
        : `${primaryReason} The signal is mild, but the system still recorded it for protection.`;

  const nextStep = input.requireOtp
    ? `Complete the ${input.otpChannel || "additional"} verification before continuing.`
    : input.riskLevel === "high"
      ? "Pause and verify the activity before you continue."
      : input.riskLevel === "medium"
        ? "Review the signals before you approve the action."
        : "Continue only if the activity looks expected to you.";

  const recommendedActions = dedupeStringList([
    ...(input.warning?.mustDo || []),
    input.requireOtp
      ? `Finish the ${input.otpChannel || "step-up"} check on this session.`
      : null,
    "Verify the device, IP, and timing match your own activity.",
    input.riskLevel === "high"
      ? "If this was not you, stop immediately and reset credentials."
      : "If anything looks unfamiliar, do not approve the action yet.",
    ...(input.warning?.doNot || []).map((item) => `Do not ${item}`),
  ]).slice(0, 4);
  const timeline = dedupeStringList([
    "Signal captured from device, IP, and recent authentication history.",
    /failed attempt|credential/i.test(joinedSignals)
      ? "Recent failed or mismatched credential activity increased the risk score."
      : null,
    /new or untrusted ip|different ip|different device|new device|vpn/i.test(
      joinedSignals,
    ) || input.requireOtp
      ? "The session did not match a trusted sign-in profile."
      : null,
    input.requireOtp
      ? `Step-up verification was triggered${input.otpChannel ? ` via ${input.otpChannel}` : ""}.`
      : input.riskLevel === "high"
        ? "The session is treated as high risk until verified."
        : input.riskLevel === "medium"
          ? "The session should be reviewed before it is trusted."
          : "The event was logged as a low-severity deviation for future comparison.",
  ]).slice(0, 4);

  return {
    archetype,
    headline,
    summary,
    nextStep,
    recommendedActions,
    timeline,
  };
};

const softenLowValueTransferAiResult = (input: {
  aiResult: AnomalyResponse;
  amount: number;
  recipientKnown: boolean;
  suspiciousNoteCount: number;
  failedTx24h: number;
  velocity1h: number;
  sessionRestrictLargeTransfers: boolean;
  faceIdRequired: boolean;
  behaviorProfile: TransferBehaviorProfile;
}): AnomalyResponse => {
  const amount = Math.max(0, Number(input.amount) || 0);
  const lowValueThreshold = Math.max(
    50,
    Math.min(100, TRANSFER_PROBE_SMALL_AMOUNT_MAX),
  );
  const hasProbeBurst =
    input.behaviorProfile.smallProbeCount24h >=
      TRANSFER_PROBE_BURST_COUNT_24H ||
    input.behaviorProfile.sameRecipientSmallProbeCount24h >= 2 ||
    input.behaviorProfile.newRecipientSmallProbeCount24h >= 2 ||
    input.behaviorProfile.distinctSmallProbeRecipients24h >= 3 ||
    input.behaviorProfile.probeThenLargeRiskScore >= 0.45;
  const hasEscalatingSessionSignals =
    input.failedTx24h >= 1 ||
    input.velocity1h >= 3 ||
    input.sessionRestrictLargeTransfers ||
    input.faceIdRequired;
  const hasHistoricalRiskPattern =
    input.behaviorProfile.recentBlockedCount30d >= 2 ||
    input.behaviorProfile.sameRecipientFlaggedCount90d >= 2;

  if (
    amount > lowValueThreshold ||
    input.suspiciousNoteCount > 0 ||
    hasProbeBurst ||
    hasEscalatingSessionSignals ||
    hasHistoricalRiskPattern
  ) {
    return input.aiResult;
  }

  const relaxedReasons = input.recipientKnown
    ? ["Low-value transfer remains under normal AI monitoring."]
    : [
        "Low-value first transfer is being monitored without step-up escalation.",
      ];

  return {
    ...input.aiResult,
    riskLevel: "low",
    reasons: relaxedReasons,
    archetype: input.recipientKnown
      ? "Low Value Transfer"
      : "Low Value New Recipient",
    timeline: dedupeStringList([
      input.recipientKnown
        ? "This recipient already exists in your completed transfer history."
        : "This is a first-time recipient, but the amount is still in the low-value band.",
      "No repeated small-transfer burst or scam-pressure signal was confirmed for this payment.",
      "The transfer stays under normal monitoring unless stronger signals appear.",
    ]).slice(0, 3),
    headline: input.recipientKnown
      ? "Low-value transfer stays in normal monitoring"
      : "Low-value first transfer stays under light monitoring",
    summary: input.recipientKnown
      ? "This payment is low value and does not show the repeated probing pattern needed for step-up protection."
      : "This payment is low value and does not show the repeated small-transfer pattern that would justify scam escalation.",
    nextStep:
      "Allow the transfer and continue passive monitoring for repeated low-value bursts.",
    recommendedActions: dedupeStringList([
      ...(input.recipientKnown
        ? []
        : ["Double-check the recipient once before sending."]),
      "Continue normal monitoring and escalate only if repeated low-value attempts appear in a short time.",
    ]).slice(0, 3),
    requireOtp: false,
    otpReason: null,
    finalAction: "ALLOW",
    finalScore: input.recipientKnown ? 12 : 24,
    baseScore:
      typeof input.aiResult.baseScore === "number"
        ? input.aiResult.baseScore
        : 0,
    mitigationScore:
      typeof input.aiResult.baseScore === "number"
        ? Math.max(
            0,
            input.aiResult.baseScore - (input.recipientKnown ? 12 : 24),
          )
        : input.aiResult.mitigationScore,
    warning: null,
    ruleHits: [],
    ruleHitCount: 0,
    ruleRiskLevel: "low",
    modelRiskLevel: "low",
    stepUpLevel: null,
  };
};

const sanitizeCopilotText = (value: string) =>
  value
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

const polishCopilotReplyText = (value: string) =>
  value
    .replace(/^Bạn có muốn tôi[^?]*\?\s*/iu, "")
    .replace(/^Ban co muon toi[^?]*\?\s*/iu, "")
    .replace(/^Would you like me[^?]*\?\s*/iu, "")
    .replace(/^Do you want me to[^?]*\?\s*/iu, "")
    .replace(/^Tôi có thể giúp[^.?!]*[.?!]\s*/iu, "")
    .replace(/^Toi co the giup[^.?!]*[.?!]\s*/iu, "")
    .replace(/^I can help[^.?!]*[.?!]\s*/iu, "")
    .trim();

const polishCopilotFollowUpQuestion = (value: string | null | undefined) => {
  const cleaned = String(value || "").trim();
  if (!cleaned) return null;
  if (
    /^(Bạn có muốn tôi cung cấp thêm thông tin nào khác không\??|Ban co muon toi cung cap them thong tin nao khac khong\??|Would you like more information\??|Do you want more information\??)$/iu.test(
      cleaned,
    )
  ) {
    return null;
  }
  return cleaned;
};

const extractCopilotJsonCandidate = (value: string) => {
  const sanitized = sanitizeCopilotText(value);
  if (!sanitized) return "";
  if (sanitized.startsWith("{") && sanitized.endsWith("}")) {
    return sanitized;
  }

  const firstBrace = sanitized.indexOf("{");
  const lastBrace = sanitized.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    return sanitized.slice(firstBrace, lastBrace + 1).trim();
  }

  return sanitized;
};

const buildFallbackCopilotPayload = (
  value: string,
): CopilotResponsePayload | null => {
  const cleaned = polishCopilotReplyText(sanitizeCopilotText(value));
  if (!cleaned) return null;

  const normalized = normalizeCopilotText(cleaned);
  const highRisk =
    /\b(scam|fraud|otp|pin|password|faceid|remote access|screen share|lua dao|ma otp|mat khau|pin)\b/.test(
      normalized,
    );
  const mediumRisk =
    highRisk ||
    /\b(risk|volatile|drawdown|debt|loan|margin|rui ro|bien dong|no vay)\b/.test(
      normalized,
    );

  return {
    reply: cleaned,
    topic: "copilot-chat",
    suggestedActions: [],
    suggestedDepositAmount: null,
    riskLevel: highRisk ? "high" : mediumRisk ? "medium" : "low",
    confidence: 0.58,
    followUpQuestion: null,
  };
};

const parseOpenAiCopilotPayload = (
  value: string,
): CopilotResponsePayload | null => {
  try {
    const parsed = JSON.parse(extractCopilotJsonCandidate(value)) as Record<
      string,
      unknown
    >;
    if (typeof parsed.reply !== "string" || !parsed.reply.trim()) return null;

    const suggestedActions = Array.isArray(parsed.suggestedActions)
      ? parsed.suggestedActions.filter(
          (item): item is string =>
            typeof item === "string" && item.trim().length > 0,
        )
      : [];

    const reply = polishCopilotReplyText(parsed.reply.trim());
    if (!reply) return null;

    return {
      reply,
      topic:
        typeof parsed.topic === "string" && parsed.topic.trim()
          ? parsed.topic.trim()
          : "financial-guidance",
      suggestedActions: suggestedActions.slice(0, 5),
      suggestedDepositAmount:
        typeof parsed.suggestedDepositAmount === "number" &&
        Number.isFinite(parsed.suggestedDepositAmount)
          ? parsed.suggestedDepositAmount
          : null,
      riskLevel: normalizeCopilotRiskLevel(parsed.riskLevel),
      confidence: clamp(Number(parsed.confidence || 0.72), 0.4, 0.99),
      followUpQuestion: polishCopilotFollowUpQuestion(
        typeof parsed.followUpQuestion === "string" &&
          parsed.followUpQuestion.trim()
          ? parsed.followUpQuestion.trim()
          : null,
      ),
    };
  } catch {
    return buildFallbackCopilotPayload(value);
  }
};

const normalizeCopilotIntent = (value: unknown): CopilotIntent => {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (
    normalized === "finance_education" ||
    normalized === "market_data" ||
    normalized === "portfolio_analysis" ||
    normalized === "spending_analysis" ||
    normalized === "budgeting_help" ||
    normalized === "transaction_review" ||
    normalized === "anomaly_check"
  ) {
    return normalized;
  }
  return "unsupported";
};

const normalizeCopilotIntentTool = (
  value: unknown,
): CopilotIntentTool | null => {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (
    normalized === "wallet_summary" ||
    normalized === "wallet_transactions" ||
    normalized === "market_quote" ||
    normalized === "security_signals"
  ) {
    return normalized;
  }
  return null;
};

const parseCopilotIntentClassification = (
  value: string,
): CopilotIntentClassification | null => {
  try {
    const parsed = JSON.parse(extractCopilotJsonCandidate(value)) as Record<
      string,
      unknown
    >;
    const reason =
      typeof parsed.reason === "string" && parsed.reason.trim()
        ? parsed.reason.trim()
        : "";
    if (!reason) return null;
    const requiredTools = Array.isArray(parsed.required_tools)
      ? parsed.required_tools
          .map((item) => normalizeCopilotIntentTool(item))
          .filter((item): item is CopilotIntentTool => Boolean(item))
      : [];

    return {
      intent: normalizeCopilotIntent(parsed.intent),
      needs_tools: parsed.needs_tools === true,
      required_tools: requiredTools,
      reason,
    };
  } catch {
    return null;
  }
};

const classifyCopilotIntentHeuristically = (
  latestMessage: string,
  options?: { priorUserMessage?: string | null },
): CopilotIntentClassification => {
  const normalized = normalizeCopilotText(latestMessage);
  const asksAnalyticalMarketQuestion =
    /\b(phan tich|danh gia|outlook|thesis|trend|xu huong|on dinh|bien dong|volatility|rui ro|risk|1 nam|1 year|one year|12 thang|12 months|dai han|long term|ngan han|short term|trung han|medium term)\b/.test(
      normalized,
    );

  if (
    /\b(scam|fraud|lua dao|otp|faceid|pin|mat khau|password|remote access|screen share|bat thuong|anomaly|suspicious|nghi ngo|safe account|tai khoan an toan)\b/.test(
      normalized,
    )
  ) {
    return {
      intent: "anomaly_check",
      needs_tools: true,
      required_tools: ["security_signals", "wallet_transactions"],
      reason:
        "The user is asking about suspicious activity, scam signals, or abnormal transaction behavior.",
    };
  }

  if (
    isBudgetPlanRebuildIntent(latestMessage, options?.priorUserMessage || null)
  ) {
    return {
      intent: "budgeting_help",
      needs_tools: true,
      required_tools: ["wallet_summary", "wallet_transactions"],
      reason:
        "The user wants VaultAI to rebuild or rebalance an existing budget plan based on current spending context.",
    };
  }

  if (isBudgetGoalPlanningIntent(latestMessage)) {
    return {
      intent: "budgeting_help",
      needs_tools: true,
      required_tools: ["wallet_summary", "wallet_transactions"],
      reason:
        "The user is defining a spending cap, savings goal, or a budget plan that should be handled by VaultAI budgeting logic.",
    };
  }

  if (
    isSpendingComparisonIntent(latestMessage, options?.priorUserMessage || null)
  ) {
    return {
      intent: "spending_analysis",
      needs_tools: true,
      required_tools: ["wallet_transactions", "wallet_summary"],
      reason:
        "The user wants spending trends, comparisons, or outflow analysis based on transaction history.",
    };
  }

  if (
    isTodayTransactionReportIntent(latestMessage) ||
    isWeeklyTransactionReportIntent(latestMessage) ||
    isMonthlyTransactionReportIntent(latestMessage) ||
    /\b(statement|sao ke|transaction history|lich su giao dich|giao dich cua toi|my transactions)\b/.test(
      normalized,
    )
  ) {
    return {
      intent: "transaction_review",
      needs_tools: true,
      required_tools: ["wallet_transactions"],
      reason:
        "The user is asking to review recorded transactions or account statement activity.",
    };
  }

  if (
    /\b(budget|budgeting|ngan sach|chi tieu hop ly|chi tieu|tieu toi da|tieu khoang|saving plan|tiet kiem|de danh|save up|save for|emergency fund|quy du phong|cash flow plan|ke hoach chi tieu|nhac nho|reminder|digest|brief|tom tat|summary)\b/.test(
      normalized,
    ) ||
    (extractBudgetCategoryAllocationShares(latestMessage) !== null &&
      /\d{1,3}(?:[.,]\d+)?\s*%/.test(normalized))
  ) {
    return {
      intent: "budgeting_help",
      needs_tools: true,
      required_tools: ["wallet_summary", "wallet_transactions"],
      reason:
        "The user is asking for budgeting, savings planning, or cash-flow guidance.",
    };
  }

  if (isExplicitLiveQuoteRequest(latestMessage)) {
    return {
      intent: "market_data",
      needs_tools: true,
      required_tools: ["market_quote"],
      reason:
        "The user is asking for a market price, live quote, exchange rate, or ticker-specific market data.",
    };
  }

  if (
    (detectMarketIntent(latestMessage) && asksAnalyticalMarketQuestion) ||
    /\b(portfolio|allocation|phan bo|etf|index fund|diversif|da dang hoa|valuation|p\/e|eps|market cap|dividend|free cash flow|fcf|co phieu|chung khoan|watchlist)\b/.test(
      normalized,
    )
  ) {
    return {
      intent: "portfolio_analysis",
      needs_tools: false,
      required_tools: [],
      reason:
        "The user is asking for educational portfolio, stock, valuation, or diversification analysis rather than exact live data.",
    };
  }

  if (
    /\b(finance|tai chinh|interest rate|lai suat|inflation|lam phat|bond|trai phieu|mutual fund|fundamentals|valuation basics|what is|la gi)\b/.test(
      normalized,
    )
  ) {
    return {
      intent: "finance_education",
      needs_tools: false,
      required_tools: [],
      reason:
        "The user is asking for general finance or market education that does not require live account data.",
    };
  }

  return {
    intent: "unsupported",
    needs_tools: false,
    required_tools: [],
    reason:
      "The request does not clearly match the supported finance, spending, transaction, or anomaly-review workflows.",
  };
};

const classifyCopilotIntent = async (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
}): Promise<CopilotIntentClassification> => {
  const contextualLatestUserMessage = buildContextAwareCopilotUserMessage(
    input.messages,
  );
  const latestUserMessage =
    [...input.messages].reverse().find((message) => message.role === "user")
      ?.content || "";
  const previousUserMessage =
    input.messages.filter((message) => message.role === "user").slice(-2, -1)[0]
      ?.content || "";
  const heuristic = classifyCopilotIntentHeuristically(
    contextualLatestUserMessage || latestUserMessage,
    {
      priorUserMessage: previousUserMessage,
    },
  );

  const isHighConfidenceHeuristic =
    heuristic.intent === "transaction_review" ||
    (heuristic.intent === "budgeting_help" &&
      isBudgetPlanRebuildIntent(
        contextualLatestUserMessage || latestUserMessage,
        previousUserMessage,
      )) ||
    (heuristic.intent === "spending_analysis" &&
      isSpendingComparisonIntent(latestUserMessage, previousUserMessage)) ||
    heuristic.intent === "anomaly_check" ||
    (heuristic.intent === "portfolio_analysis" &&
      Boolean(detectMarketIntent(latestUserMessage))) ||
    (heuristic.intent === "market_data" &&
      isExplicitLiveQuoteRequest(latestUserMessage));

  if (isHighConfidenceHeuristic) {
    return heuristic;
  }

  const classifierInput = {
    currency: input.currency,
    currentBalance: input.currentBalance,
    monthlyIncome: input.monthlyIncome,
    monthlyExpenses: input.monthlyExpenses,
    recentTransactions: input.recentTransactions,
    messages: input.messages,
    language: input.language,
  };

  const ollamaResult = await callOllamaCopilotClassifier(classifierInput);
  if (ollamaResult.status === "ok") {
    const payload = ollamaResult.payload;
    if (
      payload.intent !== "unsupported" ||
      heuristic.intent === "unsupported"
    ) {
      return payload;
    }
  }

  const openAiResult = await callOpenAiCopilotClassifier(classifierInput);
  if (openAiResult.status === "ok") {
    const payload = openAiResult.payload;
    if (
      payload.intent !== "unsupported" ||
      heuristic.intent === "unsupported"
    ) {
      return payload;
    }
  }

  return heuristic;
};

const shouldAllowExternalCopilotContext = (
  classification: CopilotIntentClassification | null | undefined,
) => {
  if (ALLOW_EXTERNAL_FINANCIAL_CONTEXT) return true;
  const intent = classification?.intent || "unsupported";
  return (
    intent === "finance_education" ||
    intent === "portfolio_analysis" ||
    intent === "market_data" ||
    intent === "unsupported"
  );
};

const summarizeCopilotConversation = (messages: CopilotMessagePayload[]) =>
  messages
    .slice(-12)
    .map(
      (message) =>
        `${message.role === "assistant" ? "Assistant" : message.role === "system" ? "System" : "User"}: ${message.content.trim()}`,
    )
    .join("\n");

const summarizeCopilotTransactions = (
  transactions: CopilotTransactionPayload[],
  currency: string,
) =>
  summarizeRecentTransactions(transactions)
    .map((transaction) => {
      const amount = Math.max(0, Number(transaction.amount || 0));
      const when = new Date(transaction.createdAt);
      const whenLabel = Number.isNaN(when.getTime())
        ? transaction.createdAt
        : when.toISOString();
      return [
        transaction.direction === "debit" ? "debit" : "credit",
        `${currency} ${formatMarketPrice(amount)}`,
        transaction.type,
        transaction.description || "no description",
        whenLabel,
      ].join(" | ");
    })
    .join("\n");

const normalizeCopilotKnowledgeText = (value: string) =>
  value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();

const buildRelevantFinanceKnowledgeSummary = (
  messages: CopilotMessagePayload[],
) => {
  const latestUserMessage =
    [...messages].reverse().find((message) => message.role === "user")
      ?.content || "";
  const normalizedMessage = normalizeCopilotKnowledgeText(latestUserMessage);
  if (!normalizedMessage.trim()) {
    return "No directly matched finance entities.";
  }

  const matchedEntries = COPILOT_FINANCE_KNOWLEDGE.filter((entry) =>
    entry.aliases.some((alias) => normalizedMessage.includes(alias)),
  ).slice(0, 8);

  if (!matchedEntries.length) {
    return "No directly matched finance entities.";
  }

  return matchedEntries
    .map((entry) =>
      [
        entry.canonical,
        `kind=${entry.kind}`,
        `sector=${entry.sector || "n/a"}`,
        `symbol=${entry.market?.symbol || "n/a"}`,
      ].join(" | "),
    )
    .join("\n");
};

const buildOpenAiCopilotInput = (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
  classification?: CopilotIntentClassification | null;
  shareSensitiveContext?: boolean;
}) => {
  const now = formatMarketTimestamp(new Date());
  const transactionSummary = summarizeCopilotTransactions(
    input.recentTransactions,
    input.currency,
  );
  const conversationSummary = summarizeCopilotConversation(input.messages);
  const latestUserMessage =
    [...input.messages].reverse().find((message) => message.role === "user")
      ?.content || "";
  const financeKnowledgeSummary = buildRelevantFinanceKnowledgeSummary(
    input.messages,
  );

  return [
    `Current time: ${now}`,
    `Preferred response language: ${input.language === "vi" ? "Vietnamese" : "English"}`,
    `Intent classification: ${input.classification?.intent || "unsupported"}`,
    `Classification reason: ${input.classification?.reason || "No classifier reason available."}`,
    `Required tools: ${
      input.classification?.required_tools?.length
        ? input.classification.required_tools.join(", ")
        : "none"
    }`,
    ...(input.shareSensitiveContext === false
      ? [
          "Wallet context sharing policy:",
          "Sensitive wallet balances and transaction records are withheld from this external model call. Answer using general finance reasoning plus the visible conversation only.",
        ]
      : [
          `Wallet currency: ${input.currency}`,
          `Wallet balance: ${input.currency} ${formatMarketPrice(
            Math.max(0, input.currentBalance),
          )}`,
          `Estimated monthly income: ${input.currency} ${formatMarketPrice(
            Math.max(0, input.monthlyIncome),
          )}`,
          `Estimated monthly expenses: ${input.currency} ${formatMarketPrice(
            Math.max(0, input.monthlyExpenses),
          )}`,
          "Recent wallet transactions:",
          transactionSummary || "No recent transactions available.",
        ]),
    "Latest user message:",
    latestUserMessage || "No latest message available.",
    "Recognized finance entities:",
    financeKnowledgeSummary,
    "Source-of-truth policy:",
    "Use only wallet context, transaction records, and tool results from this prompt as facts. Never invent prices, balances, portfolio values, or transaction history. If exact data is unavailable, state that clearly.",
    "Conversation transcript:",
    conversationSummary,
  ].join("\n\n");
};

const buildCopilotClassificationInput = (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
  shareSensitiveContext?: boolean;
}) => {
  const latestUserMessage =
    [...input.messages].reverse().find((message) => message.role === "user")
      ?.content || "";
  const conversationSummary = summarizeCopilotConversation(input.messages);
  const transactionSummary = summarizeCopilotTransactions(
    input.recentTransactions,
    input.currency,
  );

  return [
    `Preferred language context: ${input.language === "vi" ? "Vietnamese" : "English"}`,
    ...(input.shareSensitiveContext === false
      ? [
          "Wallet context sharing policy:",
          "Sensitive wallet balances and transaction records are withheld from this external classifier call.",
        ]
      : [
          `Wallet currency available: ${input.currency}`,
          `Wallet balance available: ${input.currency} ${formatMarketPrice(
            Math.max(0, input.currentBalance),
          )}`,
          `Estimated monthly income available: ${input.currency} ${formatMarketPrice(
            Math.max(0, input.monthlyIncome),
          )}`,
          `Estimated monthly expenses available: ${input.currency} ${formatMarketPrice(
            Math.max(0, input.monthlyExpenses),
          )}`,
          "Recent wallet transactions available to tools:",
          transactionSummary || "No recent transactions available.",
        ]),
    "Latest user message:",
    latestUserMessage || "No latest user message available.",
    "Conversation transcript:",
    conversationSummary || "No prior transcript available.",
  ].join("\n\n");
};

const buildCopilotSystemInstructions = (language: CopilotLanguage) =>
  [
    "You are a financial copilot integrated into a secure academic e-wallet system.",
    "Explain finance, stock market, and personal spending concepts clearly.",
    "Use tool results and database results as the source of truth.",
    "Never invent prices, balances, portfolio values, transaction records, or unsupported historical facts.",
    "If real-time data is unavailable, explicitly say that the data is unavailable.",
    "Do not provide definitive investment advice, guarantee returns, or present speculation as certainty.",
    "For personal-finance questions, prioritize budgeting, risk awareness, and spending insights.",
    "For stock-related questions, provide educational and analytical support only.",
    `Reply in ${language === "vi" ? "Vietnamese" : "English"} and keep the same language as the user's latest message.`,
    "Be concise, structured, and easy to understand.",
    "If confidence is low, say what is uncertain.",
    "Always separate facts, calculations, and suggestions in the reply when that improves clarity.",
    "Maintain continuity with the conversation transcript and resolve references like 'that', 'this', 'last one', or 'in the past week' using recent context.",
    "Start with the answer immediately. The first sentence must address the user's question directly.",
    "Do not begin with permission-seeking, generic offers to help, or by repeating the user's question.",
    "Prefer natural paragraphs first. Use bullets only when they genuinely improve clarity.",
    "Use Markdown tables only when numeric comparisons materially benefit from a table. Do not force tables for every answer.",
    "For short questions, answer compactly and naturally. For complex questions, organize the answer cleanly.",
    "If data is unavailable, say that in one sentence, then still give the most useful next-best analysis.",
    "Only ask a follow-up question after you have already delivered a useful answer.",
    "Use followUpQuestion sparingly; set it to null unless it materially deepens the discussion.",
    "Keep suggestedActions empty unless there are truly useful concrete next steps.",
    "Prioritize user safety over convenience when the message contains signs of fraud, impersonation, urgency, OTP harvesting, remote-access setup, fake refunds, fake investment schemes, or account-takeover attempts.",
    "If a message looks like a scam, clearly say so, tell the user not to send money or codes, and recommend official verification steps.",
    "You can answer broad personal-finance questions even when they are not tied to a live wallet action, including budgeting, debt payoff, emergency funds, savings habits, cash-flow tradeoffs, statement interpretation, and financial planning.",
    "You can answer stock-market, equity, index, ETF, and portfolio-allocation questions at an educational and practical level.",
    "For stock-market questions, help with concepts such as ticker basics, index vs stock, sector concentration, diversification, valuation checkpoints, drawdown risk, and how to read metrics like P/E, EPS, market cap, revenue growth, margin, debt, and free cash flow.",
    "When the user asks for market analysis without requiring exact real-time numbers, provide a concise structured framework and clearly label assumptions.",
    "When the user asks whether buying a stock is sensible, do not collapse the answer into a live quote. Answer with thesis, valuation, downside risk, time horizon, and position-sizing guidance.",
    "You can also help build long-term saving plans and summarize spending across daily, weekly, and monthly periods using wallet context.",
    "When the user asks for a statement or spending comparison, explicitly compare today vs yesterday, this week vs last week, and this month vs last month when relevant.",
    "If the user asks a general finance question and wallet context is not needed, still answer helpfully with practical education, decision frameworks, and clear caveats.",
    "If the user asks a conversational follow-up, answer that follow-up directly instead of resetting to a generic wallet introduction.",
    "Do not claim real-time market prices unless they were already provided by another tool in the app context.",
    "If the user asks for exact live market prices and no live quote is present, say that the data is unavailable.",
    "Return valid JSON only with these keys:",
    "reply, topic, suggestedActions, suggestedDepositAmount, riskLevel, confidence, followUpQuestion",
    "The reply field may contain Markdown.",
    "suggestedActions may be an empty array.",
    "riskLevel must be one of: low, medium, high.",
    "confidence must be a number between 0 and 1.",
    "suggestedActions must be an array of short strings.",
    "suggestedDepositAmount must be a number or null.",
    "followUpQuestion must be a string or null.",
  ].join(" ");

const buildCopilotClassificationInstructions = () =>
  [
    "You are a financial copilot query classifier integrated into a secure academic e-wallet system.",
    "Use tool results and database results as the source of truth.",
    "Never invent prices, balances, portfolio values, or transaction records.",
    "If real-time data is unavailable, the downstream assistant must say that the data is unavailable.",
    "Do not provide definitive investment advice or guarantee returns.",
    "For personal finance questions, prioritize budgeting, risk awareness, and spending insights.",
    "For stock-related questions, provide educational and analytical support only.",
    "Be concise, structured, and easy to understand.",
    "Classify the user query into exactly one intent from this list:",
    "finance_education, market_data, portfolio_analysis, spending_analysis, budgeting_help, transaction_review, anomaly_check, unsupported.",
    "If the user asks for exact market prices, exchange rates, or ticker quotes, choose market_data.",
    "If the user asks whether a stock has been stable over months or a year, or asks for trend, outlook, volatility, or risk analysis without needing an exact live price, choose portfolio_analysis.",
    "If the user asks to review transactions, statements, or recent wallet activity, choose transaction_review.",
    "If the user asks for spending trends, category insights, or outflow comparisons, choose spending_analysis.",
    "If the user asks for budgeting, savings planning, or cash-flow discipline, choose budgeting_help.",
    "If the user asks about scams, suspicious transfers, anomalies, or risky behavior, choose anomaly_check.",
    "If the user asks for stock, ETF, diversification, valuation, or portfolio concepts without needing exact live prices, choose portfolio_analysis.",
    "If the user asks for broad finance concepts, choose finance_education.",
    "Use required_tools only from this list: wallet_summary, wallet_transactions, market_quote, security_signals.",
    "Return JSON only with these keys:",
    "intent, needs_tools, required_tools, reason",
    "needs_tools must be boolean.",
    "reason must be one short sentence.",
  ].join(" ");

const callOllamaCopilotWithModel = async (
  input: {
    currency: string;
    currentBalance: number;
    monthlyIncome: number;
    monthlyExpenses: number;
    recentTransactions: CopilotTransactionPayload[];
    messages: CopilotMessagePayload[];
    language: CopilotLanguage;
    classification?: CopilotIntentClassification | null;
  },
  options: { model: string; timeoutMs: number },
): Promise<OllamaCopilotResult> => {
  if (!options.model.trim()) return { status: "disabled" };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);

  try {
    const response = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        model: options.model,
        prompt: buildOpenAiCopilotInput(input),
        system: buildCopilotSystemInstructions(input.language),
        format: "json",
        stream: false,
        options: {
          temperature: OLLAMA_TEMPERATURE,
          top_p: OLLAMA_TOP_P,
          repeat_penalty: OLLAMA_REPEAT_PENALTY,
          num_ctx: OLLAMA_NUM_CTX,
          num_predict: OLLAMA_NUM_PREDICT,
        },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      return {
        status: "error",
        code:
          response.status === 404
            ? "ollama_model_not_found"
            : response.status === 400
              ? "ollama_bad_request"
              : `ollama_http_${response.status}`,
        message:
          errorText || `Ollama request failed with status ${response.status}`,
      };
    }

    const payload = (await response.json().catch(() => null)) as Record<
      string,
      unknown
    > | null;
    const responseText =
      payload && typeof payload.response === "string"
        ? payload.response.trim()
        : "";
    if (!responseText) {
      return {
        status: "error",
        code: "ollama_empty_response",
        message: "Ollama returned an empty response.",
      };
    }

    const parsed = parseOpenAiCopilotPayload(responseText);
    if (!parsed) {
      return {
        status: "error",
        code: "ollama_invalid_response_format",
        message:
          "Ollama returned a response that did not match the expected format.",
      };
    }

    return { status: "ok", payload: parsed };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const code =
      message.includes("ECONNREFUSED") || message.includes("fetch failed")
        ? "ollama_unreachable"
        : message.includes("aborted")
          ? "ollama_timeout"
          : "ollama_unknown_error";
    return { status: "error", code, message };
  } finally {
    clearTimeout(timeout);
  }
};

const callOllamaCopilot = async (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
  classification?: CopilotIntentClassification | null;
}): Promise<OllamaCopilotResult> => {
  if (!OLLAMA_MODEL.trim()) return { status: "disabled" };

  const primaryResult = await callOllamaCopilotWithModel(input, {
    model: OLLAMA_MODEL,
    timeoutMs: OLLAMA_TIMEOUT_MS,
  });
  if (primaryResult.status === "ok" || primaryResult.status === "disabled") {
    return primaryResult;
  }

  const fallbackModel = OLLAMA_FALLBACK_MODEL.trim();
  if (!fallbackModel || fallbackModel === OLLAMA_MODEL.trim()) {
    return primaryResult;
  }

  if (
    primaryResult.code !== "ollama_timeout" &&
    primaryResult.code !== "ollama_model_not_found" &&
    primaryResult.code !== "ollama_unreachable" &&
    primaryResult.code !== "ollama_invalid_response_format"
  ) {
    return primaryResult;
  }

  const fallbackResult = await callOllamaCopilotWithModel(input, {
    model: fallbackModel,
    timeoutMs: OLLAMA_FALLBACK_TIMEOUT_MS,
  });
  return fallbackResult.status === "ok" ? fallbackResult : primaryResult;
};

const callOllamaCopilotClassifierWithModel = async (
  input: {
    currency: string;
    currentBalance: number;
    monthlyIncome: number;
    monthlyExpenses: number;
    recentTransactions: CopilotTransactionPayload[];
    messages: CopilotMessagePayload[];
    language: CopilotLanguage;
  },
  options: { model: string; timeoutMs: number },
): Promise<OllamaCopilotClassificationResult> => {
  if (!options.model.trim()) return { status: "disabled" };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);

  try {
    const response = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        model: options.model,
        prompt: buildCopilotClassificationInput(input),
        system: buildCopilotClassificationInstructions(),
        format: "json",
        stream: false,
        options: {
          temperature: 0.05,
          top_p: 0.3,
          repeat_penalty: 1,
          num_ctx: Math.min(OLLAMA_NUM_CTX, 2048),
          num_predict: 220,
        },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      return {
        status: "error",
        code:
          response.status === 404
            ? "ollama_model_not_found"
            : response.status === 400
              ? "ollama_bad_request"
              : `ollama_http_${response.status}`,
        message:
          errorText || `Ollama request failed with status ${response.status}`,
      };
    }

    const payload = (await response.json().catch(() => null)) as Record<
      string,
      unknown
    > | null;
    const responseText =
      payload && typeof payload.response === "string"
        ? payload.response.trim()
        : "";
    if (!responseText) {
      return {
        status: "error",
        code: "ollama_empty_response",
        message: "Ollama returned an empty classifier response.",
      };
    }

    const parsed = parseCopilotIntentClassification(responseText);
    if (!parsed) {
      return {
        status: "error",
        code: "ollama_invalid_response_format",
        message:
          "Ollama returned a classifier response that did not match the expected format.",
      };
    }

    return { status: "ok", payload: parsed };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const code =
      message.includes("ECONNREFUSED") || message.includes("fetch failed")
        ? "ollama_unreachable"
        : message.includes("aborted")
          ? "ollama_timeout"
          : "ollama_unknown_error";
    return { status: "error", code, message };
  } finally {
    clearTimeout(timeout);
  }
};

const callOllamaCopilotClassifier = async (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
}): Promise<OllamaCopilotClassificationResult> => {
  if (!OLLAMA_MODEL.trim()) return { status: "disabled" };

  const primaryResult = await callOllamaCopilotClassifierWithModel(input, {
    model: OLLAMA_MODEL,
    timeoutMs: Math.min(OLLAMA_TIMEOUT_MS, 12000),
  });
  if (primaryResult.status === "ok" || primaryResult.status === "disabled") {
    return primaryResult;
  }

  const fallbackModel = OLLAMA_FALLBACK_MODEL.trim();
  if (!fallbackModel || fallbackModel === OLLAMA_MODEL.trim()) {
    return primaryResult;
  }

  const fallbackResult = await callOllamaCopilotClassifierWithModel(input, {
    model: fallbackModel,
    timeoutMs: Math.min(OLLAMA_FALLBACK_TIMEOUT_MS, 8000),
  });
  return fallbackResult.status === "ok" ? fallbackResult : primaryResult;
};

const callOpenAiCopilot = async (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
  classification?: CopilotIntentClassification | null;
}): Promise<OpenAiCopilotResult> => {
  if (!openaiClient) return { status: "disabled" };
  const shareSensitiveContext = shouldAllowExternalCopilotContext(
    input.classification,
  );
  if (!shareSensitiveContext && input.classification?.needs_tools) {
    return { status: "disabled" };
  }

  try {
    const response = await openaiClient.responses.create({
      model: OPENAI_MODEL,
      reasoning: {
        effort: OPENAI_REASONING_EFFORT as "low" | "medium" | "high",
      },
      instructions: buildCopilotSystemInstructions(input.language),
      input: buildOpenAiCopilotInput({
        ...input,
        shareSensitiveContext,
      }),
    });

    const responseText =
      typeof response.output_text === "string" && response.output_text.trim()
        ? response.output_text.trim()
        : "";
    if (!responseText) {
      return {
        status: "error",
        code: "empty_response",
        message: "OpenAI returned an empty response.",
      };
    }

    const parsed = parseOpenAiCopilotPayload(responseText);
    if (!parsed) {
      return {
        status: "error",
        code: "invalid_response_format",
        message:
          "OpenAI returned a response that did not match the expected format.",
      };
    }

    return { status: "ok", payload: parsed };
  } catch (err) {
    console.warn("OpenAI copilot request failed", err);
    const errorCode =
      err &&
      typeof err === "object" &&
      "code" in err &&
      typeof err.code === "string"
        ? err.code
        : "unknown_error";
    const errorMessage =
      err instanceof Error && err.message
        ? err.message
        : "OpenAI request failed";
    return {
      status: "error",
      code: errorCode,
      message: errorMessage,
    };
  }
};

const callOpenAiCopilotClassifier = async (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
}): Promise<OpenAiCopilotClassificationResult> => {
  if (!openaiClient) return { status: "disabled" };
  if (!ALLOW_EXTERNAL_FINANCIAL_CONTEXT) {
    return { status: "disabled" };
  }

  try {
    const response = await openaiClient.responses.create({
      model: OPENAI_MODEL,
      reasoning: {
        effort: "low",
      },
      instructions: buildCopilotClassificationInstructions(),
      input: buildCopilotClassificationInput({
        ...input,
        shareSensitiveContext: ALLOW_EXTERNAL_FINANCIAL_CONTEXT,
      }),
    });

    const responseText =
      typeof response.output_text === "string" && response.output_text.trim()
        ? response.output_text.trim()
        : "";
    if (!responseText) {
      return {
        status: "error",
        code: "empty_response",
        message: "OpenAI returned an empty classifier response.",
      };
    }

    const parsed = parseCopilotIntentClassification(responseText);
    if (!parsed) {
      return {
        status: "error",
        code: "invalid_response_format",
        message:
          "OpenAI returned a classifier response that did not match the expected format.",
      };
    }

    return { status: "ok", payload: parsed };
  } catch (err) {
    const errorCode =
      err &&
      typeof err === "object" &&
      "code" in err &&
      typeof err.code === "string"
        ? err.code
        : "unknown_error";
    const errorMessage =
      err instanceof Error && err.message
        ? err.message
        : "OpenAI classifier request failed";
    return {
      status: "error",
      code: errorCode,
      message: errorMessage,
    };
  }
};

const COPILOT_MARKET_TIMEOUT_MS = Number(
  process.env.COPILOT_MARKET_TIMEOUT_MS || "7000",
);

const normalizeCopilotText = (value: string) =>
  value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();

const VIETNAMESE_CHAR_REGEX =
  /[ăâđêôơưáàạảãấầậẩẫắằặẳẵéèẹẻẽếềệểễíìịỉĩóòọỏõốồộổỗớờợởỡúùụủũứừựửữýỳỵỷỹ]/i;

const localizeCopilotText = (
  language: CopilotLanguage,
  vi: string,
  en: string,
) => (language === "vi" ? vi : en);

const detectCopilotLanguage = (message: string): CopilotLanguage => {
  const trimmed = message.trim();
  if (!trimmed) return "en";
  if (VIETNAMESE_CHAR_REGEX.test(trimmed)) return "vi";

  const normalized = normalizeCopilotText(trimmed);
  return /\b(xin chao|chao|toi|minh|ban|giup|bao nhieu|nhu the nao|tai sao|la gi|hom nay|tien|chung khoan|co phieu|ti gia|ty gia|dong tien|tai chinh|tiet kiem|chi tieu|thu nhap|chi phi)\b/.test(
    normalized,
  )
    ? "vi"
    : "en";
};

const isLikelyMarketQuestion = (normalizedMessage: string) =>
  /ty gia|ti gia|exchange rate|fx|forex|gia vang|gold|bitcoin|btc|ethereum|eth|co phieu|chung khoan|stock|share price|ticker|index|nasdaq|dow jones|s&p|vn-index|vnindex|price|bao nhieu|how much|hom nay|today/.test(
    normalizedMessage,
  );

const extractFxIntent = (normalizedMessage: string): MarketIntent | null => {
  const compactMessage = normalizedMessage.replace(/\s+/g, "");
  const slashPair = normalizedMessage.match(
    /\b([a-z]{3})\s*[/-]\s*([a-z]{3})\b/,
  );
  const compactPair = compactMessage.match(/\b([a-z]{3})([a-z]{3})\b/);
  const pair = slashPair || compactPair;
  if (!pair) return null;

  const base = pair[1].toUpperCase();
  const quote = pair[2].toUpperCase();
  if (base === quote) return null;
  if (
    !/[a-z]{3}/.test(pair[1]) ||
    !/[a-z]{3}/.test(pair[2]) ||
    !/(ty gia|ti gia|exchange|rate|fx|forex|usd|eur|jpy|gbp|aud|cad|sgd|vnd)/.test(
      normalizedMessage,
    )
  ) {
    return null;
  }

  return {
    assetClass: "fx",
    symbol: `${base}${quote}=X`,
    label: `${base}/${quote}`,
    quoteHint: quote,
  };
};

const extractTickerIntent = (
  originalMessage: string,
  normalizedMessage: string,
): MarketIntent | null => {
  const hasTickerCue =
    /co phieu|chung khoan|stock|share|ticker|symbol|index|nasdaq|dow|s&p|gia|price|bao nhieu|how much|hom nay|today/.test(
      normalizedMessage,
    );

  for (const [alias, intent] of Object.entries(COPILOT_COMPANY_ALIASES)) {
    if (normalizedMessage.includes(alias) && hasTickerCue) return intent;
  }

  for (const [alias, intent] of Object.entries(COPILOT_INDEX_ALIASES)) {
    if (normalizedMessage.includes(alias) && hasTickerCue) return intent;
  }

  const explicitTicker =
    originalMessage.match(
      /\b(?:ticker|symbol|ma)\s*[:\-]?\s*([A-Za-z^][A-Za-z0-9.=^-]{0,9})\b/i,
    )?.[1] || originalMessage.match(/\b([A-Z]{1,5}(?:\.[A-Z]{1,3})?)\b/)?.[1];

  if (!explicitTicker) return null;
  const symbol = explicitTicker.toUpperCase();
  if (!COPILOT_COMMON_MARKET_SYMBOLS.has(symbol) && symbol.length < 2) {
    return null;
  }

  if (!hasTickerCue) {
    return null;
  }

  return {
    assetClass: /index|nasdaq|dow|s&p|vnindex|vn-index/.test(normalizedMessage)
      ? "index"
      : "stock",
    symbol,
    label: symbol,
  };
};

const detectMarketIntent = (message: string): MarketIntent | null => {
  const normalizedMessage = normalizeCopilotText(message);
  if (!isLikelyMarketQuestion(normalizedMessage)) return null;

  if (/bitcoin|\bbtc\b/.test(normalizedMessage)) {
    return {
      assetClass: "crypto",
      symbol: "BTC-USD",
      label: "Bitcoin",
      quoteHint: "USD",
    };
  }

  if (/ethereum|\beth\b/.test(normalizedMessage)) {
    return {
      assetClass: "crypto",
      symbol: "ETH-USD",
      label: "Ethereum",
      quoteHint: "USD",
    };
  }

  if (/gia vang|gold|\bxau\b/.test(normalizedMessage)) {
    return {
      assetClass: "commodity",
      symbol: "GC=F",
      label: "Gold futures",
      quoteHint: "USD",
    };
  }

  return (
    extractFxIntent(normalizedMessage) ||
    extractTickerIntent(message, normalizedMessage)
  );
};

const collectMarketIntents = (message: string): MarketIntent[] => {
  const normalizedMessage = normalizeCopilotText(message);
  const intents = new Map<string, MarketIntent>();

  const pushIntent = (intent: MarketIntent | null) => {
    if (!intent) return;
    intents.set(intent.symbol, intent);
  };

  pushIntent(extractFxIntent(normalizedMessage));

  for (const [alias, intent] of Object.entries(COPILOT_COMPANY_ALIASES)) {
    if (normalizedMessage.includes(alias)) {
      pushIntent(intent);
    }
  }

  for (const [alias, intent] of Object.entries(COPILOT_INDEX_ALIASES)) {
    if (normalizedMessage.includes(alias)) {
      pushIntent(intent);
    }
  }

  const tickerMatches = message.match(/\b[A-Z]{1,5}(?:\.[A-Z]{1,3})?\b/g) || [];
  for (const rawSymbol of tickerMatches) {
    const symbol = rawSymbol.toUpperCase();
    if (!COPILOT_COMMON_MARKET_SYMBOLS.has(symbol) && symbol.length < 2) {
      continue;
    }
    pushIntent({
      assetClass: /index|nasdaq|dow|s&p|vnindex|vn-index/i.test(message)
        ? "index"
        : "stock",
      symbol,
      label: symbol,
    });
  }

  if (/bitcoin|\bbtc\b/.test(normalizedMessage)) {
    pushIntent({
      assetClass: "crypto",
      symbol: "BTC-USD",
      label: "Bitcoin",
      quoteHint: "USD",
    });
  }

  if (/ethereum|\beth\b/.test(normalizedMessage)) {
    pushIntent({
      assetClass: "crypto",
      symbol: "ETH-USD",
      label: "Ethereum",
      quoteHint: "USD",
    });
  }

  if (/gia vang|gold|\bxau\b/.test(normalizedMessage)) {
    pushIntent({
      assetClass: "commodity",
      symbol: "GC=F",
      label: "Gold futures",
      quoteHint: "USD",
    });
  }

  const primaryIntent = detectMarketIntent(message);
  pushIntent(primaryIntent);

  return Array.from(intents.values()).slice(0, 6);
};

const isMarketAdvisoryRequest = (message: string) => {
  const normalizedMessage = normalizeCopilotText(message);
  return /\b(co nen mua|nen mua|nen ban|co nen ban|should i buy|should i sell|buy now|sell now|phan tich|phan tich rui ro|rui ro|risk|upside|downside|danh gia|outlook|luan diem|thesis|co hop ly khong|worth buying)\b/.test(
    normalizedMessage,
  );
};

const isExplicitLiveQuoteRequest = (message: string) => {
  const normalizedMessage = normalizeCopilotText(message);
  const asksForQuote =
    /\b(gia|price|quote|realtime|real time|bao nhieu|ti gia|ty gia|exchange rate|hom nay gia|today price|latest price|market price)\b/.test(
      normalizedMessage,
    ) ||
    /usd\/vnd|btc-usd|eth-usd|\^[a-z0-9]+|=[xfi]|\b[a-z]{2,5}\/[a-z]{2,5}\b/i.test(
      message,
    );

  return asksForQuote && !isMarketAdvisoryRequest(message);
};

const formatMarketPrice = (value: number) => {
  const decimals = value >= 1000 ? 2 : value >= 100 ? 2 : value >= 1 ? 4 : 6;
  return value.toLocaleString("en-US", {
    minimumFractionDigits: 0,
    maximumFractionDigits: decimals,
  });
};

const formatMarketDelta = (value: number, currency: string) =>
  `${value >= 0 ? "+" : "-"}${currency} ${formatMarketPrice(Math.abs(value))}`;

const formatMarketTimestamp = (value: Date) =>
  value.toLocaleString("en-US", {
    timeZone: APP_TIMEZONE,
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
    timeZoneName: "short",
  });

const fetchMarketQuote = async (
  intent: MarketIntent,
): Promise<MarketQuoteSnapshot | null> => {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    COPILOT_MARKET_TIMEOUT_MS,
  );

  try {
    const response = await fetch(
      `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(
        intent.symbol,
      )}?interval=1d&range=5d&includePrePost=false`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 FPIPay/1.0",
          Accept: "application/json",
        },
        signal: controller.signal,
      },
    );
    if (!response.ok) return null;

    const payload = (await response.json().catch(() => null)) as unknown;
    const chart = normalizeRecord(payload);
    const chartBody = normalizeRecord(chart.chart);
    const result = Array.isArray(chartBody.result)
      ? normalizeRecord(chartBody.result[0])
      : {};
    const meta = normalizeRecord(result.meta);
    const timestamps = Array.isArray(result.timestamp)
      ? result.timestamp.filter(
          (item): item is number =>
            typeof item === "number" && Number.isFinite(item),
        )
      : [];
    const indicators = normalizeRecord(result.indicators);
    const quoteGroup = Array.isArray(indicators.quote)
      ? normalizeRecord(indicators.quote[0])
      : {};
    const closes = Array.isArray(quoteGroup.close)
      ? quoteGroup.close.filter(
          (item): item is number =>
            typeof item === "number" && Number.isFinite(item),
        )
      : [];
    const price =
      asNumberOrNull(meta.regularMarketPrice) ??
      asNumberOrNull(closes.length ? closes[closes.length - 1] : null) ??
      null;
    const previousClose =
      asNumberOrNull(meta.previousClose) ??
      asNumberOrNull(meta.chartPreviousClose) ??
      null;
    const marketTime =
      asNumberOrNull(meta.regularMarketTime) ??
      asNumberOrNull(
        timestamps.length ? timestamps[timestamps.length - 1] : null,
      ) ??
      null;
    const currency = asStringOrNull(meta.currency) ?? intent.quoteHint ?? "USD";

    if (price === null || marketTime === null) return null;

    const change =
      previousClose !== null && Number.isFinite(previousClose)
        ? roundMoney(price - previousClose)
        : null;
    const changePercent =
      previousClose && Number.isFinite(previousClose) && previousClose !== 0
        ? roundMoney(((price - previousClose) / previousClose) * 100)
        : null;

    return {
      symbol: intent.symbol,
      label: intent.label,
      assetClass: intent.assetClass,
      price,
      currency,
      previousClose,
      change,
      changePercent,
      exchangeName: asStringOrNull(meta.exchangeName),
      marketState: asStringOrNull(meta.marketState),
      asOf: new Date(marketTime * 1000),
      source: "Yahoo Finance",
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
};

const fetchMarketAnalysisSnapshot = async (
  intent: MarketIntent,
): Promise<MarketAnalysisSnapshot | null> => {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    COPILOT_MARKET_TIMEOUT_MS,
  );

  try {
    const response = await fetch(
      `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(
        intent.symbol,
      )}?interval=1d&range=1y&includePrePost=false`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 FPIPay/1.0",
          Accept: "application/json",
        },
        signal: controller.signal,
      },
    );
    if (!response.ok) return null;

    const payload = (await response.json().catch(() => null)) as unknown;
    const chart = normalizeRecord(payload);
    const chartBody = normalizeRecord(chart.chart);
    const result = Array.isArray(chartBody.result)
      ? normalizeRecord(chartBody.result[0])
      : {};
    const meta = normalizeRecord(result.meta);
    const timestamps = Array.isArray(result.timestamp)
      ? result.timestamp.filter(
          (item): item is number =>
            typeof item === "number" && Number.isFinite(item),
        )
      : [];
    const indicators = normalizeRecord(result.indicators);
    const quoteGroup = Array.isArray(indicators.quote)
      ? normalizeRecord(indicators.quote[0])
      : {};
    const closes = Array.isArray(quoteGroup.close)
      ? quoteGroup.close.filter(
          (item): item is number =>
            typeof item === "number" && Number.isFinite(item),
        )
      : [];

    const price =
      asNumberOrNull(meta.regularMarketPrice) ??
      asNumberOrNull(closes.length ? closes[closes.length - 1] : null) ??
      null;
    const previousClose =
      asNumberOrNull(meta.previousClose) ??
      asNumberOrNull(meta.chartPreviousClose) ??
      null;
    const marketTime =
      asNumberOrNull(meta.regularMarketTime) ??
      asNumberOrNull(
        timestamps.length ? timestamps[timestamps.length - 1] : null,
      ) ??
      null;
    const currency = asStringOrNull(meta.currency) ?? intent.quoteHint ?? "USD";
    if (price === null || marketTime === null) return null;

    const firstClose = closes.length ? closes[0] : null;
    const oneYearStartPrice =
      firstClose !== null && Number.isFinite(firstClose)
        ? roundMoney(firstClose)
        : null;
    const oneYearChange =
      oneYearStartPrice !== null ? roundMoney(price - oneYearStartPrice) : null;
    const oneYearChangePercent =
      oneYearStartPrice !== null && oneYearStartPrice !== 0
        ? roundMoney(((price - oneYearStartPrice) / oneYearStartPrice) * 100)
        : null;

    return {
      symbol: intent.symbol,
      label: intent.label,
      assetClass: intent.assetClass,
      price,
      currency,
      previousClose,
      change:
        previousClose !== null && Number.isFinite(previousClose)
          ? roundMoney(price - previousClose)
          : null,
      changePercent:
        previousClose && Number.isFinite(previousClose) && previousClose !== 0
          ? roundMoney(((price - previousClose) / previousClose) * 100)
          : null,
      exchangeName: asStringOrNull(meta.exchangeName),
      marketState: asStringOrNull(meta.marketState),
      asOf: new Date(marketTime * 1000),
      source: "Yahoo Finance",
      oneYearStartPrice,
      oneYearChange,
      oneYearChangePercent,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
};

const formatCopilotPercent = (value: number | null, digits = 2) =>
  value === null || !Number.isFinite(value)
    ? "Unavailable"
    : `${value >= 0 ? "+" : ""}${value.toFixed(digits)}%`;

const buildPortfolioAnalysisWithLiveDataResponse = async (input: {
  latestMessage: string;
  language: CopilotLanguage;
}): Promise<CopilotResponsePayload | null> => {
  const intents = collectMarketIntents(input.latestMessage).filter(
    (intent) => intent.assetClass === "stock" || intent.assetClass === "index",
  );
  if (!intents.length) return null;

  const snapshots = (
    await Promise.all(
      intents.slice(0, 4).map((intent) => fetchMarketAnalysisSnapshot(intent)),
    )
  ).filter((item): item is MarketAnalysisSnapshot => Boolean(item));

  if (!snapshots.length) {
    return null;
  }

  const formatLocalizedPercent = (value: number | null, digits = 2) =>
    value === null || !Number.isFinite(value)
      ? localizeCopilotText(input.language, "Không có dữ liệu", "Unavailable")
      : `${value >= 0 ? "+" : ""}${value.toFixed(digits)}%`;

  const latest = normalizeCopilotText(input.latestMessage);
  const asksCompare =
    snapshots.length >= 2 ||
    /\b(compare|comparison|vs|versus|so sanh|khac nhau)\b/.test(latest);
  const asksOneYear = /\b(1 nam|1 year|one year|12 thang|12 months)\b/.test(
    latest,
  );

  if (asksCompare) {
    const comparisonTable = buildCopilotMarkdownTable(
      input.language === "vi"
        ? ["Mã", "Giá gần nhất", "1D", asksOneYear ? "1Y" : "Xu hướng 1 năm"]
        : ["Symbol", "Latest price", "1D", asksOneYear ? "1Y" : "1Y trend"],
      snapshots.map((snapshot) => [
        snapshot.symbol,
        `${snapshot.currency} ${formatMarketPrice(snapshot.price)}`,
        formatLocalizedPercent(snapshot.changePercent),
        formatLocalizedPercent(snapshot.oneYearChangePercent),
      ]),
    );

    return {
      reply:
        input.language === "vi"
          ? `${comparisonTable}\n\nCách đọc nhanh:\n- "1D" là biến động so với giá đóng cửa trước đó.\n- "1Y" là thay đổi so với mức giá đầu tiên có sẵn trong cửa sổ dữ liệu 1 năm.\n\nGợi ý:\n- Dùng bảng này để nhìn tương quan giá và động lượng.\n- Để kết luận chắc hơn, vẫn nên xem thêm ROE, chất lượng lợi nhuận và định giá.`
          : `${comparisonTable}\n\nQuick read:\n- "1D" is measured versus the previous close.\n- "1Y" is measured from the earliest available close in the one-year chart window.\n\nSuggestions:\n- Use this table for relative price context.\n- Add ROE, earnings quality, and valuation before drawing a conclusion.`,
      topic: "portfolio-analysis-live-compare",
      suggestedActions:
        input.language === "vi"
          ? [
              "Tôi có thể so sánh tiếp theo ROE, định giá và rủi ro drawdown của các mã này.",
              "Nếu muốn, tôi sẽ tách riêng từng mã theo: dữ liệu, kết luận nhanh và rủi ro.",
            ]
          : [
              "I can compare ROE, valuation, and drawdown risk for these symbols next.",
              "If you want, I can break the analysis into separate facts, calculations, and suggestions for each symbol.",
            ],
      suggestedDepositAmount: null,
      riskLevel: "medium",
      confidence: 0.84,
      followUpQuestion: localizeCopilotText(
        input.language,
        "Bạn muốn tôi đào sâu hơn vào định giá hay độ ổn định lợi nhuận?",
        "Do you want me to go deeper on valuation or on earnings stability?",
      ),
    };
  }

  const snapshot = snapshots[0];
  const facts = [
    `${snapshot.label}: ${snapshot.currency} ${formatMarketPrice(snapshot.price)}`,
    `${input.language === "vi" ? "Biến động 1D" : "1D move"}: ${formatLocalizedPercent(snapshot.changePercent)}`,
    `${input.language === "vi" ? "Biến động 1Y" : "1Y move"}: ${formatLocalizedPercent(snapshot.oneYearChangePercent)}`,
  ].join("\n");

  return {
    reply:
      input.language === "vi"
        ? `${facts}\n\nCách đọc nhanh:\n- Giá gần nhất được lấy từ ${snapshot.source} tại ${formatMarketTimestamp(snapshot.asOf)}.\n- Nếu "1Y" hiện "Không có dữ liệu", nghĩa là provider chưa trả đủ chart để tính biến động 1 năm.\n\nGợi ý:\n- Tôi có thể dùng bộ số liệu này để đánh giá độ ổn định giá.\n- Để kết luận chắc hơn, vẫn nên xem thêm drawdown, chất lượng lợi nhuận và định giá.`
        : `Facts:\n${facts}\n\nCalculations:\n- The latest price was pulled from ${snapshot.source} at ${formatMarketTimestamp(snapshot.asOf)}.\n- If "1Y" is unavailable, the provider did not return enough chart data to calculate a one-year move.\n\nSuggestions:\n- I can use this data to discuss price stability, but a true stability view should still include drawdown, earnings quality, and valuation.`,
    topic: "portfolio-analysis-live-single",
    suggestedActions:
      input.language === "vi"
        ? [
            "Tôi có thể phân tích tiếp độ ổn định 1 năm của mã này dựa trên 1D/1Y và khung drawdown.",
            "Nếu muốn, tôi có thể so sánh mã này với một ngân hàng khác ngay bây giờ.",
          ]
        : [
            "I can continue with a one-year stability read using 1D/1Y and a drawdown framework.",
            "If you want, I can compare this symbol with another bank right now.",
          ],
    suggestedDepositAmount: null,
    riskLevel: "medium",
    confidence: 0.82,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Bạn muốn tôi so sánh tiếp với mã nào?",
      "Which symbol do you want me to compare it with next?",
    ),
  };
};

const buildLiveMarketCopilotResponse = async (
  latestMessage: string,
): Promise<CopilotResponsePayload | null> => {
  const language = detectCopilotLanguage(latestMessage);
  if (!isExplicitLiveQuoteRequest(latestMessage)) {
    return null;
  }
  const intent = detectMarketIntent(latestMessage);
  if (!intent) return null;

  const quote = await fetchMarketQuote(intent);
  if (!quote) {
    return {
      reply: localizeCopilotText(
        language,
        "Tôi nhận ra đây là câu hỏi về dữ liệu thị trường, nhưng nguồn live quote hiện chưa trả về dữ liệu dùng được. Hãy thử lại với mã rõ ràng như AAPL, BTC-USD hoặc USD/VND.",
        "I recognized this as a market-data question, but the live quote provider did not return a usable quote right now. Try again with an explicit ticker like AAPL, BTC-USD, or USD/VND.",
      ),
      topic: "market-data-unavailable",
      suggestedActions:
        language === "vi"
          ? [
              "Thử lại cùng mã sau vài giây.",
              "Dùng mã rõ ràng như USD/VND, BTC-USD, AAPL hoặc ^GSPC.",
              "Với cổ phiếu Việt Nam, hãy hỏi bằng đúng ticker tương thích Yahoo.",
            ]
          : [
              "Retry the same quote in a few seconds.",
              "Use an explicit symbol like USD/VND, BTC-USD, AAPL, or ^GSPC.",
              "For Vietnam-listed equities, ask with the exact Yahoo-compatible ticker.",
            ],
      suggestedDepositAmount: null,
      riskLevel: "medium",
      confidence: 0.58,
      followUpQuestion: localizeCopilotText(
        language,
        "Bạn muốn tôi kiểm tra mã khác hay chuyển sang tư vấn dòng tiền ví?",
        "Do you want me to check another ticker or switch to wallet cash-flow guidance?",
      ),
    };
  }

  const changeText =
    quote.change !== null && quote.changePercent !== null
      ? language === "vi"
        ? `${formatMarketDelta(quote.change, quote.currency)} (${quote.changePercent >= 0 ? "+" : ""}${quote.changePercent.toFixed(2)}%) so với giá đóng cửa trước đó`
        : `${formatMarketDelta(quote.change, quote.currency)} (${quote.changePercent >= 0 ? "+" : ""}${quote.changePercent.toFixed(2)}%) versus the previous close`
      : language === "vi"
        ? "chưa có dữ liệu biến động so với giá đóng cửa trước đó"
        : "change versus previous close is unavailable";
  const marketStateText = quote.marketState
    ? language === "vi"
      ? ` Trang thai thi truong: ${quote.marketState}.`
      : ` Market state: ${quote.marketState}.`
    : "";
  const exchangeText = quote.exchangeName
    ? language === "vi"
      ? ` San: ${quote.exchangeName}.`
      : ` Exchange: ${quote.exchangeName}.`
    : "";

  return {
    reply:
      language === "vi"
        ? `Giá gần nhất của ${quote.label} là ${quote.currency} ${formatMarketPrice(
            quote.price,
          )} tại ${formatMarketTimestamp(quote.asOf)}. Biến động là ${changeText}.${exchangeText}${marketStateText}`
        : `Latest available quote for ${quote.label} is ${quote.currency} ${formatMarketPrice(
            quote.price,
          )} as of ${formatMarketTimestamp(quote.asOf)}. That is ${changeText}.${exchangeText}${marketStateText}`,
    topic: "live-market-quote",
    suggestedActions:
      language === "vi"
        ? [
            "Hỏi thêm quote realtime với mã như AAPL, NVDA, BTC-USD hoặc USD/JPY.",
            "Dùng quote realtime để tham khảo; giá khớp lệnh thực tế vẫn có thể khác.",
            "Nếu muốn, tôi có thể liên hệ biến động này với dòng tiền hoặc phân bổ ví của bạn.",
          ]
        : [
            "Ask another live quote using a ticker like AAPL, NVDA, BTC-USD, or USD/JPY.",
            "Use live quotes for context; your execution price can still differ at order time.",
            "If you want, I can relate this market move back to your wallet cash flow or allocation.",
          ],
    suggestedDepositAmount: null,
    riskLevel:
      quote.assetClass === "crypto"
        ? "high"
        : quote.assetClass === "stock" || quote.assetClass === "commodity"
          ? "medium"
          : "low",
    confidence: 0.93,
    followUpQuestion: localizeCopilotText(
      language,
      "Bạn muốn xem thêm quote realtime hay để tôi nối thông tin này với ví và dòng tiền của bạn?",
      "Do you want another live quote, or should I connect this to your wallet and cash-flow context?",
    ),
  };
};

const buildHeuristicDepositPlan = (input: {
  goal: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  currency: string;
}): DepositAgentResponse => {
  const income = Math.max(0, Number(input.monthlyIncome || 0));
  const expenses = Math.max(0, Number(input.monthlyExpenses || 0));
  const buffer = Math.max(0, income - expenses);
  const goal = input.goal.trim().toLowerCase();
  let multiplier = 0.3;
  let riskLevel = "low";

  if (/emergency|safety|buffer|reserve/.test(goal)) {
    multiplier = 1.2;
  } else if (/travel|tuition|device|laptop|phone|school/.test(goal)) {
    multiplier = 0.65;
  } else if (/invest|crypto|stock|trading/.test(goal)) {
    multiplier = 0.4;
    riskLevel = "medium";
  }

  if (expenses > income && income > 0) {
    riskLevel = "high";
  } else if (buffer <= 0 && income > 0) {
    riskLevel = "medium";
  }

  const baseline =
    buffer > 0
      ? buffer * multiplier
      : Math.max(100, input.currentBalance * 0.1);
  const recommendedAmount = roundMoney(clamp(baseline, 50, 10000));
  const confidence = clamp(
    income > 0 ? 0.82 : input.currentBalance > 0 ? 0.68 : 0.61,
    0.55,
    0.92,
  );

  const reasoning = [
    `Current balance is ${input.currency} ${roundMoney(input.currentBalance).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}.`,
    income > 0
      ? `Estimated monthly free cash flow is ${input.currency} ${roundMoney(buffer).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}.`
      : "Monthly income and expense data were not fully provided, so the suggestion uses a conservative baseline.",
    /emergency|safety|buffer|reserve/.test(goal)
      ? "Emergency-fund intent detected, so the recommendation prioritizes liquidity and runway."
      : "Recommendation balances your stated goal with preserving working balance.",
  ];

  return {
    recommendedAmount,
    reasoning,
    riskLevel,
    nextAction:
      riskLevel === "high"
        ? "Deposit only a small buffer first and review recurring expenses before larger top-ups."
        : "Top up the suggested amount and review again after your next salary cycle.",
    confidence,
  };
};

const buildHeuristicStockEducationResponse = (input: {
  latestMessage: string;
  language: CopilotLanguage;
  intent: MarketIntent | null;
  intents: MarketIntent[];
}): CopilotResponsePayload | null => {
  const latest = normalizeCopilotText(input.latestMessage);
  const asksCompare =
    /\b(compare|comparison|vs|versus|so sanh|khac nhau)\b/.test(latest);
  const asksAllocation =
    /\b(portfolio|allocation|phan bo|diversif|da dang hoa|etf|index fund)\b/.test(
      latest,
    );
  const asksValuation =
    /\b(pe|p\/e|eps|valuation|dinh gia|market cap|von hoa|dividend|free cash flow|fcf|debt|no vay|margin|bien loi nhuan|revenue|doanh thu)\b/.test(
      latest,
    );
  const asksStockLearning =
    /\b(co phieu|chung khoan|stock|share|ticker|index|etf|portfolio|valuation|dinh gia|sector|nganh|beta|dividend|eps|pe|market cap)\b/.test(
      latest,
    );
  const asksWatchlist =
    /\b(watchlist|danh sach theo doi|theo doi|screen|scanner|shortlist|goi y ma|nhom co phieu)\b/.test(
      latest,
    );
  const asksDecisionSupport =
    isMarketAdvisoryRequest(input.latestMessage) ||
    /\b(mua hay khong|ban hay khong|co hop ly khong|nen giai ngan|nen vao lenh|co dang de mua|dau tu duoc khong)\b/.test(
      latest,
    );
  const horizon: "short-term" | "medium-term" | "long-term" =
    /\b(luot song|ltng|short term|short-term|ngan han|trong ngay|day trade|swing trade|trade ngan)\b/.test(
      latest,
    )
      ? "short-term"
      : /\b(6 thang|12 thang|6-12 thang|6 den 12 thang|6 to 12 months|medium term|medium-term|trung han)\b/.test(
            latest,
          )
        ? "medium-term"
        : /\b(2 nam|3 nam|2-3 nam|2 den 3 nam|2 to 3 years|long term|long-term|dai han|nam giu dai)\b/.test(
              latest,
            )
          ? "long-term"
          : "medium-term";
  const riskTolerance: "low" | "medium" | "high" =
    /\b(an toan|it rui ro|than trong|phong thu|bao toan von|low risk|defensive|capital preservation)\b/.test(
      latest,
    )
      ? "low"
      : /\b(rui ro cao|chap nhan bien dong|mao hiem|aggressive|high risk|volatility)\b/.test(
            latest,
          )
        ? "high"
        : "medium";

  if (
    !asksCompare &&
    !asksAllocation &&
    !asksValuation &&
    !asksStockLearning &&
    !asksWatchlist &&
    !asksDecisionSupport
  ) {
    return null;
  }

  const focusLabel =
    input.intent?.label ||
    localizeCopilotText(
      input.language,
      "co phieu / chi so",
      "stocks / indexes",
    );
  const mentionedSymbols = input.intents.map((item) => item.symbol).slice(0, 4);
  const mentionedLabels = input.intents.map((item) => item.label).slice(0, 4);

  if (asksWatchlist) {
    const watchlistTheme = /\b(bank|banking|ngan hang)\b/.test(latest)
      ? "banking"
      : /\b(tech|technology|cong nghe|ai|semiconductor|chip)\b/.test(latest)
        ? "technology"
        : /\b(dividend|co tuc|income)\b/.test(latest)
          ? "dividend"
          : /\b(vietnam|vn|viet nam)\b/.test(latest)
            ? "vietnam"
            : "core";

    const watchlistRows =
      watchlistTheme === "banking"
        ? [
            ["VCB.VN", "Quality leader", "Asset quality and credit growth"],
            [
              "TCB.VN",
              "Private bank scale",
              "CASA, fee mix, margin discipline",
            ],
            ["MBB.VN", "Operational efficiency", "Loan mix and provisioning"],
            [
              "ACB.VN",
              "Retail franchise",
              "Deposit stability and asset quality",
            ],
          ]
        : watchlistTheme === "technology"
          ? [
              ["AAPL", "Platform moat", "Services mix and device cycle"],
              [
                "MSFT",
                "Enterprise quality",
                "Cloud growth and margin resilience",
              ],
              [
                "NVDA",
                "AI demand leader",
                "Revenue concentration and valuation",
              ],
              [
                "FPT.VN",
                "Vietnam tech compounder",
                "Export pipeline and margin",
              ],
            ]
          : watchlistTheme === "dividend"
            ? [
                [
                  "VNM.VN",
                  "Defensive cash flow",
                  "Payout durability and volume trend",
                ],
                [
                  "VCB.VN",
                  "Quality compounder",
                  "Yield not highest, franchise is strong",
                ],
                [
                  "MSFT",
                  "Dividend growth",
                  "Cash flow and balance sheet strength",
                ],
                ["KO", "Income classic", "Yield stability and pricing power"],
              ]
            : watchlistTheme === "vietnam"
              ? [
                  [
                    "FPT.VN",
                    "Technology",
                    "Export growth and execution quality",
                  ],
                  [
                    "VCB.VN",
                    "Banking",
                    "Credit quality and valuation vs peers",
                  ],
                  ["HPG.VN", "Materials", "Steel cycle sensitivity and margin"],
                  [
                    "MWG.VN",
                    "Consumer",
                    "Demand recovery and store productivity",
                  ],
                ]
              : [
                  [
                    "SPY",
                    "US equity core",
                    "Broad exposure and lower single-name risk",
                  ],
                  [
                    "QQQ",
                    "Growth-heavy core",
                    "Tech concentration and valuation",
                  ],
                  [
                    "^VNINDEX",
                    "Vietnam market lens",
                    "Macro beta and domestic cycle",
                  ],
                  [
                    "AAPL",
                    "Single-stock benchmark",
                    "Quality franchise vs concentration risk",
                  ],
                ];

    const watchlistTable = buildCopilotMarkdownTable(
      input.language === "vi"
        ? ["Ma", "Vai tro", "Diem can theo doi"]
        : ["Symbol", "Role", "What to track"],
      watchlistRows,
    );

    return {
      reply:
        input.language === "vi"
          ? `Toi da tao mot watchlist mau theo chu de ${watchlistTheme === "banking" ? "ngan hang" : watchlistTheme === "technology" ? "cong nghe" : watchlistTheme === "dividend" ? "co tuc" : watchlistTheme === "vietnam" ? "co phieu Viet Nam" : "cot loi"}. Day la danh sach de theo doi va sang loc, khong phai khuyen nghi mua ban.\n\n${watchlistTable}`
          : `I built a starter ${watchlistTheme} watchlist. Treat it as a tracking and screening list, not an automatic buy list.\n\n${watchlistTable}`,
      topic: "stock-watchlist",
      suggestedActions:
        input.language === "vi"
          ? [
              "Giu watchlist o muc 5-8 ma de de theo doi.",
              "Sang loc tiep theo tang truong, dinh gia, no vay va bien loi nhuan.",
              "Neu muon, toi co the rut gon watchlist theo phong thu, tang truong, hoac co tuc.",
            ]
          : [
              "Keep the watchlist around 5-8 names so it stays actionable.",
              "Refine it by growth, valuation, debt, and margin quality.",
              "If you want, I can narrow the list for defensive, growth, or dividend style.",
            ],
      suggestedDepositAmount: null,
      riskLevel: "medium",
      confidence: 0.79,
      followUpQuestion: localizeCopilotText(
        input.language,
        "Ban muon toi rut gon watchlist nay theo tieu chi nao: tang truong, re hon, hay phong thu?",
        "How do you want me to refine this watchlist: growth, cheaper valuation, or more defensive names?",
      ),
    };
  }

  if (asksCompare || mentionedSymbols.length >= 2) {
    const compareNames =
      mentionedLabels.length >= 2 ? mentionedLabels.join(" vs ") : focusLabel;
    const comparisonTable = buildCopilotMarkdownTable(
      input.language === "vi"
        ? ["Goc nhin", "Co phieu don le", "Chi so / ETF rong"]
        : ["Lens", "Single stock", "Broad index / ETF"],
      [
        input.language === "vi"
          ? [
              "Rui ro",
              "Cao hon, phu thuoc mot doanh nghiep",
              "Thap hon nho da dang hoa",
            ]
          : [
              "Risk",
              "Higher, tied to one company",
              "Lower through diversification",
            ],
        input.language === "vi"
          ? [
              "Loi nhuan ky vong",
              "Co the vuot troi neu chon dung",
              "On dinh hon, kho vuot troi lon",
            ]
          : [
              "Expected return",
              "Can outperform if chosen well",
              "More stable, harder to dramatically outperform",
            ],
        input.language === "vi"
          ? ["Bien dong", "Manh hon", "Thuong mem hon"]
          : ["Volatility", "Usually sharper", "Usually smoother"],
        input.language === "vi"
          ? [
              "Cong viec can lam",
              "Can theo doi ket qua kinh doanh va dinh gia",
              "Chu yeu theo doi phan bo va ky luat giai ngan",
            ]
          : [
              "Work required",
              "Need earnings and valuation tracking",
              "Mostly allocation and discipline tracking",
            ],
      ],
    );

    return {
      reply:
        input.language === "vi"
          ? `Neu ban dang so sanh ${compareNames}, khung nhin huu ich nhat van la: muc do tap trung, do ben loi nhuan, dinh gia, va rui ro drawdown. Voi nha dau tu ca nhan, diem khac nhau lon nhat thuong den tu do da dang hoa va kha nang chiu bien dong.\n\n${comparisonTable}`
          : `If you are comparing ${compareNames}, the most useful lens is concentration, earnings durability, valuation, and drawdown risk. For most individual investors, the biggest difference still comes from diversification and tolerance for volatility.\n\n${comparisonTable}`,
      topic: "stock-comparison-framework",
      suggestedActions:
        input.language === "vi"
          ? [
              "Neu ban moi bat dau, uu tien mot lop tai san rong truoc khi tang ty trong co phieu don le.",
              "So sanh co phieu theo cung mot nganh va cung mot chu ky kinh doanh.",
              "Dung muc cat lo va kich thuoc vi the phu hop voi muc chiu rui ro.",
            ]
          : [
              "If you are early, build a broad core allocation before sizing single-stock bets.",
              "Compare stocks against peers in the same sector and business cycle.",
              "Set position size and downside rules before entering concentrated trades.",
            ],
      suggestedDepositAmount: null,
      riskLevel: "medium",
      confidence: 0.82,
      followUpQuestion: localizeCopilotText(
        input.language,
        "Ban muon toi so sanh tiep theo gi: co phieu My va VN, co phieu va ETF, hay co phieu tang truong va co tuc?",
        "What do you want to compare next: US vs Vietnam stocks, stock vs ETF, or growth vs dividend style?",
      ),
    };
  }

  if (asksDecisionSupport) {
    const horizonLabel =
      input.language === "vi"
        ? horizon === "short-term"
          ? "luot song / ngan han"
          : horizon === "long-term"
            ? "nam giu dai han 2-3 nam"
            : "nam giu trung han 6-12 thang"
        : horizon === "short-term"
          ? "short-term / trading"
          : horizon === "long-term"
            ? "long-term 2-3 year hold"
            : "medium-term 6-12 month hold";
    const riskLabel =
      input.language === "vi"
        ? riskTolerance === "low"
          ? "than trong"
          : riskTolerance === "high"
            ? "chap nhan rui ro cao"
            : "rui ro trung binh"
        : riskTolerance === "low"
          ? "defensive"
          : riskTolerance === "high"
            ? "higher-risk"
            : "moderate-risk";
    const decisionTable = buildCopilotMarkdownTable(
      input.language === "vi"
        ? ["Goc nhin", "Can tu hoi", "Vi sao quan trong"]
        : ["Lens", "Question to ask", "Why it matters"],
      [
        input.language === "vi"
          ? [
              "Luan diem",
              `${focusLabel} dang tang truong nho dieu gi, va dong luc do co ben khong?`,
              "Tach cau chuyen dai han khoi bien dong ngan han trong ngay.",
            ]
          : [
              "Thesis",
              `What is driving ${focusLabel}, and is that driver durable?`,
              "Separates a long-term thesis from one-day price action.",
            ],
        input.language === "vi"
          ? [
              "Dinh gia",
              "Muc dinh gia hien tai dang re, hop ly, hay da phan anh qua nhieu ky vong?",
              "Mot doanh nghiep tot van co the la khoan mua kem neu vao o muc gia qua cao.",
            ]
          : [
              "Valuation",
              "Does the current valuation look cheap, fair, or already rich?",
              "A strong business can still be a poor entry if expectations are overpriced.",
            ],
        input.language === "vi"
          ? [
              "Rui ro",
              "Kich ban xau nhat 6-12 thang toi la gi: tang truong cham lai, bien loi nhuan giam, hay thi truong chung dieu chinh?",
              "Giup ban hinh dung downside thay vi chi nhin upside.",
            ]
          : [
              "Risk",
              "What is the main downside over the next 6-12 months: slower growth, margin pressure, or a broader market drawdown?",
              "Forces downside thinking instead of upside-only optimism.",
            ],
        input.language === "vi"
          ? [
              "Ky luat vi the",
              "Neu mua, ty trong bao nhieu la hop ly va diem nao khien ban phai xem lai quyet dinh?",
              "Dung ma nhung sai kich thuoc vi the van co the gay hai danh muc.",
            ]
          : [
              "Position discipline",
              "If you buy, what position size is reasonable and what would invalidate the idea?",
              "Even the right stock can hurt the portfolio if sizing is wrong.",
            ],
      ],
    );
    const horizonTable = buildCopilotMarkdownTable(
      input.language === "vi"
        ? ["Khung nam giu", "Trong tam", "Dieu kien de tham gia", "Can tranh"]
        : [
            "Holding horizon",
            "Primary focus",
            "Reasonable entry condition",
            "Avoid",
          ],
      [
        input.language === "vi"
          ? [
              "Luot song / ngan han",
              "Dong luc gia, thanh khoan, va ky luat cat lo",
              "Chi nen vao khi ban da co muc vao, muc sai, va kich thuoc vi the ro rang",
              "Mua chi vi thay xanh manh hoac FOMO theo dong tien trong ngay",
            ]
          : [
              "Short-term / trading",
              "Price momentum, liquidity, and strict downside rules",
              "Only enter when entry, invalidation, and size are already defined",
              "Chasing a green candle or intraday FOMO",
            ],
        input.language === "vi"
          ? [
              "6-12 thang",
              "Tang truong loi nhuan, dinh gia, va xac suat rerating",
              "Hop ly khi luan diem co catalyst ro trong 2-4 quy toi",
              "Mua khi ky vong da qua day ma catalyst khong ro",
            ]
          : [
              "6-12 months",
              "Earnings growth, valuation, and rerating potential",
              "Reasonable when the thesis has a visible 2-4 quarter catalyst",
              "Buying when expectations are already crowded and catalysts are vague",
            ],
        input.language === "vi"
          ? [
              "2-3 nam",
              "Do ben mo hinh kinh doanh, tai phan bo von, va kha nang compound",
              "Hop ly khi doanh nghiep co moat, runway tang truong, va ban chap nhan duoc bien dong",
              "Danh dong dau co dai han nhung lai khong chap nhan drawdown ngan han",
            ]
          : [
              "2-3 years",
              "Business durability, capital allocation, and compounding quality",
              "Reasonable when the company has a moat, growth runway, and you can sit through volatility",
              "Calling it long-term while being unable to tolerate short-term drawdowns",
            ],
      ],
    );
    const horizonNarrative =
      input.language === "vi"
        ? horizon === "short-term"
          ? `Voi horizon ${horizonLabel}, toi khong xem day la cau hoi "co phieu co tot khong" nua, ma la cau hoi "trade nay co du xac suat va ky luat khong". Neu ban chua co diem sai ro rang, thi giao dich nay chua hop le.`
          : horizon === "long-term"
            ? `Voi horizon ${horizonLabel}, toi uu tien chat luong doanh nghiep hon bien dong gia trong ngay. Cau hoi dung la: ${focusLabel} co kha nang tang truong va compound trong 2-3 nam, hay ban dang bi hut vao tin hieu ngan han?`
            : `Voi horizon ${horizonLabel}, diem can nhin la catalyst 2-4 quy toi va muc ky vong da duoc gia phan anh den dau. Toi se uu tien can bang giua luan diem tang truong va muc dinh gia vao lenh.`
        : horizon === "short-term"
          ? `For a ${horizonLabel} approach, this is less a question of whether the company is good and more a question of whether the trade has edge and discipline. If you do not already know your invalidation point, the trade is not ready.`
          : horizon === "long-term"
            ? `For a ${horizonLabel} approach, I care much more about business quality than one-day price movement. The right question is whether ${focusLabel} can compound over 2-3 years, or whether you are being pulled in by a short-term signal.`
            : `For a ${horizonLabel} approach, the key is whether there is a visible 2-4 quarter catalyst and how much of that expectation is already priced in. I would balance the growth thesis against the entry valuation.`;
    const riskNarrative =
      input.language === "vi"
        ? riskTolerance === "low"
          ? `Voi muc chiu rui ro ${riskLabel}, toi se nghieng ve cach vao nho, giai ngan tung phan, va uu tien khong de mot ma don le lam lech danh muc.`
          : riskTolerance === "high"
            ? `Voi muc chiu rui ro ${riskLabel}, ban co the chap nhan bien dong cao hon, nhung van nen tach ro dau la luan diem va dau la FOMO. Rui ro cao khong dong nghia voi vao lenh vo ky luat.`
            : `Voi muc chiu rui ro ${riskLabel}, cach hop ly nhat la giu kich thuoc vi the vua phai va de san mot moc xem lai khi gia/luan diem di nguoc ky vong.`
        : riskTolerance === "low"
          ? `With a ${riskLabel} profile, I would lean smaller, staged entries and avoid letting a single name dominate the portfolio.`
          : riskTolerance === "high"
            ? `With a ${riskLabel} profile, you can accept more volatility, but you still need to separate a thesis from FOMO. Higher risk tolerance is not a license for undisciplined entries.`
            : `With a ${riskLabel} profile, a moderate position size plus a clear review trigger is usually the most balanced approach.`;

    return {
      reply:
        input.language === "vi"
          ? `Neu ban hoi “co nen mua ${focusLabel} hom nay khong”, toi se khong dua chi vao gia trong ngay de ket luan co hoac khong. Cach an toan hon la tach quyet dinh theo horizon nam giu va muc chiu rui ro.\n\n${horizonNarrative} ${riskNarrative}\n\n${horizonTable}\n\n${decisionTable}\n\nVoi ${focusLabel}, toi nghieng ve cach tiep can: chi can nhac giai ngan khi ban hieu ro luan diem tang truong, chap nhan duoc rui ro giam gia, va co ke hoach ty trong ro rang. Neu chua tra loi duoc 4 y tren, cau tra loi thuc te la chua nen mua voi chi vi bien dong hom nay.`
          : `If you are asking whether you should buy ${focusLabel} today, I would not answer from one-day price action alone. A safer decision is to split the decision by holding horizon and risk tolerance.\n\n${horizonNarrative} ${riskNarrative}\n\n${horizonTable}\n\n${decisionTable}\n\nFor ${focusLabel}, my bias would be: only consider buying when you understand the growth thesis, accept the downside, and already know your position size and review trigger. If those checks are still unclear, the practical answer is not to rush into the trade today.`,
      topic: "stock-decision-support",
      suggestedActions:
        input.language === "vi"
          ? [
              "Yeu cau toi phan tich tiep theo khung: tang truong, bien loi nhuan, dinh gia, no vay, va rui ro.",
              "Noi ro ban dang luot song, nam giu 6-12 thang, hay nam giu 2-3 nam de toi siet khung khuyen nghi.",
              "Neu can du lieu gia, hay hoi rieng quote; neu can quyet dinh mua, hay giu trong tam o luan diem, catalyst, va downside.",
            ]
          : [
              "Ask me to continue with growth, margin, valuation, debt, and risk.",
              "Tell me whether you are trading short-term, holding 6-12 months, or holding 2-3 years so I can tighten the lens.",
              "Use a separate quote question for price; keep buy/sell decisions focused on thesis, catalyst, and downside.",
            ],
      suggestedDepositAmount: null,
      riskLevel: "medium",
      confidence: 0.88,
      followUpQuestion: localizeCopilotText(
        input.language,
        `Ban dang nghi den ${focusLabel} theo kieu luot song, nam giu 6-12 thang, hay giu 2-3 nam?`,
        `Are you thinking about ${focusLabel} as a short-term trade, a 6-12 month hold, or a 2-3 year hold?`,
      ),
    };
  }

  const checklistTable = buildCopilotMarkdownTable(
    input.language === "vi"
      ? ["Chi so", "Cach doc nhanh", "Y nghia"]
      : ["Metric", "Quick read", "Why it matters"],
    [
      input.language === "vi"
        ? [
            "Tang truong doanh thu",
            "So voi cung ky va trung binh 2-3 nam",
            "Cho biet doanh nghiep con mo rong hay khong",
          ]
        : [
            "Revenue growth",
            "Compare YoY and vs 2-3 year average",
            "Shows whether the business is still expanding",
          ],
      input.language === "vi"
        ? [
            "Bien loi nhuan",
            "On dinh, mo rong hay co lai/giam",
            "Cho thay chat luong tang truong",
          ]
        : [
            "Margin trend",
            "Stable, expanding, or compressing",
            "Signals quality of growth",
          ],
      input.language === "vi"
        ? [
            "P/E hoac dinh gia",
            "So voi lich su va peers",
            "Cho biet ky vong da bi day len den dau",
          ]
        : [
            "P/E or valuation",
            "Compare against history and peers",
            "Shows how much optimism is already priced in",
          ],
      input.language === "vi"
        ? [
            "No vay va dong tien",
            "No rong, FCF, kha nang tra lai",
            "Giup do suc ben khi chu ky xau di",
          ]
        : [
            "Debt and cash flow",
            "Net debt, FCF, interest coverage",
            "Helps judge resilience in weaker cycles",
          ],
      input.language === "vi"
        ? [
            "Rui ro tap trung",
            "Ty trong 1 ma, 1 nganh, 1 chu de",
            "Tranh danh muc nghieng qua muc",
          ]
        : [
            "Concentration risk",
            "Weight in one stock, sector, or theme",
            "Prevents accidental overexposure",
          ],
    ],
  );

  return {
    reply:
      input.language === "vi"
        ? `Toi co the ho tro tra loi nhieu cau hoi chung khoan hon theo dang khung phan tich, ngay ca khi khong co quote realtime cho ${focusLabel}. Khi xem mot co phieu hay chi so, toi uu tien 5 nhom chi so duoi day de tranh mua theo cam tinh.\n\n${checklistTable}`
        : `I can handle broader stock-market questions with an analysis framework even when a live quote is not the main need for ${focusLabel}. When reviewing a stock or index, I would start with the five checkpoints below so the discussion stays disciplined.\n\n${checklistTable}`,
    topic: asksAllocation
      ? "portfolio-allocation-framework"
      : asksValuation
        ? "stock-valuation-framework"
        : "stock-analysis-framework",
    suggestedActions:
      input.language === "vi"
        ? [
            "Hoi toi phan tich mot ticker cu the theo khung doanh thu, bien loi nhuan, dinh gia, no vay va rui ro.",
            "Hoi cach phan bo giua ETF rong va co phieu don le theo muc chiu rui ro.",
            "Hoi toi lap watchlist co phieu My hoac VN theo tieu chi cua ban.",
          ]
        : [
            "Ask me to review a specific ticker using revenue, margin, valuation, debt, and risk.",
            "Ask for an allocation split between broad ETFs and single stocks based on your risk tolerance.",
            "Ask me to build a US or Vietnam stock watchlist around your criteria.",
          ],
    suggestedDepositAmount: null,
    riskLevel: asksAllocation ? "medium" : "low",
    confidence: 0.8,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Ban muon toi ap dung khung nay cho ticker nao, hay muon mot watchlist theo nganh?",
      "Which ticker do you want this framework applied to, or do you want a sector-based watchlist?",
    ),
  };
};

const buildHeuristicScamProtectionResponse = (input: {
  latestMessage: string;
  language: CopilotLanguage;
}): CopilotResponsePayload | null => {
  const latest = normalizeCopilotText(input.latestMessage);
  const matchesScamSignals =
    /\b(otp|ma otp|verification code|ma xac minh|faceid|sinh trac|safe account|tai khoan an toan|security team|support team|nhan vien ngan hang|bank staff|refund|hoan tien|customs|hai quan|tax|thue|penalty|phat|unlock|mo khoa|broker|forex|crypto signal|guaranteed return|bao loi nhuan|remote access|anydesk|teamviewer|screen share|chia se man hinh|chuyen ngay|urgent|gap|chuyen tien dieu tra|phuc vu dieu tra|co quan dieu tra|cong an dieu tra|vien kiem sat|toa an|ho so vu an|vu an|phong toa tai khoan|tai khoan bi phong toa|tai khoan lien quan dieu tra|tai khoan lien quan vu an|kiem tra dong tien|ra soat dong tien|xac minh nguon tien)\b/.test(
      latest,
    );

  if (!matchesScamSignals) {
    return null;
  }

  const riskTable = buildCopilotMarkdownTable(
    input.language === "vi"
      ? ["Dau hieu", "Tai sao nguy hiem"]
      : ["Signal", "Why it is dangerous"],
    [
      input.language === "vi"
        ? [
            "Yeu cau OTP / FaceID",
            "Khong ai hop le can ban doc ma OTP hoac quet sinh trac de 'ho tro'",
          ]
        : [
            "Requests for OTP / FaceID",
            "No legitimate helper needs your OTP or biometric action to 'assist' you",
          ],
      input.language === "vi"
        ? [
            "Chuyen tien vao 'tai khoan an toan'",
            "Day la kieu danh cap pho bien de day tien ra khoi tai khoan cua ban",
          ]
        : [
            "Transfer to a 'safe account'",
            "This is a common theft script used to move money out of your control",
          ],
      input.language === "vi"
        ? [
            "Ap luc gap, de doa, phi mo khoa / hoan tien",
            "Lua dao thuong ep ban ra quyet dinh truoc khi kip xac minh",
          ]
        : [
            "Urgency, threats, unlock/refund fees",
            "Scammers pressure you before you have time to verify",
          ],
      input.language === "vi"
        ? [
            "Cai app dieu khien tu xa / chia se man hinh",
            "Co the bi chiem quyen truy cap va lo ma xac thuc",
          ]
        : [
            "Remote-access app / screen sharing",
            "Can expose account access and verification codes",
          ],
    ],
  );

  return {
    reply:
      input.language === "vi"
        ? `Tin nhan nay co dau hieu lua dao hoac chiem doat tai khoan. Dung chuyen tien, dung doc OTP, dung quet FaceID, va dung cai app dieu khien tu xa cho nguoi la ngay lap tuc.\n\n${riskTable}`
        : `This message shows signs of a scam or account-takeover attempt. Do not send money, do not read any OTP aloud, do not complete FaceID for someone else, and do not install remote-access software.\n\n${riskTable}`,
    topic: "scam-protection",
    suggestedActions:
      input.language === "vi"
        ? [
            "Ngat lien lac voi nguoi dang thuc giuc ban va tu goi lai qua kenh chinh thuc cua ngan hang / vi.",
            "Khong bam link, khong cai app la, khong chia se man hinh.",
            "Neu da lo OTP hoac da chuyen tien, khoa truy cap, doi mat khau, va lien he ho tro chinh thuc ngay.",
            "Neu co dau hieu chiem tai khoan, doi mat khau email truoc, sau do doi mat khau vi va ket thuc cac phien dang nhap.",
          ]
        : [
            "Break contact with the caller and call the bank or wallet provider back through an official channel.",
            "Do not open links, install unknown apps, or share your screen.",
            "If you already exposed an OTP or sent money, lock access, change passwords, and contact official support immediately.",
            "If takeover is possible, secure your email first, then your wallet password and active sessions.",
          ],
    suggestedDepositAmount: null,
    riskLevel: "high",
    confidence: 0.94,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Ban muon toi kiem tra nhanh tinh huong nay theo checklist anti-scam 30 giay khong?",
      "Do you want me to walk through a 30-second anti-scam checklist for this situation?",
    ),
  };
};

const buildDeterministicPortfolioAnalysisResponse = (input: {
  latestMessage: string;
  language: CopilotLanguage;
}): CopilotResponsePayload | null => {
  const intents = collectMarketIntents(input.latestMessage);
  const intent = detectMarketIntent(input.latestMessage);
  if (!intents.length && !intent) {
    return null;
  }

  const baseResponse = buildHeuristicStockEducationResponse({
    latestMessage: input.latestMessage,
    language: input.language,
    intent,
    intents,
  });

  const disclaimer = localizeCopilotText(
    input.language,
    "Toi hien khong co du lieu gia hoac lich su thi truong da xac thuc trong route nay, nen toi se khong neu gia, % tang giam, hay hieu suat 1 nam nhu mot su that da kiem chung. Ben duoi la khung phan tich an toan de ban danh gia co phieu.",
    "I do not have verified market-price or historical market data in this route right now, so I will not state prices, percentage moves, or one-year performance as confirmed facts. Below is a safe analysis framework instead.",
  );

  if (baseResponse) {
    return {
      ...baseResponse,
      reply: `${disclaimer}\n\n${baseResponse.reply}`,
      confidence: Math.min(baseResponse.confidence, 0.74),
      followUpQuestion: localizeCopilotText(
        input.language,
        "Neu ban muon, toi co the tiep tuc so sanh theo chat luong loi nhuan, dinh gia, va rui ro drawdown thay vi gia thi truong.",
        "If you want, I can continue by comparing profitability quality, valuation, and drawdown risk instead of market-price moves.",
      ),
    };
  }

  const mentionedLabels = intents.map((item) => item.label).slice(0, 4);
  const focusLabel =
    mentionedLabels.length > 0
      ? mentionedLabels.join(" vs ")
      : localizeCopilotText(
          input.language,
          "co phieu dang duoc hoi",
          "the stocks you mentioned",
        );
  const frameworkTable = buildCopilotMarkdownTable(
    input.language === "vi"
      ? ["Goc nhin", "Can xem gi"]
      : ["Lens", "What to review"],
    input.language === "vi"
      ? [
          [
            "Chat luong loi nhuan",
            "ROE, NIM/bien loi nhuan, chat luong tai san",
          ],
          ["Dinh gia", "P/B, P/E, tang truong loi nhuan so voi peers"],
          ["Rui ro", "Drawdown, chu ky nganh, no xau/that thoat dong tien"],
          [
            "Phu hop voi ban",
            "Thoi gian nam giu, muc chiu bien dong, kich thuoc vi the",
          ],
        ]
      : [
          ["Profit quality", "ROE, margin/NIM, and asset quality"],
          ["Valuation", "P/B, P/E, and earnings growth versus peers"],
          ["Risk", "Drawdown, sector cycle, and credit/cash-flow stress"],
          [
            "Fit for you",
            "Time horizon, volatility tolerance, and position size",
          ],
        ],
  );

  return {
    reply:
      input.language === "vi"
        ? `${disclaimer}\n\nNeu ban muon danh gia ${focusLabel} ma khong co data gia xac thuc, cach an toan nhat la so sanh theo 4 nhom sau:\n\n${frameworkTable}`
        : `${disclaimer}\n\nIf you want to assess ${focusLabel} without verified price data, the safest approach is to compare them across these four lenses:\n\n${frameworkTable}`,
    topic: "portfolio-analysis-framework",
    suggestedActions:
      input.language === "vi"
        ? [
            "Neu ban co ticker ho tro quote song, toi co the tra lai phan gia rieng.",
            "Toi co the so sanh tiep theo ROE, dinh gia, va rui ro drawdown.",
            "Khong nen xem bat ky con so gia nao khong co nguon xac thuc la co so mua ban.",
          ]
        : [
            "If you have a supported live-quote ticker, I can revisit the price section.",
            "I can compare ROE, valuation, and drawdown risk next.",
            "Do not treat any unsupported price number as a basis for a buy or sell decision.",
          ],
    suggestedDepositAmount: null,
    riskLevel: "medium",
    confidence: 0.7,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Ban muon toi tiep tuc theo huong nao: dinh gia, chat luong loi nhuan, hay rui ro giam sau?",
      "Which lens do you want next: valuation, profit quality, or downside risk?",
    ),
  };
};

const buildHeuristicCopilotResponse = (input: {
  currentBalance: number;
  currency: string;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  latestMessage: string;
}): CopilotResponsePayload => {
  const language = detectCopilotLanguage(input.latestMessage);
  const latest = normalizeCopilotText(input.latestMessage);
  const marketIntent = detectMarketIntent(input.latestMessage);
  const marketIntents = collectMarketIntents(input.latestMessage);
  const scamProtectionResponse = buildHeuristicScamProtectionResponse({
    latestMessage: input.latestMessage,
    language,
  });
  if (scamProtectionResponse) {
    return scamProtectionResponse;
  }
  const income = Math.max(0, Number(input.monthlyIncome || 0));
  const expenses = Math.max(0, Number(input.monthlyExpenses || 0));
  const balance = Math.max(0, Number(input.currentBalance || 0));
  const recentTransactions = summarizeRecentTransactions(
    input.recentTransactions,
  );
  const netCashFlow = income - expenses;
  const recentSpend = recentTransactions
    .filter((tx) => tx.direction === "debit")
    .reduce((sum, tx) => sum + Math.max(0, Number(tx.amount || 0)), 0);

  const suggestedDepositAmount =
    netCashFlow > 0 ? roundMoney(clamp(netCashFlow * 0.35, 50, 5000)) : null;
  const asksLongTermSavingsPlan =
    /\b(tiet kiem dai han|ke hoach tiet kiem|long term savings?|saving plan|muc tieu tiet kiem|save for|quy hoc phi|quy mua nha|6 thang|12 thang|1 nam|2 nam|3 nam)\b/.test(
      latest,
    );

  if (asksLongTermSavingsPlan) {
    const horizonMonths = (() => {
      const explicitMonths = latest.match(/(\d+)\s*thang/)?.[1];
      if (explicitMonths) return clamp(Number(explicitMonths), 1, 60);
      const explicitYears = latest.match(/(\d+)\s*(nam|year|years)/)?.[1];
      if (explicitYears) return clamp(Number(explicitYears) * 12, 12, 120);
      return 12;
    })();
    const safeMonthlySave =
      netCashFlow > 0 ? roundMoney(Math.max(0, netCashFlow * 0.4)) : 0;
    const projectedBalance = roundMoney(
      balance + safeMonthlySave * horizonMonths,
    );
    const planTable = buildCopilotMarkdownTable(
      language === "vi" ? ["Hạng mục", "Giá trị"] : ["Item", "Value"],
      [
        [
          language === "vi" ? "Số dư hiện tại" : "Current balance",
          formatCopilotMoney(input.currency, balance),
        ],
        [
          language === "vi" ? "Dòng tiền ròng tháng" : "Monthly free cash flow",
          formatCopilotSignedMoney(input.currency, netCashFlow),
        ],
        [
          language === "vi"
            ? "Mức tiết kiệm gợi ý / tháng"
            : "Suggested monthly saving",
          formatCopilotMoney(input.currency, safeMonthlySave),
        ],
        [
          language === "vi" ? "Khung thời gian" : "Horizon",
          language === "vi"
            ? `${horizonMonths} tháng`
            : `${horizonMonths} months`,
        ],
        [
          language === "vi"
            ? "Số dư ước tính cuối kỳ"
            : "Projected balance at horizon",
          formatCopilotMoney(input.currency, projectedBalance),
        ],
      ],
    );

    return {
      reply:
        language === "vi"
          ? `Tôi đã dùng số dư ví và dòng tiền hiện tại để lập một kế hoạch tiết kiệm dài hạn có thể duy trì đều thay vì quá sức.\n\n${planTable}\n\nNếu bạn muốn đi đường dài hạn, ưu tiên là giữ đều lịch tiết kiệm hàng tháng và không để một giao dịch tùy ý làm vỡ kỷ luật dòng tiền.`
          : `I used your current wallet balance and cash flow to outline a long-term saving plan that looks sustainable instead of aggressive.\n\n${planTable}\n\nFor longer goals, the main edge is consistency: keep the monthly saving habit stable and avoid letting discretionary spending break the plan.`,
      topic: "long-term-savings-plan",
      suggestedActions:
        language === "vi"
          ? [
              "Cho tôi biết mục tiêu cụ thể như học phí, dự phòng hay mua tài sản để tôi siết kế hoạch sát hơn.",
              "Nếu thu nhập không đều, tôi có thể đổi thành mức tiết kiệm tối thiểu và mức tiết kiệm stretch.",
              "Hỏi tôi báo cáo chi tiêu tháng này nếu bạn muốn tìm thêm room cho tiết kiệm.",
            ]
          : [
              "Tell me the exact goal, such as tuition, emergency fund, or a major purchase, and I can tighten the plan.",
              "If income is uneven, I can split this into a minimum target and a stretch target.",
              "Ask for this month's spending report if you want to free up more saving room.",
            ],
      suggestedDepositAmount: safeMonthlySave || null,
      riskLevel: netCashFlow > 0 ? "low" : "medium",
      confidence: 0.87,
      followUpQuestion: localizeCopilotText(
        language,
        "Bạn muốn tôi đổi kế hoạch này theo mục tiêu 6 tháng, 12 tháng hay 24 tháng?",
        "Do you want me to reshape this plan for a 6, 12, or 24 month goal?",
      ),
    };
  }

  if (
    /deposit|top up|fund|emergency|save|nap tien|gui tien|tiet kiem|quy du phong|du phong/.test(
      latest,
    )
  ) {
    const summaryTable = buildCopilotMarkdownTable(
      language === "vi" ? ["Chỉ số", "Giá trị"] : ["Metric", "Value"],
      [
        [
          language === "vi" ? "Số dư hiện tại" : "Current balance",
          formatCopilotMoney(input.currency, balance),
        ],
        [
          language === "vi" ? "Thu nhập tháng" : "Monthly income",
          formatCopilotMoney(input.currency, income),
        ],
        [
          language === "vi" ? "Chi phí tháng" : "Monthly expenses",
          formatCopilotMoney(input.currency, expenses),
        ],
        [
          language === "vi" ? "Dòng tiền ròng" : "Net cash flow",
          formatCopilotSignedMoney(input.currency, netCashFlow),
        ],
        [
          language === "vi" ? "Mức nạp gợi ý" : "Suggested deposit",
          suggestedDepositAmount !== null
            ? formatCopilotMoney(input.currency, suggestedDepositAmount)
            : language === "vi"
              ? "Cần thêm dữ liệu"
              : "Need more data",
        ],
      ],
    );
    return {
      reply:
        language === "vi"
          ? netCashFlow > 0
            ? `Ví của bạn có khả năng hấp thụ một khoản nạp thêm có kế hoạch mà không gây áp lực lớn lên dòng tiền hàng tháng. Dựa trên các số liệu bạn nhập, nạp theo từng đợt sẽ an toàn hơn chuyển một khoản lớn ngay lập tức.\n\n${summaryTable}`
            : `Dữ liệu hiện tại cho thấy dòng tiền tự do đang hạn chế, vì vậy tôi sẽ ưu tiên giữ thanh khoản và tránh nạp thêm quá mạnh ở lúc này.\n\n${summaryTable}`
          : netCashFlow > 0
            ? `Your wallet can likely absorb a planned top-up without stressing monthly cash flow. Based on the numbers you entered, a staged deposit is safer than moving a large amount at once.\n\n${summaryTable}`
            : `Your current inputs show limited free cash flow, so I would avoid an aggressive top-up and preserve liquidity first.\n\n${summaryTable}`,
      topic: "deposit-planning",
      suggestedActions:
        language === "vi"
          ? [
              "Giữ lại ít nhất một chu kỳ chi phí hàng tháng ở trạng thái thanh khoản trước khi nạp thêm lớn.",
              suggestedDepositAmount
                ? `Bắt đầu với mức nạp khoảng ${input.currency} ${suggestedDepositAmount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}.`
                : "Cập nhật thu nhập và chi phí hàng tháng để tôi đề xuất mức nạp chính xác hơn.",
              "Rà soát các giao dịch ghi nợ định kỳ để cắt giảm những khoản có thể tối ưu trong tháng này.",
            ]
          : [
              "Keep at least one monthly expense cycle liquid before larger deposits.",
              suggestedDepositAmount
                ? `Start with a deposit around ${input.currency} ${suggestedDepositAmount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}.`
                : "Update monthly income and expenses to improve the deposit recommendation.",
              "Review recurring debit transactions for expenses that can be reduced this month.",
            ],
      suggestedDepositAmount,
      riskLevel: netCashFlow > 0 ? "low" : "medium",
      confidence: netCashFlow > 0 ? 0.84 : 0.7,
      followUpQuestion: localizeCopilotText(
        language,
        "Bạn muốn tôi đề xuất sát hơn cho quỹ dự phòng, học phí hay phân bổ tiền đầu tư không?",
        "Do you want a tighter recommendation for emergency fund, tuition, or investment cash allocation?",
      ),
    };
  }

  if (
    /spend|expense|budget|cash flow|cashflow|chi tieu|chi phi|ngan sach|dong tien/.test(
      latest,
    )
  ) {
    const summaryTable = buildCopilotMarkdownTable(
      language === "vi" ? ["Chi so", "Gia tri"] : ["Metric", "Value"],
      [
        [
          language === "vi" ? "Tong chi gan day" : "Recent debit total",
          formatCopilotMoney(input.currency, recentSpend),
        ],
        [
          language === "vi" ? "Thu nhap thang" : "Monthly income",
          formatCopilotMoney(input.currency, income),
        ],
        [
          language === "vi" ? "Chi phi thang" : "Monthly expenses",
          formatCopilotMoney(input.currency, expenses),
        ],
        [
          language === "vi" ? "Dong tien rong" : "Net cash flow",
          formatCopilotSignedMoney(input.currency, netCashFlow),
        ],
        [
          language === "vi" ? "So giao dich gan day" : "Recent transactions",
          recentTransactions.length,
        ],
      ],
    );
    return {
      reply:
        language === "vi"
          ? `Toi da tong hop nhanh tinh hinh chi tieu va dong tien gan day cua ban nhu bang duoi day.\n\n${summaryTable}`
          : `I summarized your recent spending and cash-flow picture in the table below.\n\n${summaryTable}`,
      topic: "budget-review",
      suggestedActions:
        language === "vi"
          ? [
              netCashFlow >= 0
                ? "Giu dong tien duong bang cach gioi han cac khoan chuyen khong thiet yeu trong phan con lai cua chu ky."
                : "Chi phi dang vuot thu nhap; hay giam cac khoan chi tuy y truoc khi them cam ket moi.",
              "Gan nhan giao dich ghi no gan day theo nhom can thiet va tuy chon.",
              "Dat ngan sach chuyen tien theo tuan neu ban thuong xuyen rut tien khoi vi.",
            ]
          : [
              netCashFlow >= 0
                ? "Preserve positive cash flow by capping non-essential transfers for the rest of the cycle."
                : "Your expenses are outpacing income; reduce discretionary debits before adding new commitments.",
              "Tag recent debit transactions by necessity vs optional spend.",
              "Set a weekly transfer budget if you frequently move funds out of the wallet.",
            ],
      suggestedDepositAmount,
      riskLevel: netCashFlow >= 0 ? "low" : "high",
      confidence: 0.78,
      followUpQuestion: localizeCopilotText(
        language,
        "Ban co muon toi doi phan nay thanh goi y muc chi tieu theo tuan khong?",
        "Do you want me to turn this into a weekly spending cap suggestion?",
      ),
    };
  }

  if (
    /bitcoin|btc|gold|stock|usd|vnd|exchange|vang|co phieu|chung khoan|ti gia|ty gia/.test(
      latest,
    )
  ) {
    const stockEducationResponse = buildHeuristicStockEducationResponse({
      latestMessage: input.latestMessage,
      language,
      intent: marketIntent,
      intents: marketIntents,
    });
    if (stockEducationResponse) {
      return stockEducationResponse;
    }

    return {
      reply: localizeCopilotText(
        language,
        "Khong gian lam viec nay hien chua stream du lieu thi truong theo thoi gian thuc, nen toi chi co the dua ra huong dan dua tren ngu canh vi. Neu ban can quote realtime, hay ket noi nha cung cap du lieu thi truong hoac bat lai backend du lieu song.",
        "This workspace does not currently stream live market data, so I can only give wallet-context guidance here. For live quotes, wire a market data provider or re-enable a live-data backend.",
      ),
      topic: "market-context",
      suggestedActions:
        language === "vi"
          ? [
              "Xem tai san bien dong manh la von rui ro cao, khong phai thanh khoan khan cap.",
              "Uu tien quyet dinh chuyen tien va nap tien dua tren runway cua vi truoc.",
              "Them nha cung cap quote realtime neu ban muon hoi FX, vang hoac crypto theo thoi diem thuc.",
            ]
          : [
              "Treat volatile assets as high-risk capital, not emergency liquidity.",
              "Keep transfer and deposit decisions anchored to your wallet runway first.",
              "Add a live quote provider if you want real-time FX, gold, or crypto answers in the copilot.",
            ],
      suggestedDepositAmount: null,
      riskLevel: "medium",
      confidence: 0.63,
      followUpQuestion: localizeCopilotText(
        language,
        "Ban co muon toi goi y phan bo danh muc dua tren so du vi thay vi quote realtime khong?",
        "Do you want portfolio-allocation guidance based on your wallet balance instead of live quotes?",
      ),
    };
  }

  return {
    reply: localizeCopilotText(
      language,
      "Toi co the ho tro dong tien, ke hoach nap tien, do san sang giao dich va toi uu chi tieu dua tren ngu canh vi cua ban. Hay hoi ve ke hoach nap tien, danh gia chi tieu hoac kiem tra rui ro giao dich.",
      "I can help with cash flow, deposit planning, transfer readiness, and budget hygiene using your wallet context. Ask for a deposit plan, spending review, or transfer-risk check.",
    ),
    topic: "wallet-guidance",
    suggestedActions:
      language === "vi"
        ? [
            "Hoi muc goi y nap tien gan voi mot muc tieu cu the.",
            "Hoi danh gia chi tieu dua tren giao dich gan day.",
            "Dung transfer monitoring truoc cac giao dich noi bo gia tri lon.",
          ]
        : [
            "Ask for a deposit recommendation tied to a specific goal.",
            "Ask for a spending review using recent transactions.",
            "Use transfer monitoring before high-value internal transfers.",
          ],
    suggestedDepositAmount,
    riskLevel: "low",
    confidence: 0.72,
    followUpQuestion: localizeCopilotText(
      language,
      "Ban muon toi uu dieu gi truoc: tiet kiem, chuyen tien hay chi tieu hang thang?",
      "What do you want to optimize first: savings, transfers, or monthly spending?",
    ),
  };
};

const isTodayTransactionReportIntent = (message: string) => {
  const normalized = normalizeCopilotText(message);
  const asksForToday = /\b(today|hom nay)\b/.test(normalized);
  const asksForTransactions =
    /\b(transaction|transactions|giao dich|dong tien|thu chi|money flow|cash flow|sao ke|statement)\b/.test(
      normalized,
    );
  const asksForReport =
    /\b(report|summary|summarize|list|bao cao|tong hop|liet ke|thong ke|sao ke|statement)\b/.test(
      normalized,
    ) ||
    /giao dich hom nay|transactions today|today transaction/.test(normalized) ||
    (asksForToday &&
      asksForTransactions &&
      /\b(xem|cho toi|cua toi|my|show|review|giup|di)\b/.test(normalized));

  return asksForToday && asksForTransactions && asksForReport;
};

const isWeeklyTransactionReportIntent = (message: string) => {
  const normalized = normalizeCopilotText(message);
  const asksForWeek =
    /\b(this week|weekly|last week|past week|past 7 days|last 7 days|7 day|7 days|tuan nay|tuan qua|7 ngay qua|7 ngay gan day)\b/.test(
      normalized,
    ) ||
    /giao dich tuan|bao cao tuan|weekly transaction|week report/.test(
      normalized,
    );
  const asksForTransactions =
    /\b(transaction|transactions|giao dich|dong tien|thu chi|money flow|cash flow|sao ke|statement)\b/.test(
      normalized,
    );
  const asksForReport =
    /\b(report|summary|summarize|list|bao cao|tong hop|liet ke|thong ke|sao ke|statement)\b/.test(
      normalized,
    ) ||
    /giao dich tuan|weekly transaction|week transaction/.test(normalized) ||
    (asksForWeek &&
      asksForTransactions &&
      /\b(xem|cho toi|cua toi|my|show|review|giup|di|trong)\b/.test(
        normalized,
      ));

  return asksForWeek && asksForTransactions && asksForReport;
};

const isMonthlyTransactionReportIntent = (message: string) => {
  const normalized = normalizeCopilotText(message);
  const asksForMonth =
    /\b(this month|monthly|month report|month summary|past month|last 30 days|30 days|30 day|1 month|one month|thang nay|thang truoc|1 thang qua|mot thang qua|30 ngay qua|bao cao thang|tong hop thang|thong ke thang)\b/.test(
      normalized,
    ) ||
    /\b(sao ke|statement)\b/.test(normalized) ||
    /\b(trong|during)\s+(1\s+thang\s+qua|mot\s+thang\s+qua|30\s+ngay\s+qua|1\s+month|30\s+days)\b/.test(
      normalized,
    );
  const asksForTransactions =
    /\b(transaction|transactions|giao dich|dong tien|thu chi|money flow|cash flow|sao ke)\b/.test(
      normalized,
    );
  const asksForReport =
    /\b(report|summary|summarize|list|bao cao|tong hop|liet ke|thong ke|sao ke|statement)\b/.test(
      normalized,
    ) ||
    (asksForMonth &&
      asksForTransactions &&
      /\b(xem|cho toi|cua toi|my|show|review|giup|di|trong)\b/.test(
        normalized,
      ));

  return asksForMonth && asksForTransactions && asksForReport;
};

const buildContextAwareCopilotUserMessage = (
  messages: CopilotMessagePayload[],
) => {
  const userMessages = messages.filter((message) => message.role === "user");
  const latest = userMessages[userMessages.length - 1]?.content?.trim() || "";
  const previous = userMessages[userMessages.length - 2]?.content?.trim() || "";
  if (!latest || !previous) return latest;

  const normalizedLatest = normalizeCopilotText(latest);
  const isContextualFollowUp =
    latest.length <= 120 &&
    /\b(so sanh|compare|comparison|vs|versus|thi sao|the nao|thang truoc|tuan truoc|hom qua|chi tiet hon|noi ro hon|tach them|tach rieng|them nua|deep dive|lap lai|lam lai|tao lai|can lai|dieu chinh lai|replan|rebalance)\b/.test(
      normalizedLatest,
    );

  return isContextualFollowUp ? `${previous}\n${latest}` : latest;
};

const isBudgetPlanRebuildIntent = (
  message: string,
  contextMessage?: string | null,
) => {
  const normalized = normalizeCopilotText(message);
  const contextualNormalized = normalizeCopilotText(
    [contextMessage || "", message].filter(Boolean).join("\n"),
  );
  const asksToRebuild =
    /\b(lap lai|lam lai|tao lai|can lai|dieu chinh lai|tinh lai|sua lai|replan|rebalance|rebuild|redo)\b/.test(
      normalized,
    );
  const mentionsBudgetContext =
    /\b(budget|ngan sach|ke hoach|chi tieu|tieu|han muc|tiet kiem|tich kiem|de danh|spending cap|saving|thang nay|vuot ngan sach|over budget|qua nhieu)\b/.test(
      contextualNormalized,
    );

  return asksToRebuild && mentionsBudgetContext;
};

const isSpendingComparisonIntent = (
  message: string,
  contextMessage?: string | null,
) => {
  const normalized = normalizeCopilotText(message);
  const contextualNormalized = normalizeCopilotText(
    [contextMessage || "", message].filter(Boolean).join("\n"),
  );
  const asksComparison =
    /\b(so sanh|so voi|compare|comparison|vs|versus|trend|xu huong)\b/.test(
      normalized,
    ) ||
    /\b(hom nay.*hom qua|tuan nay.*tuan truoc|thang nay.*thang truoc|today.*yesterday|this week.*last week|this month.*last month)\b/.test(
      normalized,
    );
  const asksSpending =
    /\b(chi tieu|spend|spending|thu chi|money flow|cash flow)\b/.test(
      normalized,
    );
  const asksReportLikeReview =
    /\b(bao cao|tong hop|liet ke|thong ke|phan tich|xem|review|summary|report|statement)\b/.test(
      normalized,
    );
  const contextSuggestsTransactionReview =
    /\b(transaction|transactions|giao dich|sao ke|statement|bao cao|tong hop|liet ke|thong ke)\b/.test(
      contextualNormalized,
    );
  const asksRelativeComparisonOnly =
    /\b(thang truoc|tuan truoc|hom qua|last month|last week|yesterday)\b/.test(
      normalized,
    );

  return (
    (asksSpending || contextSuggestsTransactionReview) &&
    (asksComparison ||
      asksRelativeComparisonOnly ||
      (asksReportLikeReview &&
        /\b(hom nay|hom qua|tuan nay|tuan truoc|thang nay|thang truoc|today|yesterday|this week|last week|this month|last month)\b/.test(
          normalized,
        )))
  );
};

const formatCopilotTransactionLine = (input: {
  language: CopilotLanguage;
  currency: string;
  createdAt: Date;
  amount: number;
  direction: "credit" | "debit";
  description: string;
  type: string;
}) => {
  const timeLabel = input.createdAt.toLocaleTimeString(
    input.language === "vi" ? "vi-VN" : "en-US",
    {
      timeZone: APP_TIMEZONE,
      hour: "2-digit",
      minute: "2-digit",
      hour12: input.language !== "vi",
    },
  );
  const amountLabel = formatCopilotMoney(input.currency, input.amount);
  const signedAmount =
    input.direction === "credit" ? `+${amountLabel}` : `-${amountLabel}`;

  return input.language === "vi"
    ? `- ${timeLabel} | ${input.direction === "credit" ? "Vào" : "Ra"} | ${signedAmount} | ${input.description} (${input.type})`
    : `- ${timeLabel} | ${input.direction === "credit" ? "Inflow" : "Outflow"} | ${signedAmount} | ${input.description} (${input.type})`;
};

const buildTransactionReportReply = (input: {
  language: CopilotLanguage;
  currency: string;
  transactions: Array<{
    amount: number;
    createdAt: Date;
    direction: "credit" | "debit";
    type: string;
    description: string;
  }>;
  periodLabel: string;
  detailMode: "time" | "datetime";
}) => {
  const inflows = input.transactions.filter(
    (transaction) => transaction.direction === "credit",
  );
  const outflows = input.transactions.filter(
    (transaction) => transaction.direction === "debit",
  );
  const totalInflow = roundMoney(
    inflows.reduce((sum, transaction) => sum + transaction.amount, 0),
  );
  const totalOutflow = roundMoney(
    outflows.reduce((sum, transaction) => sum + transaction.amount, 0),
  );
  const netFlow = roundMoney(totalInflow - totalOutflow);

  const summaryTable = buildCopilotMarkdownTable(
    input.language === "vi" ? ["Chỉ số", "Giá trị"] : ["Metric", "Value"],
    [
      [
        input.language === "vi" ? "Tổng tiền vào" : "Total inflow",
        formatCopilotMoney(input.currency, totalInflow),
      ],
      [
        input.language === "vi" ? "Tổng tiền ra" : "Total outflow",
        formatCopilotMoney(input.currency, totalOutflow),
      ],
      [
        input.language === "vi" ? "Dòng tiền ròng" : "Net flow",
        formatCopilotSignedMoney(input.currency, netFlow),
      ],
      [
        input.language === "vi" ? "Số giao dịch" : "Transaction count",
        input.transactions.length,
      ],
    ],
  );

  const detailRows = input.transactions.map((transaction) => [
    formatCopilotTransactionTimestamp(
      input.language,
      transaction.createdAt,
      input.detailMode,
    ),
    input.language === "vi"
      ? transaction.direction === "credit"
        ? "Vào"
        : "Ra"
      : transaction.direction === "credit"
        ? "Inflow"
        : "Outflow",
    formatCopilotSignedMoney(
      input.currency,
      transaction.direction === "credit"
        ? transaction.amount
        : -transaction.amount,
    ),
    transaction.description,
    transaction.type,
  ]);

  const detailsTable =
    detailRows.length > 0
      ? buildCopilotMarkdownTable(
          input.language === "vi"
            ? ["Thời gian", "Hướng", "Số tiền", "Nội dung", "Loại"]
            : ["Time", "Direction", "Amount", "Description", "Type"],
          detailRows,
        )
      : null;

  if (!detailRows.length) {
    return [
      input.periodLabel,
      "",
      summaryTable,
      "",
      localizeCopilotText(
        input.language,
        "Không có giao dịch trong khoảng thời gian này.",
        "There were no transactions in this period.",
      ),
    ].join("\n");
  }

  return [
    input.periodLabel,
    "",
    summaryTable,
    "",
    input.language === "vi" ? "Chi tiết giao dịch:" : "Transaction details:",
    "",
    detailsTable,
  ].join("\n");
};

const getStartOfDay = (value: Date) => {
  const next = new Date(value);
  next.setHours(0, 0, 0, 0);
  return next;
};

const getStartOfWeek = (value: Date) => {
  const next = getStartOfDay(value);
  const currentDay = next.getDay();
  const diff = currentDay === 0 ? -6 : 1 - currentDay;
  next.setDate(next.getDate() + diff);
  return next;
};

const getStartOfMonth = (value: Date) => {
  const next = getStartOfDay(value);
  next.setDate(1);
  return next;
};

const getEndOfDay = (value: Date) => {
  const next = getStartOfDay(value);
  next.setDate(next.getDate() + 1);
  return next;
};

const getEndOfWeek = (value: Date) => {
  const next = getStartOfWeek(value);
  next.setDate(next.getDate() + 7);
  return next;
};

const getEndOfMonth = (value: Date) => {
  const next = getStartOfMonth(value);
  next.setMonth(next.getMonth() + 1);
  return next;
};

const getBudgetDigestPeriodRange = (period: BudgetDigestPeriod, now: Date) => {
  if (period === "daily") {
    return {
      startInclusive: getStartOfDay(now),
      endExclusive: getEndOfDay(now),
      previousStartInclusive: getStartOfDay(new Date(now.getTime() - 86400000)),
      previousEndExclusive: getStartOfDay(now),
    };
  }
  if (period === "weekly") {
    const startInclusive = getStartOfWeek(now);
    const previousStartInclusive = new Date(startInclusive);
    previousStartInclusive.setDate(previousStartInclusive.getDate() - 7);
    return {
      startInclusive,
      endExclusive: getEndOfWeek(now),
      previousStartInclusive,
      previousEndExclusive: startInclusive,
    };
  }
  const startInclusive = getStartOfMonth(now);
  const previousStartInclusive = new Date(startInclusive);
  previousStartInclusive.setMonth(previousStartInclusive.getMonth() - 1);
  return {
    startInclusive,
    endExclusive: getEndOfMonth(now),
    previousStartInclusive,
    previousEndExclusive: startInclusive,
  };
};

const getBudgetDigestPeriodKey = (period: BudgetDigestPeriod, now: Date) => {
  if (period === "daily") {
    return formatCopilotCalendarDate("en", getStartOfDay(now));
  }
  if (period === "weekly") {
    return formatCopilotCalendarDate("en", getStartOfWeek(now));
  }
  const month = String(now.getMonth() + 1).padStart(2, "0");
  return `${now.getFullYear()}-${month}`;
};

const mapTransactionsForCopilot = (
  txns: Parameters<typeof decryptStoredTransaction>[0][],
  context: string,
) =>
  txns
    .map((txn) => safelyDecryptTransaction(txn, context))
    .filter((txn): txn is NonNullable<typeof txn> => Boolean(txn))
    .map((txn) => {
      const metadata =
        txn.metadata && typeof txn.metadata === "object"
          ? (txn.metadata as Record<string, unknown>)
          : null;
      const direction: "credit" | "debit" =
        txn.type === "DEPOSIT" || metadata?.entry === "CREDIT"
          ? "credit"
          : "debit";

      return {
        id: txn.id,
        amount: Math.max(0, Number(txn.amount || 0)),
        createdAt: txn.createdAt,
        direction,
        type: txn.type,
        description:
          txn.description?.trim() ||
          (txn.type === "DEPOSIT"
            ? "Wallet deposit"
            : txn.type === "WITHDRAW"
              ? "Wallet withdrawal"
              : "Wallet transfer"),
      };
    });

const fetchCopilotTransactionsForUser = async (input: {
  userId: string;
  startInclusive: Date;
  endExclusive: Date;
  limit: number;
  context: string;
}) => {
  const wallets = await prisma.wallet.findMany({
    where: { userId: input.userId },
    select: { id: true },
  });
  const walletIds = wallets.map((wallet: { id: string }) => wallet.id);

  const txns = await prisma.transaction.findMany({
    where: {
      ...(walletIds.length
        ? { walletId: { in: walletIds } }
        : { walletId: "__NO_WALLET__" }),
      createdAt: {
        gte: input.startInclusive,
        lt: input.endExclusive,
      },
    },
    orderBy: { createdAt: "asc" },
    take: input.limit,
  });

  return mapTransactionsForCopilot(txns, input.context);
};

const buildCopilotSourceTruthContext = async (input: {
  userId: string;
  preferredCurrency?: string | null;
}) => {
  const wallets = await prisma.wallet.findMany({
    where: { userId: input.userId },
    select: { id: true, balance: true, currency: true },
  });
  const preferredCurrency =
    typeof input.preferredCurrency === "string" &&
    input.preferredCurrency.trim().length
      ? input.preferredCurrency.trim().toUpperCase()
      : null;
  const resolvedCurrency =
    preferredCurrency ||
    wallets.find((wallet) => typeof wallet.currency === "string")?.currency ||
    "USD";
  const walletBalance = roundMoney(
    wallets
      .filter(
        (wallet) =>
          !preferredCurrency ||
          (wallet.currency || "").toUpperCase() === resolvedCurrency,
      )
      .reduce(
        (sum, wallet) => sum + Math.max(0, Number(wallet.balance || 0)),
        0,
      ),
  );

  const now = new Date();
  const lookbackStart = new Date(now);
  lookbackStart.setDate(lookbackStart.getDate() - 90);
  const monthlyStart = new Date(now);
  monthlyStart.setDate(monthlyStart.getDate() - 30);

  const transactions = await fetchCopilotTransactionsForUser({
    userId: input.userId,
    startInclusive: lookbackStart,
    endExclusive: now,
    limit: 500,
    context: "/ai/copilot-chat:source-truth",
  });

  const monthlyTransactions = transactions.filter(
    (transaction) => transaction.createdAt >= monthlyStart,
  );
  const monthlyIncome = roundMoney(
    monthlyTransactions.reduce(
      (sum, transaction) =>
        sum +
        (transaction.direction === "credit"
          ? Math.max(0, Number(transaction.amount || 0))
          : 0),
      0,
    ),
  );
  const monthlyExpenses = roundMoney(
    monthlyTransactions.reduce(
      (sum, transaction) =>
        sum +
        (transaction.direction === "debit"
          ? Math.max(0, Number(transaction.amount || 0))
          : 0),
      0,
    ),
  );

  return {
    currency: resolvedCurrency,
    currentBalance: walletBalance,
    monthlyIncome,
    monthlyExpenses,
    recentTransactions: transactions.slice(-120),
  };
};

const buildFallbackCopilotSourceTruthContext = (input: {
  preferredCurrency?: string | null;
}) => ({
  currency:
    typeof input.preferredCurrency === "string" &&
    input.preferredCurrency.trim().length
      ? input.preferredCurrency.trim().toUpperCase()
      : "USD",
  currentBalance: 0,
  monthlyIncome: 0,
  monthlyExpenses: 0,
  recentTransactions: [] as CopilotTransactionPayload[],
});

const sumDebitAmount = (
  transactions: Array<{ amount: number; direction: "credit" | "debit" }>,
) =>
  roundMoney(
    transactions.reduce(
      (sum, transaction) =>
        sum +
        (transaction.direction === "debit"
          ? Math.max(0, transaction.amount)
          : 0),
      0,
    ),
  );

const buildComparisonRow = (input: {
  currentLabel: string;
  previousLabel: string;
  current: number;
  previous: number;
  currency: string;
  language: CopilotLanguage;
}) => {
  const delta = roundMoney(input.current - input.previous);
  const percent =
    input.previous > 0
      ? `${delta >= 0 ? "+" : ""}${roundMoney((delta / input.previous) * 100).toFixed(2)}%`
      : input.current > 0
        ? input.language === "vi"
          ? "mới phát sinh"
          : "new spend"
        : "0.00%";

  return [
    input.currentLabel,
    formatCopilotMoney(input.currency, input.current),
    input.previousLabel,
    formatCopilotMoney(input.currency, input.previous),
    formatCopilotSignedMoney(input.currency, delta),
    percent,
  ];
};

const sumCompletedDebitTransactionsForUser = async (input: {
  userId: string;
  startInclusive: Date;
  endExclusive: Date;
  context: string;
}) => {
  const wallets = await prisma.wallet.findMany({
    where: { userId: input.userId },
    select: { id: true },
  });
  const walletIds = wallets.map((wallet: { id: string }) => wallet.id);
  const txns = await prisma.transaction.findMany({
    where: {
      ...(walletIds.length
        ? { walletId: { in: walletIds } }
        : { walletId: "__NO_WALLET__" }),
      createdAt: {
        gte: input.startInclusive,
        lt: input.endExclusive,
      },
    },
    orderBy: { createdAt: "asc" },
    take: 3000,
  });

  return roundMoney(
    txns.reduce((sum, txn) => {
      const decrypted = safelyDecryptTransaction(txn, input.context);
      if (!decrypted) return sum;
      if (decrypted.status !== "COMPLETED") return sum;
      const metadata = normalizeRecord(decrypted.metadata);
      const isDebit =
        decrypted.type !== "DEPOSIT" && metadata.entry !== "CREDIT";
      return sum + (isDebit ? Math.max(0, Number(decrypted.amount || 0)) : 0);
    }, 0),
  );
};

const buildBudgetPlanReply = (input: {
  language: CopilotLanguage;
  plan: StoredBudgetPlan;
  isNewPlan: boolean;
}) => {
  const overviewRows: Array<[string, string]> = [];
  if (input.plan.planningMode === "savings_goal") {
    overviewRows.push(
      [
        input.language === "vi" ? "Chế độ lập kế hoạch" : "Planning mode",
        localizeCopilotText(
          input.language,
          "Theo mục tiêu tiết kiệm",
          "Savings-led budget",
        ),
      ],
      [
        input.language === "vi"
          ? "Mục tiêu để dành cuối tháng"
          : "End-of-month savings goal",
        formatCopilotMoney(
          input.plan.currency,
          Math.max(0, input.plan.savingsGoalAmount || 0),
        ),
      ],
      [
        input.language === "vi"
          ? "Nguồn tiền tháng dùng để tính"
          : "Monthly income baseline used",
        formatCopilotMoney(
          input.plan.currency,
          Math.max(0, input.plan.incomeBaselineAmount || 0),
        ),
      ],
      [
        input.language === "vi"
          ? "Trần chi tối đa để giữ mục tiêu"
          : "Allowed spend cap to protect the goal",
        formatCopilotMoney(input.plan.currency, input.plan.targetAmount),
      ],
    );
  } else {
    overviewRows.push([
      input.language === "vi" ? "Trần chi tiêu tháng" : "Monthly budget cap",
      formatCopilotMoney(input.plan.currency, input.plan.targetAmount),
    ]);
  }

  overviewRows.push(
    [
      input.language === "vi" ? "Đã chi trong kỳ" : "Spent in active period",
      formatCopilotMoney(input.plan.currency, input.plan.spentAmount),
    ],
    [
      input.language === "vi" ? "Còn lại" : "Remaining budget",
      input.plan.remainingAmount >= 0
        ? formatCopilotMoney(input.plan.currency, input.plan.remainingAmount)
        : `-${formatCopilotMoney(
            input.plan.currency,
            Math.abs(input.plan.remainingAmount),
          )}`,
    ],
    [
      input.language === "vi"
        ? "Trần chi / ngày còn lại"
        : "Daily cap for remaining days",
      typeof input.plan.dailyCapRemaining === "number"
        ? formatCopilotMoney(input.plan.currency, input.plan.dailyCapRemaining)
        : input.language === "vi"
          ? "Không áp dụng"
          : "Not available",
    ],
    [
      input.language === "vi"
        ? "Trần chi / tuần còn lại"
        : "Weekly cap for remaining weeks",
      typeof input.plan.weeklyCapRemaining === "number"
        ? formatCopilotMoney(input.plan.currency, input.plan.weeklyCapRemaining)
        : input.language === "vi"
          ? "Không áp dụng"
          : "Not available",
    ],
    [
      input.language === "vi" ? "Cảnh báo email" : "Email alert thresholds",
      `${Math.round(input.plan.warningThreshold * 100)}% / ${Math.round(
        input.plan.criticalThreshold * 100,
      )}%`,
    ],
  );

  const overviewTable = buildCopilotMarkdownTable(
    input.language === "vi" ? ["Chỉ số", "Giá trị"] : ["Metric", "Value"],
    overviewRows,
  );

  const categoryTable = buildCopilotMarkdownTable(
    input.language === "vi"
      ? ["Nhóm ngân sách", "Tỷ trọng", "Hạn mức"]
      : ["Budget bucket", "Share", "Cap"],
    input.plan.categories.map((category) => [
      input.language === "vi" &&
      SPENDING_CATEGORY_ORDER.includes(category.key as SpendingCategoryKey)
        ? getSpendingCategoryLabel(
            input.language,
            category.key as SpendingCategoryKey,
          )
        : category.label,
      `${Math.round(category.share * 100)}%`,
      formatCopilotMoney(input.plan.currency, category.amount),
    ]),
  );

  const lead =
    input.language === "vi"
      ? input.isNewPlan
        ? input.plan.planningMode === "savings_goal"
          ? "Tôi đã tạo và lưu kế hoạch ngân sách theo mục tiêu tiết kiệm cho bạn. Tôi lấy mức để dành cuối tháng để suy ra trần chi tối đa, rồi hệ thống sẽ theo dõi giao dịch thực tế và gửi email khi bạn chạm ngưỡng cảnh báo hoặc vượt mức cho phép."
          : "Tôi đã tạo và lưu kế hoạch ngân sách tháng này cho bạn. Từ giờ, hệ thống sẽ theo dõi chi tiêu thực tế và gửi email khi bạn chạm ngưỡng cảnh báo hoặc vượt trần."
        : input.plan.planningMode === "savings_goal"
          ? "Đây là kế hoạch đang được lưu theo mục tiêu tiết kiệm. Tôi đã đối chiếu nó với giao dịch hiện tại để bạn thấy ngay mức chi tối đa còn lại."
          : "Đây là kế hoạch ngân sách đang được lưu trong hệ thống. Tôi đã đối chiếu nó với giao dịch hiện tại để bạn thấy ngay mức còn lại."
      : input.isNewPlan
        ? input.plan.planningMode === "savings_goal"
          ? "I created and saved a savings-led monthly plan for you. I used the savings goal to derive the maximum spending cap, and the system will now watch real spending and email you when you hit warning levels or go past the allowed limit."
          : "I created and saved this month's budget plan for you. From now on, the system will watch real spending and email you when you hit warning levels or go over budget."
        : input.plan.planningMode === "savings_goal"
          ? "This is the savings-led plan currently saved in the system. I refreshed it against your latest transactions so you can see the spend room left right now."
          : "This is the budget plan currently saved in the system. I refreshed it against your latest transactions so you can see what remains right now.";

  const pressureLine =
    input.plan.remainingAmount < 0
      ? localizeCopilotText(
          input.language,
          input.plan.planningMode === "savings_goal"
            ? "Bạn đã vượt trần chi tối đa để giữ mục tiêu tiết kiệm, vì vậy mức để dành cuối tháng đang bị đe dọa và ưu tiên lúc này là cắt giảm các khoản linh hoạt."
            : "Bạn đã vượt trần ngân sách hiện tại, vì vậy ưu tiên lúc này là cắt giảm các khoản linh hoạt cho phần còn lại của tháng.",
          input.plan.planningMode === "savings_goal"
            ? "You are already above the spend cap that protects the savings goal, so the end-of-month savings target is now at risk and flexible spending should be cut first."
            : "You are already over the current budget cap, so the priority now is to cut flexible spending for the rest of the month.",
        )
      : input.plan.utilizationRatio >= input.plan.warningThreshold
        ? localizeCopilotText(
            input.language,
            input.plan.planningMode === "savings_goal"
              ? "Bạn đang ở vùng cảnh báo của kế hoạch tiết kiệm, nên mỗi giao dịch ghi nợ tiếp theo đều ảnh hưởng trực tiếp đến số tiền bạn muốn để dành cuối tháng."
              : "Bạn đang ở vùng cảnh báo, nên mỗi giao dịch ghi nợ tiếp theo cần được cân nhắc kỹ để tránh vượt trần.",
            input.plan.planningMode === "savings_goal"
              ? "You are in the warning zone of the savings-led plan, so each new debit now directly affects the amount you want to keep by month end."
              : "You are in the warning zone, so each new debit should be weighed carefully to avoid crossing the cap.",
          )
        : localizeCopilotText(
            input.language,
            input.plan.planningMode === "savings_goal"
              ? "Nếu bạn giữ những trần chi còn lại này, mục tiêu để dành cuối tháng vẫn nằm trong tầm tay."
              : "Nếu bạn giữ những trần chi còn lại này, khả năng giữ đúng mục tiêu tháng là tốt.",
            input.plan.planningMode === "savings_goal"
              ? "If you hold to the remaining daily and weekly caps, the end-of-month savings goal is still realistic."
              : "If you keep to the remaining daily and weekly caps, the monthly target is still realistic.",
          );

  return [lead, "", overviewTable, "", pressureLine, "", categoryTable].join(
    "\n",
  );
};

const buildBudgetPromptMissingAmountResponse = (input: {
  language: CopilotLanguage;
  currency: string;
}): CopilotResponsePayload => ({
  reply: localizeCopilotText(
    input.language,
    `Toi co the lap va luu ke hoach ngan sach ngay trong chat, nhung toi can mot tran chi tieu cu the cho thang nay. Vi du: "thang nay toi muon gioi han chi tieu o muc ${input.currency} 2,000". Ban cung co the noi "toi muon de danh ${input.currency} 500 cuoi thang" de toi tu suy tran chi toi da.`,
    `I can create and save a budget plan right here in chat, but I need a concrete monthly cap first. For example: "this month I want to keep spending under ${input.currency} 2,000". You can also say "I want to save ${input.currency} 500 by month end" and I will derive the spend cap for you.`,
  ),
  topic: "budget-plan-amount-needed",
  suggestedActions:
    input.language === "vi"
      ? [
          "Nhap tran chi tieu thang nay ban muon dat.",
          "Neu muon, noi them muc tieu tiet kiem de toi tu suy ra tran chi va chia lai ngan sach.",
          "Sau khi luu, he thong se canh bao email khi cham nguong 85% va 100%.",
        ]
      : [
          "Send the monthly spending cap you want to enforce.",
          "Add a savings goal too if you want me to derive the cap and reshape the budget mix.",
          "After saving, the system will email warnings at 85% and 100%.",
        ],
  suggestedDepositAmount: null,
  riskLevel: "low",
  confidence: 0.93,
  followUpQuestion: localizeCopilotText(
    input.language,
    "Ban muon dat tran chi tieu thang nay la bao nhieu?",
    "What monthly spending cap do you want to set?",
  ),
  budgetPlan: null,
});

const buildSavingsGoalMissingIncomeResponse = (input: {
  language: CopilotLanguage;
  currency: string;
  savingsGoalAmount: number;
}): CopilotResponsePayload => ({
  reply: localizeCopilotText(
    input.language,
    `Toi da hieu muc tieu de danh ${formatCopilotMoney(input.currency, input.savingsGoalAmount)} cuoi thang, nhung hien chua co du du lieu thu nhap thang de suy ra tran chi toi da. Ban co the nhap them thu nhap thang, vi du: "thu nhap thang nay cua toi la ${input.currency} 3,000", hoac dat thang tran chi tieu truc tiep.`,
    `I understand the goal to save ${formatCopilotMoney(input.currency, input.savingsGoalAmount)} by month end, but I do not have enough monthly income data yet to derive a safe spending cap. You can provide monthly income, for example "my income this month is ${input.currency} 3,000", or set the spending cap directly.`,
  ),
  topic: "budget-plan-income-needed",
  suggestedActions:
    input.language === "vi"
      ? [
          "Nhap thu nhap thang de toi suy ra tran chi toi da.",
          "Hoac gui truc tiep tran chi tieu ban muon dat trong thang nay.",
          "Sau khi luu, he thong se doi chieu giao dich voi ke hoach moi.",
        ]
      : [
          "Share monthly income so I can derive a safe spending cap.",
          "Or send the exact spending cap you want to set this month.",
          "Once saved, the system will compare transactions against the new plan.",
        ],
  suggestedDepositAmount: null,
  riskLevel: "low",
  confidence: 0.91,
  followUpQuestion: localizeCopilotText(
    input.language,
    "Thu nhap thang nay cua ban khoang bao nhieu?",
    "What is your expected monthly income?",
  ),
  budgetPlan: null,
});

const buildSavingsGoalTooHighResponse = (input: {
  language: CopilotLanguage;
  currency: string;
  savingsGoalAmount: number;
  incomeBaselineAmount: number;
}): CopilotResponsePayload => ({
  reply: localizeCopilotText(
    input.language,
    `Toi da doi muc tieu de danh ${formatCopilotMoney(input.currency, input.savingsGoalAmount)} voi dong tien vao thang gan day la ${formatCopilotMoney(input.currency, input.incomeBaselineAmount)}, va muc tieu nay dang cao hon hoac bang toan bo thu nhap thang duoc ghi nhan. De lap ke hoach kha thi, ban nen giam muc tieu de danh hoac gui cho toi mot tran chi tieu cu the.`,
    `I compared the savings goal of ${formatCopilotMoney(input.currency, input.savingsGoalAmount)} with the recent monthly inflow baseline of ${formatCopilotMoney(input.currency, input.incomeBaselineAmount)}, and the goal is at or above the full monthly income on record. To build a workable plan, lower the savings goal or send me a direct monthly spending cap.`,
  ),
  topic: "budget-plan-savings-goal-too-high",
  suggestedActions:
    input.language === "vi"
      ? [
          "Giam muc tieu de danh xuong duoi muc thu nhap thang duoc ghi nhan.",
          "Hoac dat mot tran chi tieu thang cu the de toi luu ke hoach ngay.",
          "Neu du lieu thu nhap hien tai chua dung, ban co the cap nhat thu nhap va hoi lai.",
        ]
      : [
          "Lower the savings goal below the income level currently on record.",
          "Or set a direct monthly spending cap so I can save the plan now.",
          "If the income baseline is outdated, update it and ask again.",
        ],
  suggestedDepositAmount: null,
  riskLevel: "medium",
  confidence: 0.92,
  followUpQuestion: localizeCopilotText(
    input.language,
    "Ban muon toi tinh lai voi mot muc tiet kiem thap hon khong?",
    "Do you want me to recalculate with a smaller savings goal?",
  ),
  budgetPlan: null,
});

const buildWeeklyBudgetPromptMissingAmountResponse = (input: {
  language: CopilotLanguage;
  currency: string;
}): CopilotResponsePayload => ({
  reply: localizeCopilotText(
    input.language,
    `Tôi có thể lập kế hoạch chi tiêu cho tuần tiếp theo ngay trong chat, nhưng tôi cần tổng kinh phí cho tuần đó. Ví dụ: "lập kế hoạch chi tiêu cho tuần tới, kinh phí ${input.currency} 2,000".`,
    `I can create a spending plan for next week right here in chat, but I need the total budget for that week first. For example: "plan next week spending, budget ${input.currency} 2,000".`,
  ),
  topic: "budget-plan-weekly-amount-needed",
  suggestedActions:
    input.language === "vi"
      ? [
          "Nhập tổng kinh phí bạn muốn dùng cho tuần tới.",
          "Nếu muốn, bạn có thể thêm tỷ trọng danh mục ngay trong cùng tin nhắn.",
          "Ví dụ: ăn uống 30%, đi lại 10%, hóa đơn 20%.",
        ]
      : [
          "Send the total amount you want to use next week.",
          "You can also include category percentages in the same message.",
          "For example: food 30%, transport 10%, bills 20%.",
        ],
  suggestedDepositAmount: null,
  riskLevel: "low",
  confidence: 0.94,
  followUpQuestion: localizeCopilotText(
    input.language,
    "Bạn muốn tổng kinh phí cho tuần tới là bao nhiêu?",
    "What total budget do you want for next week?",
  ),
  budgetPlan: null,
});

const buildWeeklyBudgetPreviewResponse = (input: {
  language: CopilotLanguage;
  currency: string;
  targetAmount: number;
  categories: StoredBudgetPlanCategory[];
  recentTransactions: CopilotTransactionPayload[];
}): CopilotResponsePayload => {
  const now = new Date();
  const nextWeekStart = getStartOfWeek(new Date(now.getTime() + 7 * 86400000));
  const nextWeekEnd = new Date(nextWeekStart);
  nextWeekEnd.setDate(nextWeekEnd.getDate() + 7);
  const lastWeekStart = getStartOfWeek(now);
  const lastWeekSpend = roundMoney(
    input.recentTransactions
      .filter(
        (transaction) =>
          transaction.direction === "debit" &&
          transaction.createdAt >= lastWeekStart &&
          transaction.createdAt < now,
      )
      .reduce((sum, transaction) => sum + transaction.amount, 0),
  );
  const dailyCap = roundMoney(input.targetAmount / 7);
  const weeklyTable = buildCopilotMarkdownTable(
    input.language === "vi" ? ["Chỉ số", "Giá trị"] : ["Metric", "Value"],
    [
      [
        input.language === "vi"
          ? "Kinh phí tuần tiếp theo"
          : "Next-week total budget",
        formatCopilotMoney(input.currency, input.targetAmount),
      ],
      [
        input.language === "vi" ? "Trần chi mỗi ngày" : "Daily cap",
        formatCopilotMoney(input.currency, dailyCap),
      ],
      [
        input.language === "vi"
          ? "Chi tuần gần nhất"
          : "Most recent week spend",
        formatCopilotMoney(input.currency, lastWeekSpend),
      ],
      [
        input.language === "vi" ? "Khoảng thời gian" : "Planned period",
        `${formatCopilotCalendarDate(input.language, nextWeekStart)} - ${formatCopilotCalendarDate(input.language, nextWeekEnd)}`,
      ],
    ],
  );
  const categoryTable = buildCopilotMarkdownTable(
    input.language === "vi"
      ? ["Danh mục", "Tỷ trọng", "Hạn mức tuần"]
      : ["Category", "Share", "Weekly cap"],
    input.categories.map((category) => [
      category.label,
      `${Math.round(category.share * 100)}%`,
      formatCopilotMoney(input.currency, category.amount),
    ]),
  );

  return {
    reply: [
      localizeCopilotText(
        input.language,
        "Tôi đã lập nhanh kế hoạch chi tiêu cho tuần tiếp theo dựa trên kinh phí bạn vừa đưa.",
        "I created a quick spending plan for next week based on the budget you provided.",
      ),
      "",
      weeklyTable,
      "",
      localizeCopilotText(
        input.language,
        "Phân bổ danh mục để bạn bám sát kế hoạch:",
        "Category allocation to keep the week under control:",
      ),
      "",
      categoryTable,
    ].join("\n"),
    topic: "budget-plan-weekly-preview",
    suggestedActions:
      input.language === "vi"
        ? [
            "Nếu muốn, chat thêm tỷ trọng danh mục như ăn uống 30%, đi lại 10% để tôi cân lại kế hoạch tuần.",
            "Hỏi tôi mức chi mỗi ngày nếu bạn muốn tôi tách thành 7 ngày cụ thể.",
            "Nếu bạn muốn lưu thành plan tháng, gửi thêm mục tiêu chi tiêu tháng.",
          ]
        : [
            "Send category percentages like food 30%, transport 10% if you want me to rebalance the weekly mix.",
            "Ask me for a day-by-day cap if you want a tighter 7-day pacing plan.",
            "If you want it saved as a persistent plan, send a monthly budget target too.",
          ],
    suggestedDepositAmount: null,
    riskLevel: lastWeekSpend > input.targetAmount ? "medium" : "low",
    confidence: 0.95,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Bạn có muốn tôi cân lại kế hoạch tuần này theo danh mục ưu tiên của bạn không?",
      "Do you want me to rebalance this weekly plan around your priority categories?",
    ),
    budgetPlan: null,
  };
};

const buildBudgetPlanCopilotResponse = async (input: {
  req: Request;
  userId: string;
  currency: string;
  language: CopilotLanguage;
  messages: CopilotMessagePayload[];
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
}): Promise<CopilotResponsePayload> => {
  const latestUserMessage =
    [...input.messages].reverse().find((message) => message.role === "user")
      ?.content || "";
  const contextualMessage =
    buildContextAwareCopilotUserMessage(input.messages) || latestUserMessage;
  const normalized = normalizeCopilotText(contextualMessage);
  const requestedBudgetAmount = extractBudgetTargetAmount(contextualMessage);
  const requestedSavingsGoalAmount =
    extractSavingsGoalAmount(contextualMessage);
  const requestedPlanningScope = extractBudgetPlanningScope(contextualMessage);
  const requestedCategoryAllocations =
    extractBudgetCategoryAllocationShares(contextualMessage);
  const requestedPreferenceUpdates =
    extractBudgetAssistantPreferenceUpdates(contextualMessage);
  const requestedDigestPeriod =
    extractBudgetDigestRequestPeriod(contextualMessage);
  const userRepository = createUserRepository();
  const userDoc = await userRepository.findValidatedById(input.userId);
  if (!userDoc) {
    return buildHeuristicCopilotResponse({
      currentBalance: input.currentBalance,
      currency: input.currency,
      monthlyIncome: input.monthlyIncome,
      monthlyExpenses: input.monthlyExpenses,
      recentTransactions: input.recentTransactions,
      latestMessage: latestUserMessage,
    });
  }
  const existingPlan = getStoredBudgetPlan(userDoc.metadata);

  if (requestedPreferenceUpdates) {
    const nextPreferences = {
      ...getBudgetAssistantPreferences(userDoc.metadata),
      ...requestedPreferenceUpdates,
    };
    await userRepository.updateMetadata(
      input.userId,
      setBudgetAssistantPreferences(userDoc.metadata, nextPreferences),
    );
    invalidateUserResponseCache(input.userId, ["auth"]);
    await logAuditEvent({
      actor: input.req.user?.email || userDoc.email,
      userId: input.userId,
      action: "BUDGET_ASSISTANT_PREFERENCES_UPDATED",
      details: nextPreferences,
      ipAddress: getRequestIp(input.req),
    });

    return buildBudgetAssistantPreferenceResponse({
      language: input.language,
      preferences: nextPreferences,
    });
  }

  if (requestedDigestPeriod) {
    return buildBudgetDigestCopilotResponse({
      userId: input.userId,
      currency: input.currency,
      language: input.language,
      period: requestedDigestPeriod,
    });
  }

  if (requestedPlanningScope === "weekly") {
    if (requestedBudgetAmount === null) {
      return buildWeeklyBudgetPromptMissingAmountResponse({
        language: input.language,
        currency: input.currency,
      });
    }

    const weeklyMix = normalizeBudgetCategoryShares({
      customShares: requestedCategoryAllocations,
      baseShares: buildBudgetPlanBaseShares(existingPlan),
    });
    const weeklyCategories = buildBudgetPlanCategories(
      requestedBudgetAmount,
      "spend_cap",
      weeklyMix
        ? {
            customShares: weeklyMix.shares,
          }
        : undefined,
    );

    return buildWeeklyBudgetPreviewResponse({
      language: input.language,
      currency: input.currency,
      targetAmount: requestedBudgetAmount,
      categories: weeklyCategories,
      recentTransactions: input.recentTransactions,
    });
  }

  if (
    requestedCategoryAllocations &&
    normalizeBudgetCategoryShares({
      customShares: requestedCategoryAllocations,
      baseShares: buildBudgetPlanBaseShares(existingPlan),
    }) === null
  ) {
    return buildBudgetCategoryAllocationInvalidResponse({
      language: input.language,
    });
  }

  if (
    existingPlan &&
    isBudgetPlanRebuildIntent(contextualMessage, latestUserMessage)
  ) {
    const now = new Date();
    const refreshedPlan = recalculateBudgetPlanProgress(
      existingPlan,
      await sumCompletedDebitTransactionsForUser({
        userId: input.userId,
        startInclusive: new Date(existingPlan.startAt),
        endExclusive: new Date(existingPlan.endAt),
        context: "/ai/copilot-chat:budget-plan-rebuild",
      }),
      now,
    );

    if (JSON.stringify(refreshedPlan) !== JSON.stringify(existingPlan)) {
      await userRepository.updateMetadata(
        input.userId,
        setStoredBudgetPlan(userDoc.metadata, refreshedPlan),
      );
      invalidateUserResponseCache(input.userId, ["auth"]);
    }

    const intro = localizeCopilotText(
      input.language,
      refreshedPlan.remainingAmount < 0
        ? "Tôi đã lập lại kế hoạch theo mức chi thực tế tháng này. Hiện bạn đã vượt trần đang lưu, nên phương án khả thi nhất là siết các nhóm chi linh hoạt hoặc đặt lại trần nếu đây là tháng ngoại lệ."
        : "Tôi đã lập lại kế hoạch theo mức chi thực tế tháng này và cân lại phần ngân sách còn lại cho những ngày còn lại trong kỳ.",
      refreshedPlan.remainingAmount < 0
        ? "I rebuilt the plan around this month's actual spending. You are already above the saved cap, so the realistic options now are to cut flexible categories or reset the cap if this is an exceptional month."
        : "I rebuilt the plan around this month's actual spending and rebalanced the remaining budget across the days left in the period.",
    );

    return {
      reply: [
        intro,
        "",
        buildBudgetPlanReply({
          language: input.language,
          plan: refreshedPlan,
          isNewPlan: false,
        }),
      ].join("\n"),
      topic: "budget-plan-rebuilt",
      suggestedActions:
        input.language === "vi"
          ? [
              "Nếu muốn, tôi có thể siết lại tỷ trọng danh mục theo mức chi hiện tại.",
              "Bạn cũng có thể gửi lại trần chi tiêu mới nếu muốn lập lại toàn bộ kế hoạch tháng.",
              "Hỏi tôi danh mục nào đang vượt mạnh nhất nếu muốn cắt nhanh.",
            ]
          : [
              "If you want, I can tighten the category mix around the current spend pattern.",
              "You can also send a new cap if you want a full month-level rebuild.",
              "Ask which category is overshooting the most if you want the fastest cuts.",
            ],
      suggestedDepositAmount: null,
      riskLevel:
        refreshedPlan.utilizationRatio >= refreshedPlan.criticalThreshold
          ? "high"
          : refreshedPlan.utilizationRatio >= refreshedPlan.warningThreshold
            ? "medium"
            : "low",
      confidence: 0.96,
      followUpQuestion: localizeCopilotText(
        input.language,
        "Bạn có muốn tôi cân lại luôn theo các danh mục ưu tiên của bạn không?",
        "Do you want me to rebalance it around your priority categories now?",
      ),
      budgetPlan: buildPublicBudgetPlanSummary(refreshedPlan),
    };
  }

  if (requestedBudgetAmount !== null || requestedSavingsGoalAmount !== null) {
    let effectiveTargetAmount = requestedBudgetAmount;
    let planningMode: "spend_cap" | "savings_goal" = "spend_cap";
    let savingsGoalAmount: number | null = null;
    let incomeBaselineAmount: number | null = null;
    const grossBudgetPoolAmount =
      requestedBudgetAmount !== null && requestedSavingsGoalAmount !== null
        ? requestedBudgetAmount
        : null;
    const explicitSavingsGoalAmount =
      requestedBudgetAmount !== null && requestedSavingsGoalAmount !== null
        ? requestedSavingsGoalAmount
        : null;
    const usesGrossBudgetPool =
      grossBudgetPoolAmount !== null &&
      explicitSavingsGoalAmount !== null &&
      /\b(kinh phi|thu nhap|nguon tien|tong tien|tong ngan sach|tong budget|available|co trong thang)\b/.test(
        normalized,
      );
    const allocationMix = normalizeBudgetCategoryShares({
      customShares: requestedCategoryAllocations,
      baseShares: buildBudgetPlanBaseShares(existingPlan),
    });

    if (usesGrossBudgetPool) {
      const derivedSpendCap = roundMoney(
        grossBudgetPoolAmount - explicitSavingsGoalAmount,
      );
      if (derivedSpendCap <= 0) {
        return buildSavingsGoalTooHighResponse({
          language: input.language,
          currency: input.currency,
          savingsGoalAmount: explicitSavingsGoalAmount,
          incomeBaselineAmount: grossBudgetPoolAmount,
        });
      }
      effectiveTargetAmount = derivedSpendCap;
      planningMode = "savings_goal";
      savingsGoalAmount = explicitSavingsGoalAmount;
      incomeBaselineAmount = roundMoney(grossBudgetPoolAmount);
    }

    if (effectiveTargetAmount === null && requestedSavingsGoalAmount !== null) {
      if (input.monthlyIncome <= 0) {
        return buildSavingsGoalMissingIncomeResponse({
          language: input.language,
          currency: input.currency,
          savingsGoalAmount: requestedSavingsGoalAmount,
        });
      }
      const derivedSpendCap = roundMoney(
        input.monthlyIncome - requestedSavingsGoalAmount,
      );
      if (derivedSpendCap <= 0) {
        return buildSavingsGoalTooHighResponse({
          language: input.language,
          currency: input.currency,
          savingsGoalAmount: requestedSavingsGoalAmount,
          incomeBaselineAmount: input.monthlyIncome,
        });
      }
      effectiveTargetAmount = derivedSpendCap;
      planningMode = "savings_goal";
      savingsGoalAmount = requestedSavingsGoalAmount;
      incomeBaselineAmount = roundMoney(input.monthlyIncome);
    }

    if (effectiveTargetAmount === null) {
      return buildBudgetPromptMissingAmountResponse({
        language: input.language,
        currency: input.currency,
      });
    }

    const now = new Date();
    const startAt = getStartOfMonth(now);
    const endAt = new Date(startAt);
    endAt.setMonth(endAt.getMonth() + 1);
    const spentAmount = await sumCompletedDebitTransactionsForUser({
      userId: input.userId,
      startInclusive: startAt,
      endExclusive: endAt,
      context: "/ai/copilot-chat:budget-plan-create",
    });
    const nextPlan = recalculateBudgetPlanProgress(
      {
        planId: crypto.randomUUID(),
        status: "ACTIVE",
        period: "MONTHLY",
        currency: input.currency,
        planningMode,
        targetAmount: effectiveTargetAmount,
        savingsGoalAmount,
        incomeBaselineAmount,
        spentAmount: 0,
        remainingAmount: effectiveTargetAmount,
        utilizationRatio: 0,
        warningThreshold: BUDGET_WARNING_THRESHOLD,
        criticalThreshold: BUDGET_CRITICAL_THRESHOLD,
        thresholdAlertsSent: [],
        startAt: startAt.toISOString(),
        endAt: endAt.toISOString(),
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        lastEvaluatedAt: now.toISOString(),
        sourcePrompt: latestUserMessage,
        dailyCapRemaining: null,
        weeklyCapRemaining: null,
        categories: buildBudgetPlanCategories(
          effectiveTargetAmount,
          planningMode,
          allocationMix
            ? {
                customShares: allocationMix.shares,
              }
            : undefined,
        ),
        emailAlertsEnabled: true,
      },
      spentAmount,
      now,
    );

    await userRepository.updateMetadata(
      input.userId,
      setStoredBudgetPlan(userDoc.metadata, nextPlan),
    );
    invalidateUserResponseCache(input.userId, ["auth"]);
    await logAuditEvent({
      actor: input.req.user?.email || userDoc.email,
      userId: input.userId,
      action: "BUDGET_PLAN_SAVED",
      details: {
        targetAmount: nextPlan.targetAmount,
        currency: nextPlan.currency,
        period: nextPlan.period,
        warningThreshold: nextPlan.warningThreshold,
        criticalThreshold: nextPlan.criticalThreshold,
      },
      ipAddress: getRequestIp(input.req),
    });

    return {
      reply: buildBudgetPlanReply({
        language: input.language,
        plan: nextPlan,
        isNewPlan: true,
      }),
      topic: "budget-plan-saved",
      suggestedActions:
        input.language === "vi"
          ? [
              "Hoi toi ngan sach hien tai con bao nhieu neu ban muon kiem tra nhanh bat ky luc nao.",
              "Khi chi tieu cham 85% hoac vuot 100%, he thong se gui email canh bao cho ban.",
              requestedCategoryAllocations
                ? "Ty trong danh muc vua duoc luu; ban co the chat lai % moi bat cu luc nao de doi mix."
                : "Ban co the chat lai mot muc tieu moi bat cu luc nao de cap nhat ke hoach.",
            ]
          : [
              "Ask me how much budget remains anytime you want a quick check.",
              "When spending reaches 85% or exceeds 100%, the system will email you a warning.",
              requestedCategoryAllocations
                ? "The category mix was saved too; send new percentages anytime to rebalance it."
                : "You can send a new target in chat anytime to replace this plan.",
            ],
      suggestedDepositAmount: null,
      riskLevel:
        nextPlan.utilizationRatio >= nextPlan.criticalThreshold
          ? "high"
          : nextPlan.utilizationRatio >= nextPlan.warningThreshold
            ? "medium"
            : "low",
      confidence: 0.96,
      followUpQuestion: localizeCopilotText(
        input.language,
        planningMode === "savings_goal"
          ? "Ban co muon toi doi chieu ngay muc chi con lai de giu muc tieu tiet kiem khong?"
          : "Ban co muon toi kiem tra ngay muc ngan sach con lai cua thang nay khong?",
        planningMode === "savings_goal"
          ? "Do you want me to check the remaining spend room that still protects the savings goal?"
          : "Do you want me to check the remaining budget for this month right now?",
      ),
      budgetPlan: buildPublicBudgetPlanSummary(nextPlan),
    };
  }

  if (requestedCategoryAllocations) {
    if (!existingPlan) {
      return buildBudgetCategoryAllocationPromptResponse({
        language: input.language,
        currency: input.currency,
      });
    }

    const allocationMix = normalizeBudgetCategoryShares({
      customShares: requestedCategoryAllocations,
      baseShares: buildBudgetPlanBaseShares(existingPlan),
    });
    if (!allocationMix) {
      return buildBudgetCategoryAllocationInvalidResponse({
        language: input.language,
      });
    }

    const now = new Date();
    const refreshedPlan = recalculateBudgetPlanProgress(
      {
        ...existingPlan,
        categories: buildBudgetPlanCategories(
          existingPlan.targetAmount,
          existingPlan.planningMode,
          {
            customShares: allocationMix.shares,
          },
        ).map((category) => ({
          ...category,
          thresholdAlertsSent:
            existingPlan.categories.find((entry) => entry.key === category.key)
              ?.thresholdAlertsSent || [],
        })),
      },
      await sumCompletedDebitTransactionsForUser({
        userId: input.userId,
        startInclusive: new Date(existingPlan.startAt),
        endExclusive: new Date(existingPlan.endAt),
        context: "/ai/copilot-chat:budget-plan-category-update",
      }),
      now,
    );

    await userRepository.updateMetadata(
      input.userId,
      setStoredBudgetPlan(userDoc.metadata, refreshedPlan),
    );
    invalidateUserResponseCache(input.userId, ["auth"]);
    await logAuditEvent({
      actor: input.req.user?.email || userDoc.email,
      userId: input.userId,
      action: "BUDGET_PLAN_CATEGORY_ALLOCATION_UPDATED",
      details: {
        targetAmount: refreshedPlan.targetAmount,
        currency: refreshedPlan.currency,
        providedCategories: allocationMix.providedKeys,
      },
      ipAddress: getRequestIp(input.req),
    });

    const intro = localizeCopilotText(
      input.language,
      allocationMix.remainderDistributed
        ? "Toi da cap nhat ty trong danh muc theo yeu cau va tu can lai phan con lai vao nhung nhom ban chua chinh."
        : "Toi da cap nhat ty trong danh muc dung theo % ban vua gui.",
      allocationMix.remainderDistributed
        ? "I updated the category weights you asked for and rebalanced the remaining share across the categories you did not touch."
        : "I updated the category weights exactly as you sent them.",
    );

    return {
      reply: [
        intro,
        "",
        buildBudgetPlanReply({
          language: input.language,
          plan: refreshedPlan,
          isNewPlan: false,
        }),
      ].join("\n"),
      topic: "budget-plan-category-updated",
      suggestedActions:
        input.language === "vi"
          ? [
              "Hoi toi danh muc nao dang tieu nhieu nhat de doi chieu voi mix moi.",
              "Neu muon, chat lai mot vai % khac va toi se can lai tiep.",
              "Khi mot danh muc cham nguong canh bao, he thong se gui email rieng.",
            ]
          : [
              "Ask which category is spending the most to compare with the new mix.",
              "Send a few new percentages anytime and I will rebalance again.",
              "When a category hits its warning threshold, the system will send a separate email alert.",
            ],
      suggestedDepositAmount: null,
      riskLevel:
        refreshedPlan.utilizationRatio >= refreshedPlan.criticalThreshold
          ? "high"
          : refreshedPlan.utilizationRatio >= refreshedPlan.warningThreshold
            ? "medium"
            : "low",
      confidence: 0.96,
      followUpQuestion: localizeCopilotText(
        input.language,
        "Ban co muon toi doi chieu mix moi voi giao dich thang nay ngay bay gio khong?",
        "Do you want me to compare the new mix against this month's spending right now?",
      ),
      budgetPlan: buildPublicBudgetPlanSummary(refreshedPlan),
    };
  }

  if (isBudgetPlanSetupIntent(normalized)) {
    return buildBudgetPromptMissingAmountResponse({
      language: input.language,
      currency: input.currency,
    });
  }
  if (existingPlan && isBudgetPlanStatusIntent(normalized)) {
    const now = new Date();
    const refreshedPlan = recalculateBudgetPlanProgress(
      existingPlan,
      await sumCompletedDebitTransactionsForUser({
        userId: input.userId,
        startInclusive: new Date(existingPlan.startAt),
        endExclusive: new Date(existingPlan.endAt),
        context: "/ai/copilot-chat:budget-plan-status",
      }),
      now,
    );

    if (JSON.stringify(refreshedPlan) !== JSON.stringify(existingPlan)) {
      await userRepository.updateMetadata(
        input.userId,
        setStoredBudgetPlan(userDoc.metadata, refreshedPlan),
      );
      invalidateUserResponseCache(input.userId, ["auth"]);
    }

    return {
      reply: buildBudgetPlanReply({
        language: input.language,
        plan: refreshedPlan,
        isNewPlan: false,
      }),
      topic: "budget-plan-status",
      suggestedActions:
        input.language === "vi"
          ? [
              "Neu muon doi muc tran chi, chat lai muc tieu ngan sach moi.",
              "Hoi toi muc con lai theo ngay neu ban muon can sat trong nhung ngay toi.",
              "Email canh bao se tiep tuc duoc gui khi ban cham cac nguong da dat.",
            ]
          : [
              "If you want to change the cap, send a new budget target in chat.",
              "Ask for a remaining daily cap if you want tighter pacing for the coming days.",
              "Email alerts will keep running as spending crosses the saved thresholds.",
            ],
      suggestedDepositAmount: null,
      riskLevel:
        refreshedPlan.utilizationRatio >= refreshedPlan.criticalThreshold
          ? "high"
          : refreshedPlan.utilizationRatio >= refreshedPlan.warningThreshold
            ? "medium"
            : "low",
      confidence: 0.95,
      followUpQuestion: localizeCopilotText(
        input.language,
        "Ban co muon toi cap nhat lai ngan sach voi mot muc tran moi khong?",
        "Do you want me to update the budget with a new cap?",
      ),
      budgetPlan: buildPublicBudgetPlanSummary(refreshedPlan),
    };
  }

  return buildHeuristicCopilotResponse({
    currentBalance: input.currentBalance,
    currency: input.currency,
    monthlyIncome: input.monthlyIncome,
    monthlyExpenses: input.monthlyExpenses,
    recentTransactions: input.recentTransactions,
    latestMessage: latestUserMessage,
  });
};

const monitorBudgetPlanAfterDebit = async (input: {
  userId: string;
  amount: number;
  currency: string;
  description: string;
  occurredAt: string;
  actor?: string;
  ipAddress?: string;
}) => {
  const userRepository = createUserRepository();
  const userDoc = await userRepository.findValidatedById(input.userId);
  if (!userDoc) return;

  const storedPlan = getStoredBudgetPlan(userDoc.metadata);
  if (!storedPlan || storedPlan.emailAlertsEnabled === false) return;

  const occurredAt = new Date(input.occurredAt);
  const startAt = new Date(storedPlan.startAt);
  const endAt = new Date(storedPlan.endAt);
  if (
    Number.isNaN(occurredAt.getTime()) ||
    occurredAt < startAt ||
    occurredAt >= endAt
  ) {
    return;
  }

  const refreshedPlan = recalculateBudgetPlanProgress(
    storedPlan,
    await sumCompletedDebitTransactionsForUser({
      userId: input.userId,
      startInclusive: startAt,
      endExclusive: endAt,
      context: "/budget-alert:progress-refresh",
    }),
    occurredAt,
  );

  const monthlyTransactions = await fetchCopilotTransactionsForUser({
    userId: input.userId,
    startInclusive: startAt,
    endExclusive: endAt,
    limit: 2500,
    context: "/budget-alert:category-refresh",
  });
  const categoryUsage = summarizeBudgetPlanCategoryUsage({
    transactions: monthlyTransactions,
    plan: refreshedPlan,
    language: "en",
  });

  let milestone: "warning" | "critical" | null = null;
  if (
    refreshedPlan.utilizationRatio >= refreshedPlan.criticalThreshold &&
    !refreshedPlan.thresholdAlertsSent.includes("critical")
  ) {
    milestone = "critical";
  } else if (
    refreshedPlan.utilizationRatio >= refreshedPlan.warningThreshold &&
    !refreshedPlan.thresholdAlertsSent.includes("warning")
  ) {
    milestone = "warning";
  }

  const categoryAlerts: Array<{
    key: SpendingCategoryKey;
    label: string;
    thresholdLabel: "warning" | "critical";
    spentAmount: number;
    capAmount: number;
    utilizationRatio: number;
  }> = [];
  const nextPlanCategories = refreshedPlan.categories.map((category) => {
    const usage = categoryUsage.find((entry) => entry.key === category.key);
    if (!usage || usage.utilizationRatio === null) {
      return category;
    }
    const sent = Array.isArray(category.thresholdAlertsSent)
      ? category.thresholdAlertsSent
      : [];
    let categoryMilestone: "warning" | "critical" | null = null;
    if (usage.utilizationRatio >= refreshedPlan.criticalThreshold) {
      if (!sent.includes("critical")) {
        categoryMilestone = "critical";
      }
    } else if (usage.utilizationRatio >= refreshedPlan.warningThreshold) {
      if (!sent.includes("warning")) {
        categoryMilestone = "warning";
      }
    }
    if (!categoryMilestone) {
      return {
        ...category,
        thresholdAlertsSent: sent,
      };
    }

    categoryAlerts.push({
      key: usage.key,
      label: usage.label,
      thresholdLabel: categoryMilestone,
      spentAmount: usage.spentAmount,
      capAmount: usage.capAmount,
      utilizationRatio: usage.utilizationRatio,
    });
    return {
      ...category,
      thresholdAlertsSent: [...sent, categoryMilestone],
    };
  });

  const nextPlan = {
    ...refreshedPlan,
    categories: nextPlanCategories,
    thresholdAlertsSent:
      milestone === null
        ? refreshedPlan.thresholdAlertsSent
        : [...refreshedPlan.thresholdAlertsSent, milestone],
  };

  if (JSON.stringify(nextPlan) !== JSON.stringify(storedPlan)) {
    await userRepository.updateMetadata(
      input.userId,
      setStoredBudgetPlan(userDoc.metadata, nextPlan),
    );
    invalidateUserResponseCache(input.userId, ["auth"]);
  }

  if (!milestone && !categoryAlerts.length) return;

  if (milestone) {
    await logAuditEvent({
      actor: input.actor || userDoc.email,
      userId: input.userId,
      action:
        milestone === "critical"
          ? "BUDGET_PLAN_LIMIT_EXCEEDED"
          : "BUDGET_PLAN_WARNING_TRIGGERED",
      details: {
        amount: input.amount,
        currency: input.currency,
        description: input.description,
        spentAmount: nextPlan.spentAmount,
        targetAmount: nextPlan.targetAmount,
        utilizationRatio: nextPlan.utilizationRatio,
        remainingAmount: nextPlan.remainingAmount,
        milestone,
      },
      ipAddress: input.ipAddress,
    });
  }

  for (const categoryAlert of categoryAlerts) {
    await logAuditEvent({
      actor: input.actor || userDoc.email,
      userId: input.userId,
      action:
        categoryAlert.thresholdLabel === "critical"
          ? "BUDGET_CATEGORY_LIMIT_EXCEEDED"
          : "BUDGET_CATEGORY_WARNING_TRIGGERED",
      details: {
        amount: input.amount,
        currency: input.currency,
        description: input.description,
        category: categoryAlert.key,
        categoryLabel: categoryAlert.label,
        categorySpentAmount: categoryAlert.spentAmount,
        categoryCapAmount: categoryAlert.capAmount,
        utilizationRatio: categoryAlert.utilizationRatio,
        milestone: categoryAlert.thresholdLabel,
      },
      ipAddress: input.ipAddress,
    });

    await sendBudgetCategoryAlertEmail({
      to: userDoc.email,
      recipientName: getRecipientName(userDoc),
      currency: nextPlan.currency,
      categoryLabel: categoryAlert.label,
      transactionAmount: input.amount,
      categorySpentAmount: categoryAlert.spentAmount,
      categoryCapAmount: categoryAlert.capAmount,
      categoryUtilizationRatio: categoryAlert.utilizationRatio,
      thresholdLabel: categoryAlert.thresholdLabel,
      periodLabel: formatCopilotCalendarDate("en", startAt),
    });
  }

  if (milestone) {
    await sendBudgetThresholdAlertEmail({
      to: userDoc.email,
      recipientName: getRecipientName(userDoc),
      currency: nextPlan.currency,
      transactionAmount: input.amount,
      spentAmount: nextPlan.spentAmount,
      targetAmount: nextPlan.targetAmount,
      remainingAmount: nextPlan.remainingAmount,
      utilizationRatio: nextPlan.utilizationRatio,
      thresholdLabel: milestone,
      periodLabel: formatCopilotCalendarDate("en", startAt),
    });
  }
};

const buildTodayTransactionReportResponse = async (input: {
  userId: string;
  currency: string;
  language: CopilotLanguage;
}): Promise<CopilotResponsePayload> => {
  const wallets = await prisma.wallet.findMany({
    where: { userId: input.userId },
    select: { id: true },
  });
  const walletIds = wallets.map((wallet: { id: string }) => wallet.id);
  const now = new Date();
  const startOfDay = new Date(now);
  startOfDay.setHours(0, 0, 0, 0);
  const endOfDay = new Date(startOfDay);
  endOfDay.setDate(endOfDay.getDate() + 1);

  const txns = await prisma.transaction.findMany({
    where: {
      ...(walletIds.length
        ? { walletId: { in: walletIds } }
        : { walletId: "__NO_WALLET__" }),
      createdAt: {
        gte: startOfDay,
        lt: endOfDay,
      },
    },
    orderBy: { createdAt: "asc" },
    take: 500,
  });

  const transactions = txns
    .map((txn) =>
      safelyDecryptTransaction(txn, "/ai/copilot-chat:today-report"),
    )
    .filter((txn): txn is NonNullable<typeof txn> => Boolean(txn))
    .map((txn) => {
      const metadata =
        txn.metadata && typeof txn.metadata === "object"
          ? (txn.metadata as Record<string, unknown>)
          : null;
      const direction: "credit" | "debit" =
        txn.type === "DEPOSIT" || metadata?.entry === "CREDIT"
          ? "credit"
          : "debit";

      return {
        id: txn.id,
        amount: Math.max(0, Number(txn.amount || 0)),
        createdAt: txn.createdAt,
        direction,
        type: txn.type,
        description:
          txn.description?.trim() ||
          (txn.type === "DEPOSIT"
            ? "Wallet deposit"
            : txn.type === "WITHDRAW"
              ? "Wallet withdrawal"
              : "Wallet transfer"),
      };
    });

  return {
    reply: buildTransactionReportReply({
      language: input.language,
      currency: input.currency,
      transactions,
      periodLabel:
        input.language === "vi"
          ? `Báo cáo giao dịch hôm nay (${APP_TIMEZONE}, 00:00 đến hiện tại):`
          : `Today's transaction report (${APP_TIMEZONE}, 00:00 until now):`,
      detailMode: "time",
    }),
    topic: "today-transaction-report",
    suggestedActions:
      input.language === "vi"
        ? [
            "Hỏi thêm báo cáo giao dịch tuần này nếu bạn muốn xem xu hướng rộng hơn.",
            "Hỏi riêng tổng tiền vào hoặc tổng tiền ra nếu bạn muốn rút gọn báo cáo.",
            "Yêu cầu tôi đánh dấu giao dịch nào lớn nhất trong ngày.",
          ]
        : [
            "Ask for this week's transaction report if you want a wider trend.",
            "Ask for inflows only or outflows only if you want a shorter report.",
            "Ask me to highlight the largest transaction of the day.",
          ],
    suggestedDepositAmount: null,
    riskLevel:
      transactions
        .filter((transaction) => transaction.direction === "debit")
        .reduce((sum, transaction) => sum + transaction.amount, 0) >
      transactions
        .filter((transaction) => transaction.direction === "credit")
        .reduce((sum, transaction) => sum + transaction.amount, 0)
        ? "medium"
        : "low",
    confidence: 0.99,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Bạn có muốn tôi tách thêm theo giao dịch nạp tiền, nhận tiền và chuyển tiền không?",
      "Do you want me to break this down further by deposit, received transfer, and sent transfer?",
    ),
  };
};

const buildWeeklyTransactionReportResponse = async (input: {
  userId: string;
  currency: string;
  language: CopilotLanguage;
}): Promise<CopilotResponsePayload> => {
  const wallets = await prisma.wallet.findMany({
    where: { userId: input.userId },
    select: { id: true },
  });
  const walletIds = wallets.map((wallet: { id: string }) => wallet.id);
  const now = new Date();
  const startInclusive = getStartOfWeek(now);
  const endExclusive = getEndOfWeek(now);
  const displayEnd = new Date(endExclusive.getTime() - 1);

  const txns = await prisma.transaction.findMany({
    where: {
      ...(walletIds.length
        ? { walletId: { in: walletIds } }
        : { walletId: "__NO_WALLET__" }),
      createdAt: {
        gte: startInclusive,
        lt: endExclusive,
      },
    },
    orderBy: { createdAt: "asc" },
    take: 1000,
  });

  const transactions = txns
    .map((txn) =>
      safelyDecryptTransaction(txn, "/ai/copilot-chat:weekly-report"),
    )
    .filter((txn): txn is NonNullable<typeof txn> => Boolean(txn))
    .map((txn) => {
      const metadata =
        txn.metadata && typeof txn.metadata === "object"
          ? (txn.metadata as Record<string, unknown>)
          : null;
      const direction: "credit" | "debit" =
        txn.type === "DEPOSIT" || metadata?.entry === "CREDIT"
          ? "credit"
          : "debit";

      return {
        id: txn.id,
        amount: Math.max(0, Number(txn.amount || 0)),
        createdAt: txn.createdAt,
        direction,
        type: txn.type,
        description:
          txn.description?.trim() ||
          (txn.type === "DEPOSIT"
            ? "Wallet deposit"
            : txn.type === "WITHDRAW"
              ? "Wallet withdrawal"
              : "Wallet transfer"),
      };
    });

  return {
    reply: buildTransactionReportReply({
      language: input.language,
      currency: input.currency,
      transactions,
      periodLabel:
        input.language === "vi"
          ? `Báo cáo giao dịch tuần này (${formatCopilotCalendarDate(input.language, startInclusive)} - ${formatCopilotCalendarDate(input.language, displayEnd)}):`
          : `Transaction report for this calendar week (${formatCopilotCalendarDate(input.language, startInclusive)} - ${formatCopilotCalendarDate(input.language, displayEnd)}):`,
      detailMode: "datetime",
    }),
    topic: "weekly-transaction-report",
    suggestedActions:
      input.language === "vi"
        ? [
            "Hỏi thêm giao dịch có giá trị lớn nhất trong tuần này.",
            "Yêu cầu tách riêng dòng tiền vào hoặc dòng tiền ra nếu bạn muốn gọn hơn.",
            "Hỏi thêm so sánh tuần này với tuần trước nếu bạn muốn xem xu hướng.",
          ]
        : [
            "Ask for the largest transaction in this calendar week.",
            "Ask for inflows only or outflows only if you want a shorter report.",
            "Ask for a this-week-vs-last-week comparison if you want a trend view.",
          ],
    suggestedDepositAmount: null,
    riskLevel: "low",
    confidence: 0.99,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Bạn có muốn tôi tách thêm theo ngày hoặc theo loại giao dịch trong tuần này không?",
      "Do you want this split further by day or by transaction type within this week?",
    ),
  };
};

const buildMonthlyTransactionReportResponse = async (input: {
  userId: string;
  currency: string;
  language: CopilotLanguage;
}): Promise<CopilotResponsePayload> => {
  const endExclusive = new Date();
  const startInclusive = getStartOfMonth(endExclusive);

  const transactions = await fetchCopilotTransactionsForUser({
    userId: input.userId,
    startInclusive,
    endExclusive,
    limit: 2000,
    context: "/ai/copilot-chat:monthly-report",
  });

  return {
    reply: buildTransactionReportReply({
      language: input.language,
      currency: input.currency,
      transactions,
      periodLabel:
        input.language === "vi"
          ? `Sao kê giao dịch tháng này (${formatCopilotCalendarDate(input.language, startInclusive)} - ${formatCopilotCalendarDate(input.language, endExclusive)}):`
          : `Transaction statement for this month (${formatCopilotCalendarDate(input.language, startInclusive)} - ${formatCopilotCalendarDate(input.language, endExclusive)}):`,
      detailMode: "datetime",
    }),
    topic: "monthly-transaction-report",
    suggestedActions:
      input.language === "vi"
        ? [
            "Hỏi thêm mức chi tiêu lớn nhất tháng này nếu bạn muốn kiểm tra điểm nóng.",
            "Hỏi tôi so sánh tháng này với tháng trước nếu bạn muốn xem xu hướng.",
            "Hỏi tôi tách riêng nạp tiền, rút tiền và chuyển tiền nếu bạn muốn sao kê gọn hơn.",
          ]
        : [
            "Ask for the largest spend this month if you want to inspect the main drivers.",
            "Ask me to compare this month with last month if you want a trend view.",
            "Ask me to split deposits, withdrawals, and transfers if you want a tighter statement.",
          ],
    suggestedDepositAmount: null,
    riskLevel: "low",
    confidence: 0.99,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Bạn có muốn tôi so sánh tháng này với tháng trước và tóm tắt điểm khác biệt chính không?",
      "Do you want me to compare this month with last month and summarize the biggest differences?",
    ),
  };
};

const buildSpendingComparisonResponse = async (input: {
  userId: string;
  currency: string;
  language: CopilotLanguage;
}): Promise<CopilotResponsePayload> => {
  const now = new Date();
  const todayStart = getStartOfDay(now);
  const yesterdayStart = new Date(todayStart);
  yesterdayStart.setDate(yesterdayStart.getDate() - 1);
  const weekStart = getStartOfWeek(now);
  const prevWeekStart = new Date(weekStart);
  prevWeekStart.setDate(prevWeekStart.getDate() - 7);
  const monthStart = getStartOfMonth(now);
  const prevMonthStart = new Date(monthStart);
  prevMonthStart.setMonth(prevMonthStart.getMonth() - 1);

  const transactions = await fetchCopilotTransactionsForUser({
    userId: input.userId,
    startInclusive: prevMonthStart,
    endExclusive: now,
    limit: 3000,
    context: "/ai/copilot-chat:spending-comparison",
  });

  const compareWeekEnd = new Date(prevWeekStart);
  compareWeekEnd.setDate(
    compareWeekEnd.getDate() +
      (Math.floor((todayStart.getTime() - weekStart.getTime()) / 86400000) + 1),
  );
  const compareMonthEnd = new Date(prevMonthStart);
  compareMonthEnd.setDate(
    Math.min(
      compareMonthEnd.getDate() + now.getDate() - 1,
      new Date(
        prevMonthStart.getFullYear(),
        prevMonthStart.getMonth() + 1,
        0,
      ).getDate(),
    ),
  );
  compareMonthEnd.setHours(
    now.getHours(),
    now.getMinutes(),
    now.getSeconds(),
    now.getMilliseconds(),
  );

  const spendToday = sumDebitAmount(
    transactions.filter(
      (transaction) =>
        transaction.createdAt >= todayStart && transaction.createdAt < now,
    ),
  );
  const spendYesterday = sumDebitAmount(
    transactions.filter(
      (transaction) =>
        transaction.createdAt >= yesterdayStart &&
        transaction.createdAt < todayStart,
    ),
  );
  const spendThisWeek = sumDebitAmount(
    transactions.filter(
      (transaction) =>
        transaction.createdAt >= weekStart && transaction.createdAt < now,
    ),
  );
  const spendLastWeek = sumDebitAmount(
    transactions.filter(
      (transaction) =>
        transaction.createdAt >= prevWeekStart &&
        transaction.createdAt < compareWeekEnd,
    ),
  );
  const spendThisMonth = sumDebitAmount(
    transactions.filter(
      (transaction) =>
        transaction.createdAt >= monthStart && transaction.createdAt < now,
    ),
  );
  const spendLastMonth = sumDebitAmount(
    transactions.filter(
      (transaction) =>
        transaction.createdAt >= prevMonthStart &&
        transaction.createdAt < compareMonthEnd,
    ),
  );

  const comparisonTable = buildCopilotMarkdownTable(
    input.language === "vi"
      ? [
          "Kỳ hiện tại",
          "Chi tiêu",
          "Kỳ đối chiếu",
          "Chi tiêu",
          "Chênh lệch",
          "%",
        ]
      : ["Current period", "Spend", "Comparison period", "Spend", "Delta", "%"],
    [
      buildComparisonRow({
        currentLabel: input.language === "vi" ? "Hôm nay" : "Today",
        previousLabel: input.language === "vi" ? "Hôm qua" : "Yesterday",
        current: spendToday,
        previous: spendYesterday,
        currency: input.currency,
        language: input.language,
      }),
      buildComparisonRow({
        currentLabel: input.language === "vi" ? "Tuần này" : "This week",
        previousLabel:
          input.language === "vi"
            ? "Tuần trước cùng nhịp"
            : "Last week same pace",
        current: spendThisWeek,
        previous: spendLastWeek,
        currency: input.currency,
        language: input.language,
      }),
      buildComparisonRow({
        currentLabel: input.language === "vi" ? "Tháng này" : "This month",
        previousLabel:
          input.language === "vi"
            ? "Tháng trước cùng nhịp"
            : "Last month same pace",
        current: spendThisMonth,
        previous: spendLastMonth,
        currency: input.currency,
        language: input.language,
      }),
    ],
  );

  const userRepository = createUserRepository();
  const userDoc = await userRepository.findValidatedById(input.userId);
  const storedBudgetPlan = getStoredBudgetPlan(userDoc?.metadata);
  const refreshedBudgetPlan =
    storedBudgetPlan &&
    new Date(storedBudgetPlan.startAt) <= now &&
    new Date(storedBudgetPlan.endAt) > now
      ? recalculateBudgetPlanProgress(storedBudgetPlan, spendThisMonth, now)
      : storedBudgetPlan;
  if (
    userDoc &&
    refreshedBudgetPlan &&
    JSON.stringify(refreshedBudgetPlan) !== JSON.stringify(storedBudgetPlan)
  ) {
    await userRepository.updateMetadata(
      input.userId,
      setStoredBudgetPlan(userDoc.metadata, refreshedBudgetPlan),
    );
    invalidateUserResponseCache(input.userId, ["auth"]);
  }

  const monthlyCategorySummary = summarizeSpendingCategories({
    transactions: transactions.filter(
      (transaction) =>
        transaction.createdAt >= monthStart &&
        transaction.createdAt < now &&
        transaction.direction === "debit",
    ),
    language: input.language,
    targetAmount: refreshedBudgetPlan?.targetAmount ?? null,
    warningThreshold: refreshedBudgetPlan?.warningThreshold,
    categoryCapMap: buildBudgetCategoryCapMap(refreshedBudgetPlan || null),
  });
  const categoryTable = monthlyCategorySummary.length
    ? buildCopilotMarkdownTable(
        input.language === "vi"
          ? ["Danh mục", "Đã chi", "Tỷ trọng", "Hạn mức", "Trạng thái"]
          : ["Category", "Spent", "Share", "Cap", "Status"],
        monthlyCategorySummary
          .slice(0, 6)
          .map((category) => [
            category.label,
            formatCopilotMoney(input.currency, category.amount),
            `${Math.round(category.shareOfSpend * 100)}%`,
            category.capAmount !== null
              ? formatCopilotMoney(input.currency, category.capAmount)
              : input.language === "vi"
                ? "Chưa đặt"
                : "Not set",
            category.warningState === "over"
              ? input.language === "vi"
                ? "Vượt mức"
                : "Over limit"
              : category.warningState === "warning"
                ? input.language === "vi"
                  ? "Cảnh báo"
                  : "Warning"
                : input.language === "vi"
                  ? "Ổn định"
                  : "Stable",
          ]),
      )
    : null;
  const budgetVsActualTable = refreshedBudgetPlan
    ? buildCopilotMarkdownTable(
        input.language === "vi"
          ? ["Hạng mục", "Giá trị"]
          : ["Budget metric", "Value"],
        [
          [
            input.language === "vi"
              ? "Hạn mức tháng hiện tại"
              : "Current monthly cap",
            formatCopilotMoney(
              refreshedBudgetPlan.currency,
              refreshedBudgetPlan.targetAmount,
            ),
          ],
          [
            input.language === "vi"
              ? "Chi tiêu thực tế tháng này"
              : "Actual spend this month",
            formatCopilotMoney(
              refreshedBudgetPlan.currency,
              refreshedBudgetPlan.spentAmount,
            ),
          ],
          [
            input.language === "vi" ? "Còn lại" : "Remaining",
            refreshedBudgetPlan.remainingAmount >= 0
              ? formatCopilotMoney(
                  refreshedBudgetPlan.currency,
                  refreshedBudgetPlan.remainingAmount,
                )
              : `-${formatCopilotMoney(
                  refreshedBudgetPlan.currency,
                  Math.abs(refreshedBudgetPlan.remainingAmount),
                )}`,
          ],
          [
            input.language === "vi" ? "Mức sử dụng ngân sách" : "Budget usage",
            `${Math.round(refreshedBudgetPlan.utilizationRatio * 100)}%`,
          ],
        ],
      )
    : null;
  const categoryWarnings = monthlyCategorySummary
    .filter((category) => category.warningState !== "ok")
    .map((category) =>
      category.warningState === "over"
        ? localizeCopilotText(
            input.language,
            `${category.label} đã vượt mức tham chiếu của kế hoạch tháng này.`,
            `${category.label} is already above its reference cap for this month.`,
          )
        : localizeCopilotText(
            input.language,
            `${category.label} đang tiến sát ngưỡng cảnh báo, nên cần giảm nhịp chi ở nhóm này.`,
            `${category.label} is approaching its warning threshold, so this category should slow down next.`,
          ),
    );
  const adjustmentSuggestions = buildSpendingAdjustmentSuggestions({
    language: input.language,
    categories: monthlyCategorySummary,
    hasBudgetPlan: Boolean(refreshedBudgetPlan),
  });

  return {
    reply: [
      input.language === "vi"
        ? "Tôi đã đối chiếu toàn bộ giao dịch thu chi gần đây để tổng hợp 3 lớp: xu hướng theo ngày/tuần/tháng, mức độ bám sát ngân sách, và danh mục nào đang đẩy chi tiêu lên cao nhất."
        : "I reviewed your recent money flow in three layers: day/week/month spending trend, budget adherence, and which categories are pushing spend the most.",
      "",
      comparisonTable,
      ...(budgetVsActualTable
        ? [
            "",
            input.language === "vi"
              ? "So sánh với hạn mức đang đặt:"
              : "Comparison against your saved cap:",
            "",
            budgetVsActualTable,
          ]
        : []),
      ...(categoryTable
        ? [
            "",
            input.language === "vi"
              ? "Danh mục chi tiêu nổi bật tháng nay:"
              : "Leading spend categories this month:",
            "",
            categoryTable,
          ]
        : []),
      "",
      input.language === "vi" ? "Cảnh báo:" : "Warnings:",
      ...(categoryWarnings.length
        ? categoryWarnings
        : [
            localizeCopilotText(
              input.language,
              refreshedBudgetPlan
                ? "Chưa có danh mục nào vượt mức cảnh báo, nhưng bạn vẫn nên giữ sát trần chi còn lại của tháng."
                : "Chưa có hạn mức danh mục có sẵn, nhưng tôi đã xác định nhóm chi lớn nhất để bạn theo dõi sát hơn.",
              refreshedBudgetPlan
                ? "No category has crossed its warning threshold yet, but you should still watch the remaining monthly cap closely."
                : "No category cap is saved yet, but I identified the heaviest spend areas for closer tracking.",
            ),
          ]
      ).map((line) => `- ${line}`),
      "",
      input.language === "vi" ? "Gợi ý điều chỉnh:" : "Adjustment ideas:",
      ...adjustmentSuggestions.map((line) => `- ${line}`),
    ].join("\n"),
    topic: "spending-budget-insight",
    suggestedActions: adjustmentSuggestions,
    suggestedDepositAmount: null,
    riskLevel:
      (refreshedBudgetPlan &&
        refreshedBudgetPlan.utilizationRatio >=
          refreshedBudgetPlan.criticalThreshold) ||
      monthlyCategorySummary.some(
        (category) => category.warningState === "over",
      )
        ? "high"
        : spendToday > spendYesterday ||
            spendThisWeek > spendLastWeek ||
            monthlyCategorySummary.some(
              (category) => category.warningState === "warning",
            )
          ? "medium"
          : "low",
    confidence: 0.98,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Bạn muốn tôi đào sâu vào ngày nào, giao dịch nào, hay danh mục nào đang vượt nhiều nhất?",
      "Do you want me to drill into the specific day, transaction, or category that is overshooting the most?",
    ),
    budgetPlan: buildPublicBudgetPlanSummary(refreshedBudgetPlan || null),
  };
};

const buildRecentTransactionReviewResponse = async (input: {
  userId: string;
  currency: string;
  language: CopilotLanguage;
}): Promise<CopilotResponsePayload> => {
  const endExclusive = new Date();
  const startInclusive = new Date(endExclusive);
  startInclusive.setDate(startInclusive.getDate() - 30);

  const transactions = await fetchCopilotTransactionsForUser({
    userId: input.userId,
    startInclusive,
    endExclusive,
    limit: 120,
    context: "/ai/copilot-chat:recent-transaction-review",
  });
  const categorySummary = summarizeSpendingCategories({
    transactions,
    language: input.language,
    categoryCapMap: buildBudgetCategoryCapMap(
      getStoredBudgetPlan(
        (await createUserRepository().findValidatedById(input.userId))
          ?.metadata,
      ),
    ),
  });
  const categoryTable = categorySummary.length
    ? buildCopilotMarkdownTable(
        input.language === "vi"
          ? ["Danh muc", "Da chi", "So lan", "Ty trong"]
          : ["Category", "Spent", "Count", "Share"],
        categorySummary
          .slice(0, 5)
          .map((category) => [
            category.label,
            formatCopilotMoney(input.currency, category.amount),
            category.count,
            `${Math.round(category.shareOfSpend * 100)}%`,
          ]),
      )
    : null;

  return {
    reply: [
      buildTransactionReportReply({
        language: input.language,
        currency: input.currency,
        transactions: transactions.slice(0, 20),
        periodLabel:
          input.language === "vi"
            ? `Tổng hợp giao dịch gần đây trong 30 ngày (${formatCopilotCalendarDate(input.language, startInclusive)} - ${formatCopilotCalendarDate(input.language, endExclusive)}):`
            : `Recent transaction review for the last 30 days (${formatCopilotCalendarDate(input.language, startInclusive)} - ${formatCopilotCalendarDate(input.language, endExclusive)}):`,
        detailMode: "datetime",
      }),
      ...(categoryTable
        ? [
            "",
            input.language === "vi"
              ? "Tóm tắt danh mục chi ra:"
              : "Outflow category summary:",
            "",
            categoryTable,
          ]
        : []),
    ].join("\n"),
    topic: "recent-transaction-review",
    suggestedActions:
      input.language === "vi"
        ? [
            "Hỏi riêng sao kê hôm nay, tuần này hoặc tháng này nếu bạn muốn khung thời gian cụ thể hơn.",
            "Hỏi tôi giao dịch nào có giá trị lớn nhất nếu bạn muốn xem điểm nóng nhanh.",
            "Hỏi tôi danh mục nào đang tiêu nhiều nhất nếu bạn muốn xem tâm điểm chi phí.",
          ]
        : [
            "Ask for today's, this week's, or this month's statement if you want a tighter period.",
            "Ask which transaction was the largest if you want the main driver quickly.",
            "Ask which category is consuming the most if you want the cost hotspot.",
          ],
    suggestedDepositAmount: null,
    riskLevel: "low",
    confidence: 0.98,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Bạn có muốn tôi tách thêm theo tiền vào, tiền ra và danh mục chi tiêu không?",
      "Do you want this split further into inflows, outflows, and spend categories?",
    ),
  };
};

const buildTransactionAnomalyReviewResponse = async (input: {
  userId: string;
  currency: string;
  language: CopilotLanguage;
}): Promise<CopilotResponsePayload> => {
  const endExclusive = new Date();
  const startInclusive = new Date(endExclusive);
  startInclusive.setDate(startInclusive.getDate() - 14);

  const transactions = await fetchCopilotTransactionsForUser({
    userId: input.userId,
    startInclusive,
    endExclusive,
    limit: 120,
    context: "/ai/copilot-chat:anomaly-review",
  });

  const inflows = transactions.filter(
    (transaction) => transaction.direction === "credit",
  );
  const outflows = transactions.filter(
    (transaction) => transaction.direction === "debit",
  );
  const totalInflow = roundMoney(
    inflows.reduce((sum, transaction) => sum + transaction.amount, 0),
  );
  const totalOutflow = roundMoney(
    outflows.reduce((sum, transaction) => sum + transaction.amount, 0),
  );
  const largestOutflow = outflows.reduce(
    (max, transaction) => Math.max(max, transaction.amount),
    0,
  );
  const outflowCoverage =
    totalInflow > 0 ? roundMoney((totalOutflow / totalInflow) * 100) : null;

  const facts = [
    input.language === "vi"
      ? `Đã rà soát ${transactions.length} giao dịch trong 14 ngày gần đây từ dữ liệu ví.`
      : `Reviewed ${transactions.length} wallet transactions from the last 14 days.`,
    input.language === "vi"
      ? `Tổng tiền vào: ${formatCopilotMoney(input.currency, totalInflow)}. Tổng tiền ra: ${formatCopilotMoney(input.currency, totalOutflow)}.`
      : `Total inflow: ${formatCopilotMoney(input.currency, totalInflow)}. Total outflow: ${formatCopilotMoney(input.currency, totalOutflow)}.`,
    input.language === "vi"
      ? `Giao dịch ra lớn nhất: ${formatCopilotMoney(input.currency, largestOutflow)}.`
      : `Largest outflow: ${formatCopilotMoney(input.currency, largestOutflow)}.`,
    localizeCopilotText(
      input.language,
      "Trong route chat này, điểm bất thường realtime có thể không sẵn sàng; phần này chỉ dựa trên bản ghi giao dịch và tóm tắt ví.",
      "A real-time anomaly score may be unavailable in this chat route; this review is based on wallet records and transaction summaries only.",
    ),
  ];

  const calculations = [
    outflowCoverage !== null
      ? localizeCopilotText(
          input.language,
          `Tỷ lệ tiền ra / tiền vào 14 ngày: ${outflowCoverage.toFixed(2)}%.`,
          `14-day outflow-to-inflow ratio: ${outflowCoverage.toFixed(2)}%.`,
        )
      : localizeCopilotText(
          input.language,
          "Không có dòng tiền vào để tính tỷ lệ bao phủ tiền ra.",
          "There is no inflow data available to calculate an outflow coverage ratio.",
        ),
    localizeCopilotText(
      input.language,
      `Số giao dịch ra: ${outflows.length}. Số giao dịch vào: ${inflows.length}.`,
      `Outflow count: ${outflows.length}. Inflow count: ${inflows.length}.`,
    ),
  ];

  const suggestions =
    input.language === "vi"
      ? [
          "Nếu bạn nghi ngờ một giao dịch cụ thể, hãy đưa thời gian hoặc số tiền để tôi khoanh vùng sát hơn.",
          "Nếu có dấu hiệu bị thúc giục chuyển tiền, không chia sẻ OTP hoặc mã xác minh.",
          "Nếu muốn kiểm tra tổng quát, vào Alerts/Admin để xem risk signals thay vì chat route.",
        ]
      : [
          "If you are concerned about one specific transfer, give me the time or amount and I can narrow the review.",
          "If someone is pressuring you to move funds, do not share OTPs or verification codes.",
          "For full security signals, check the Alerts/Admin review path rather than this chat route.",
        ];

  return {
    reply: [
      input.language === "vi" ? "Facts:" : "Facts:",
      ...facts.map((fact) => `- ${fact}`),
      "",
      input.language === "vi" ? "Tính toán:" : "Calculations:",
      ...calculations.map((calculation) => `- ${calculation}`),
      "",
      input.language === "vi" ? "Gợi ý:" : "Suggestions:",
      ...suggestions.map((suggestion) => `- ${suggestion}`),
    ].join("\n"),
    topic: "transaction-anomaly-review",
    suggestedActions: suggestions,
    suggestedDepositAmount: null,
    riskLevel:
      largestOutflow >= 5000 ||
      (outflowCoverage !== null && outflowCoverage > 90)
        ? "medium"
        : "low",
    confidence: transactions.length ? 0.83 : 0.68,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Bạn có muốn tôi rà soát một giao dịch cụ thể theo số tiền, thời gian hoặc người nhận không?",
      "Do you want me to review one specific transfer by amount, time, or recipient?",
    ),
  };
};

const buildMarketDataUnavailableCopilotResponse = (input: {
  language: CopilotLanguage;
}): CopilotResponsePayload => ({
  reply: localizeCopilotText(
    input.language,
    "Du lieu thi truong realtime hien khong kha dung trong ngu canh nay, nen toi khong the xac nhan gia song mot cach chinh xac.",
    "Real-time market data is unavailable in this context, so I cannot confirm a live price accurately.",
  ),
  topic: "market-data-unavailable",
  suggestedActions:
    input.language === "vi"
      ? [
          "Hoi toi ve cach doc dinh gia, rui ro, va luan diem dau tu cua ma ban dang quan tam.",
          "Neu ban bat du lieu quote song, toi co the xu ly lai cau hoi theo gia realtime.",
        ]
      : [
          "Ask me about valuation, downside risk, and the investment thesis of the symbol you care about.",
          "If you enable a live quote source, I can revisit the question with real-time prices.",
        ],
  suggestedDepositAmount: null,
  riskLevel: "low",
  confidence: 0.95,
  followUpQuestion: localizeCopilotText(
    input.language,
    "Ban muon phan tich giao duc ve co phieu, ETF, hay dinh gia thay vi gia realtime khong?",
    "Do you want an educational analysis of the stock, ETF, or valuation instead of a live price?",
  ),
});

const buildUnsupportedCopilotResponse = (input: {
  language: CopilotLanguage;
}): CopilotResponsePayload => ({
  reply: localizeCopilotText(
    input.language,
    "Toi co the ho tro giao duc tai chinh, chi tieu ca nhan, sao ke giao dich, kiem tra bat thuong, va phan tich thi truong o muc giao duc. Yeu cau vua roi nam ngoai cac nhom ho tro do.",
    "I can help with finance education, spending insights, transaction reviews, anomaly checks, and educational market analysis. The last request falls outside those supported areas.",
  ),
  topic: "unsupported-copilot-request",
  suggestedActions:
    input.language === "vi"
      ? [
          "Hoi ve chi tieu, ngan sach, sao ke giao dich, hoac kiem tra rui ro giao dich.",
          "Hoi ve co phieu hoac ETF theo huong giao duc va phan tich, khong phai khuyen nghi mua ban.",
        ]
      : [
          "Ask about spending, budgeting, transaction statements, or transfer-risk checks.",
          "Ask about stocks or ETFs in an educational, analytical way rather than as a buy or sell instruction.",
        ],
  suggestedDepositAmount: null,
  riskLevel: "low",
  confidence: 0.9,
  followUpQuestion: localizeCopilotText(
    input.language,
    "Ban muon toi giup ve ngan sach, giao dich, hay kien thuc thi truong?",
    "Do you want help with budgeting, transactions, or market education?",
  ),
});

const sanitizeUser = (user: UserEntity | null) => {
  if (!user) return null;
  const { passwordHash, metadata, ...rest } = user;
  void passwordHash;
  return {
    ...rest,
    metadata: buildPublicUserMetadata(metadata),
  };
};

const safelyDecryptTransaction = (
  transaction: Parameters<typeof decryptStoredTransaction>[0],
  context: string,
) => {
  try {
    return decryptStoredTransaction(transaction);
  } catch (err) {
    console.warn(`Skipping undecryptable transaction in ${context}`, {
      transactionId: transaction.id,
      error: err instanceof Error ? err.message : String(err),
    });
    return null;
  }
};

const buildAuthPayload = (
  userDoc: UserEntity,
  sessionId: string,
  extra?: {
    notice?: string;
    status?: "authenticated";
    security?: SessionSecurityState;
  },
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
    security: extra?.security ?? buildSessionSecurityState("low"),
  };
};

const encodeSignedPayload = (payload: unknown, secret: string) => {
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
    "base64url",
  );
  const signature = crypto
    .createHmac("sha256", secret)
    .update(encodedPayload)
    .digest("base64url");
  return `${encodedPayload}.${signature}`;
};

const decodeSignedPayload = <T>(token: string, secret: string) => {
  const [encodedPayload, signature] = token.split(".");
  if (!encodedPayload || !signature) {
    throw new Error("INVALID_SIGNED_PAYLOAD");
  }

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(encodedPayload)
    .digest("base64url");

  if (
    signature.length !== expectedSignature.length ||
    !crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature),
    )
  ) {
    throw new Error("INVALID_SIGNED_PAYLOAD");
  }

  return JSON.parse(
    Buffer.from(encodedPayload, "base64url").toString("utf8"),
  ) as T;
};

const encodeSliderCaptchaToken = (payload: SliderCaptchaPayload) =>
  encodeSignedPayload(payload, CAPTCHA_SECRET_KEY);

const decodeSliderCaptchaToken = (captchaToken: string) => {
  let parsed: Partial<SliderCaptchaPayload>;
  try {
    parsed = decodeSignedPayload<Partial<SliderCaptchaPayload>>(
      captchaToken,
      CAPTCHA_SECRET_KEY,
    );
  } catch {
    throw new Error("INVALID_CAPTCHA");
  }
  if (
    parsed.kind !== "slider_v1" ||
    typeof parsed.nonce !== "string" ||
    typeof parsed.issuedAt !== "number" ||
    typeof parsed.expiresAt !== "number" ||
    typeof parsed.targetOffsetPx !== "number" ||
    typeof parsed.maxOffsetPx !== "number" ||
    typeof parsed.tolerancePx !== "number"
  ) {
    throw new Error("INVALID_CAPTCHA");
  }

  if (parsed.expiresAt <= Date.now()) {
    throw new Error("CAPTCHA_EXPIRED");
  }

  return parsed as SliderCaptchaPayload;
};

const FACE_ID_STEP_LABELS: Record<FaceIdStep, string> = {
  center: "Center your face",
  move_left: "Move your face to the left",
  move_right: "Move your face to the right",
  move_closer: "Move closer to the camera",
};

const buildFaceIdChallenge = () => {
  const steps: FaceIdStep[] = ["center"];
  const issuedAt = Date.now();
  const payload: FaceIdChallengePayload = {
    kind: "faceid_v1",
    nonce: crypto.randomUUID(),
    issuedAt,
    expiresAt: issuedAt + FACE_ID_CHALLENGE_TTL_MS,
    steps,
    minLivenessScore: FACE_ID_MIN_LIVENESS_SCORE,
    minMotionScore: FACE_ID_MIN_MOTION_SCORE,
    minEyeMotionScore: FACE_ID_MIN_EYE_MOTION_SCORE,
    minFaceCoverage: FACE_ID_MIN_FACE_COVERAGE,
    minSampleCount: Math.min(FACE_ID_MIN_SAMPLE_COUNT, 4),
  };

  return {
    challengeToken: encodeSignedPayload(payload, FACE_ID_SECRET_KEY),
    steps: steps.map((step) => ({
      id: step,
      label: FACE_ID_STEP_LABELS[step],
    })),
    expiresAt: new Date(payload.expiresAt).toISOString(),
  };
};

const decodeFaceIdChallengeToken = (challengeToken: string) => {
  let payload: Partial<FaceIdChallengePayload>;
  try {
    payload = decodeSignedPayload<Partial<FaceIdChallengePayload>>(
      challengeToken,
      FACE_ID_SECRET_KEY,
    );
  } catch {
    throw new Error("INVALID_FACE_ID");
  }

  if (
    payload.kind !== "faceid_v1" ||
    typeof payload.nonce !== "string" ||
    typeof payload.issuedAt !== "number" ||
    typeof payload.expiresAt !== "number" ||
    !Array.isArray(payload.steps) ||
    payload.steps.some(
      (step) =>
        step !== "center" &&
        step !== "move_left" &&
        step !== "move_right" &&
        step !== "move_closer",
    )
  ) {
    throw new Error("INVALID_FACE_ID");
  }

  if (payload.expiresAt <= Date.now()) {
    throw new Error("FACE_ID_EXPIRED");
  }

  return payload as FaceIdChallengePayload;
};

type ParsedFaceDescriptor = {
  version: "legacy" | "v2";
  legacy?: Buffer;
  aligned?: Buffer;
  geometry?: Buffer;
};

const decodeFaceDescriptorBytes = (value: string, maxLength = 4096) => {
  try {
    const raw = Buffer.from(value, "base64");
    if (!raw.length || raw.length > maxLength) {
      throw new Error("INVALID_FACE_ID_DESCRIPTOR");
    }
    return raw;
  } catch {
    throw new Error("INVALID_FACE_ID_DESCRIPTOR");
  }
};

const parseFaceDescriptor = (descriptor: string): ParsedFaceDescriptor => {
  if (!descriptor.startsWith(FACE_ID_DESCRIPTOR_V2_PREFIX)) {
    return {
      version: "legacy",
      legacy: decodeFaceDescriptorBytes(descriptor, 2048),
    };
  }

  try {
    const payload = JSON.parse(
      Buffer.from(
        descriptor.slice(FACE_ID_DESCRIPTOR_V2_PREFIX.length),
        "base64",
      ).toString("utf8"),
    ) as Record<string, unknown>;
    const legacy =
      typeof payload.legacy === "string"
        ? decodeFaceDescriptorBytes(payload.legacy, 2048)
        : undefined;
    const aligned =
      typeof payload.aligned === "string"
        ? decodeFaceDescriptorBytes(payload.aligned, 4096)
        : undefined;
    const geometry =
      typeof payload.geometry === "string"
        ? decodeFaceDescriptorBytes(payload.geometry, 512)
        : undefined;

    if (!legacy && !aligned && !geometry) {
      throw new Error("INVALID_FACE_ID_DESCRIPTOR");
    }

    return {
      version: "v2",
      legacy,
      aligned,
      geometry,
    };
  } catch {
    throw new Error("INVALID_FACE_ID_DESCRIPTOR");
  }
};

const compareDescriptorBuffers = (
  a: Buffer,
  b: Buffer,
  mode: "mean" | "midpoint" = "mean",
) => {
  if (a.length !== b.length) return 0;

  const centerA =
    mode === "midpoint"
      ? 127.5
      : a.reduce((sum, value) => sum + value, 0) / Math.max(1, a.length);
  const centerB =
    mode === "midpoint"
      ? 127.5
      : b.reduce((sum, value) => sum + value, 0) / Math.max(1, b.length);

  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (let index = 0; index < a.length; index += 1) {
    const av = (a[index] - centerA) / 127.5;
    const bv = (b[index] - centerB) / 127.5;
    dot += av * bv;
    magA += av * av;
    magB += bv * bv;
  }

  if (!magA || !magB) return 0;
  return dot / Math.sqrt(magA * magB);
};

const compareFaceDescriptors = (left: string, right: string) => {
  const a = parseFaceDescriptor(left);
  const b = parseFaceDescriptor(right);
  const alignedScore =
    a.aligned && b.aligned
      ? compareDescriptorBuffers(a.aligned, b.aligned, "midpoint")
      : undefined;
  const geometryScore =
    a.geometry && b.geometry
      ? compareDescriptorBuffers(a.geometry, b.geometry, "midpoint")
      : undefined;
  const legacyScore =
    a.legacy && b.legacy
      ? compareDescriptorBuffers(a.legacy, b.legacy, "mean")
      : undefined;

  const isV2Pair = a.version === "v2" && b.version === "v2";

  const scores: Array<{ score: number; weight: number }> = [];
  if (isV2Pair && typeof geometryScore === "number") {
    scores.push({
      score: geometryScore,
      weight: 0.4,
    });
  }
  if (isV2Pair && typeof alignedScore === "number") {
    scores.push({
      score: alignedScore,
      weight: 0.45,
    });
  }
  if (isV2Pair && typeof legacyScore === "number") {
    scores.push({
      score: legacyScore,
      weight: 0.15,
    });
  }
  if (typeof geometryScore === "number") {
    scores.push({
      score: geometryScore,
      weight: isV2Pair ? 0 : 0.35,
    });
  }
  if (typeof alignedScore === "number") {
    scores.push({
      score: alignedScore,
      weight: isV2Pair ? 0 : 0.65,
    });
  }
  if (typeof legacyScore === "number") {
    scores.push({
      score: legacyScore,
      weight: isV2Pair ? 0 : scores.length ? 0.35 : 1,
    });
  }

  const weightedScores = scores.filter((entry) => entry.weight > 0);

  if (!weightedScores.length) {
    return {
      similarity: 0,
      alignedScore,
      geometryScore,
      legacyScore,
      threshold: isV2Pair
        ? FACE_ID_V2_MATCH_THRESHOLD
        : FACE_ID_LEGACY_MATCH_THRESHOLD,
    };
  }

  const totalWeight = weightedScores.reduce(
    (sum, entry) => sum + entry.weight,
    0,
  );
  const similarity =
    weightedScores.reduce((sum, entry) => sum + entry.score * entry.weight, 0) /
    Math.max(totalWeight, 1);

  return {
    similarity,
    alignedScore,
    geometryScore,
    legacyScore,
    threshold: isV2Pair
      ? FACE_ID_V2_MATCH_THRESHOLD
      : FACE_ID_LEGACY_MATCH_THRESHOLD,
  };
};

const assessFaceIdAntiSpoof = async (
  submission: FaceIdEnrollmentSubmission,
): Promise<FaceIdAntiSpoofResult> => {
  const response = await fetch(`${AI_URL}/ai/face/liveness`, {
    method: "POST",
    headers: buildAiServiceHeaders(),
    body: JSON.stringify({
      previewImage: submission.previewImage,
      stepCaptures: submission.stepCaptures,
      livenessScore: submission.livenessScore,
      motionScore: submission.motionScore,
      eyeMotionScore: submission.eyeMotionScore,
      faceCoverage: submission.faceCoverage,
      sampleCount: submission.sampleCount,
      completedSteps: submission.completedSteps,
    }),
  }).catch(() => null);

  if (!response) {
    throw new Error("FACE_ID_ANTI_SPOOF_UNAVAILABLE");
  }

  const payload = (await response.json().catch(() => null)) as Record<
    string,
    unknown
  > | null;

  if (!response.ok || !payload) {
    throw new Error("FACE_ID_ANTI_SPOOF_UNAVAILABLE");
  }

  const passed = payload.passed === true;
  const spoofScore =
    typeof payload.spoofScore === "number"
      ? clamp(payload.spoofScore, 0, 1)
      : 1;
  const confidence =
    typeof payload.confidence === "number"
      ? clamp(payload.confidence, 0, 1)
      : 0;
  const riskLevel =
    payload.riskLevel === "low" ||
    payload.riskLevel === "medium" ||
    payload.riskLevel === "high"
      ? payload.riskLevel
      : "high";
  const reasons = Array.isArray(payload.reasons)
    ? payload.reasons.filter(
        (reason): reason is string =>
          typeof reason === "string" && reason.trim().length > 0,
      )
    : [];

  return {
    passed,
    spoofScore,
    confidence,
    riskLevel,
    reasons,
    modelSource:
      typeof payload.modelSource === "string" ? payload.modelSource : null,
    modelVersion:
      typeof payload.modelVersion === "string" ? payload.modelVersion : null,
  };
};

const readFaceIdEnrollment = (
  body: unknown,
): FaceIdEnrollmentSubmission | null => {
  const payload =
    body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const source =
    payload.faceIdEnrollment && typeof payload.faceIdEnrollment === "object"
      ? (payload.faceIdEnrollment as Record<string, unknown>)
      : payload;

  const challengeToken =
    typeof source.challengeToken === "string"
      ? source.challengeToken.trim()
      : "";
  if (!challengeToken) return null;

  const stepCaptures = Array.isArray(source.stepCaptures)
    ? source.stepCaptures.flatMap((capture) => {
        const record =
          capture && typeof capture === "object"
            ? (capture as Record<string, unknown>)
            : null;
        if (!record) return [];
        const step = record.step;
        const image = record.image;
        const centerX =
          typeof record.centerX === "number"
            ? record.centerX
            : Number(record.centerX);
        const centerY =
          typeof record.centerY === "number"
            ? record.centerY
            : Number(record.centerY);
        const coverage =
          typeof record.coverage === "number"
            ? record.coverage
            : Number(record.coverage);
        const motion =
          typeof record.motion === "number"
            ? record.motion
            : Number(record.motion);
        const aligned =
          typeof record.aligned === "boolean" ? record.aligned : undefined;

        if (
          (step !== "center" &&
            step !== "move_left" &&
            step !== "move_right" &&
            step !== "move_closer") ||
          typeof image !== "string"
        ) {
          return [];
        }

        return [
          {
            step,
            image,
            centerX,
            centerY,
            coverage,
            motion,
            aligned,
          },
        ];
      })
    : [];
  const previewImage =
    typeof source.previewImage === "string" &&
    source.previewImage.startsWith("data:image/")
      ? source.previewImage
      : stepCaptures.find((capture) => capture.image.startsWith("data:image/"))
          ?.image;

  return {
    challengeToken,
    descriptor:
      typeof source.descriptor === "string" ? source.descriptor.trim() : "",
    livenessScore:
      typeof source.livenessScore === "number"
        ? source.livenessScore
        : Number(source.livenessScore),
    motionScore:
      typeof source.motionScore === "number"
        ? source.motionScore
        : Number(source.motionScore),
    eyeMotionScore:
      typeof source.eyeMotionScore === "number"
        ? source.eyeMotionScore
        : Number(source.eyeMotionScore),
    faceCoverage:
      typeof source.faceCoverage === "number"
        ? source.faceCoverage
        : Number(source.faceCoverage),
    sampleCount:
      typeof source.sampleCount === "number"
        ? Math.round(source.sampleCount)
        : Number(source.sampleCount),
    completedSteps: Array.isArray(source.completedSteps)
      ? source.completedSteps.filter(
          (step): step is FaceIdStep =>
            step === "center" ||
            step === "move_left" ||
            step === "move_right" ||
            step === "move_closer",
        )
      : [],
    stepCaptures,
    previewImage,
    videoEvidence:
      typeof source.videoEvidence === "string"
        ? source.videoEvidence.trim()
        : undefined,
    videoDurationMs:
      typeof source.videoDurationMs === "number"
        ? source.videoDurationMs
        : Number(source.videoDurationMs),
    videoMimeType:
      typeof source.videoMimeType === "string"
        ? source.videoMimeType.trim()
        : undefined,
  };
};

const estimateBase64Bytes = (value: string) => {
  const trimmed = value.replace(/\s+/g, "");
  const padding = trimmed.endsWith("==") ? 2 : trimmed.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((trimmed.length * 3) / 4) - padding);
};

const verifyFaceIdVideoEvidence = (submission: FaceIdEnrollmentSubmission) => {
  if (!submission.videoEvidence) {
    throw new Error("FACE_ID_VIDEO_REQUIRED");
  }
  const prefixMatch =
    /^data:(video\/[-+.\w]+(?:;[-+.\w]+=[-+.\w]+)*);base64,(.+)$/i.exec(
      submission.videoEvidence,
    );
  if (!prefixMatch) {
    throw new Error("FACE_ID_VIDEO_INVALID");
  }
  const videoDurationMs = Number(submission.videoDurationMs);
  if (!Number.isFinite(videoDurationMs)) {
    throw new Error("FACE_ID_VIDEO_INVALID");
  }
  if (videoDurationMs < FACE_ID_MIN_VIDEO_DURATION_MS - 250) {
    throw new Error("FACE_ID_VIDEO_TOO_SHORT");
  }
  if (
    submission.videoEvidence.length > FACE_ID_MAX_VIDEO_DATA_URL_LENGTH ||
    estimateBase64Bytes(prefixMatch[2]) > FACE_ID_MAX_VIDEO_DATA_URL_LENGTH
  ) {
    throw new Error("FACE_ID_VIDEO_INVALID");
  }

  return {
    mimeType:
      submission.videoMimeType && submission.videoMimeType.length > 0
        ? submission.videoMimeType
        : prefixMatch[1],
    durationMs: Math.round(videoDurationMs),
  };
};

const verifyFaceIdSubmission = (
  submission: FaceIdEnrollmentSubmission,
  storedDescriptor?: string,
) => {
  const challenge = decodeFaceIdChallengeToken(submission.challengeToken);
  const minLivenessScore = Number.isFinite(challenge.minLivenessScore)
    ? challenge.minLivenessScore
    : FACE_ID_MIN_LIVENESS_SCORE;
  const minMotionScore = Number.isFinite(challenge.minMotionScore)
    ? challenge.minMotionScore
    : FACE_ID_MIN_MOTION_SCORE;
  const minEyeMotionScore = Number.isFinite(challenge.minEyeMotionScore)
    ? challenge.minEyeMotionScore
    : FACE_ID_MIN_EYE_MOTION_SCORE;
  if (submission.livenessScore < minLivenessScore) {
    throw new Error("FACE_ID_LIVENESS_TOO_LOW");
  }
  if (submission.motionScore < minMotionScore) {
    throw new Error("FACE_ID_MOTION_TOO_LOW");
  }
  if (submission.eyeMotionScore < minEyeMotionScore) {
    throw new Error("FACE_ID_EYE_MOTION_TOO_LOW");
  }
  if (submission.faceCoverage < challenge.minFaceCoverage) {
    throw new Error("FACE_ID_FACE_TOO_SMALL");
  }
  if (submission.sampleCount < challenge.minSampleCount) {
    throw new Error("FACE_ID_TOO_FEW_SAMPLES");
  }
  verifyFaceIdVideoEvidence(submission);

  parseFaceDescriptor(submission.descriptor);

  const similarityResult = storedDescriptor
    ? compareFaceDescriptors(storedDescriptor, submission.descriptor)
    : {
        similarity: 1,
        alignedScore: undefined,
        geometryScore: undefined,
        legacyScore: undefined,
        threshold: FACE_ID_V2_MATCH_THRESHOLD,
      };

  const geometryRescueMatch =
    Boolean(storedDescriptor) &&
    typeof similarityResult.geometryScore === "number" &&
    similarityResult.geometryScore >= FACE_ID_V2_RESCUE_GEOMETRY_THRESHOLD &&
    ((typeof similarityResult.legacyScore === "number" &&
      similarityResult.legacyScore >= FACE_ID_V2_RESCUE_LEGACY_THRESHOLD) ||
      (typeof similarityResult.alignedScore === "number" &&
        similarityResult.alignedScore >= FACE_ID_V2_RESCUE_ALIGNED_FLOOR));

  if (geometryRescueMatch) {
    console.warn("FaceID geometry rescue accepted", {
      similarity: similarityResult.similarity,
      alignedScore: similarityResult.alignedScore,
      geometryScore: similarityResult.geometryScore,
      legacyScore: similarityResult.legacyScore,
    });
  }

  if (
    storedDescriptor &&
    !geometryRescueMatch &&
    typeof similarityResult.alignedScore === "number" &&
    similarityResult.alignedScore < FACE_ID_V2_ALIGNED_MATCH_THRESHOLD &&
    similarityResult.similarity < similarityResult.threshold - 0.02
  ) {
    console.warn("FaceID mismatch: aligned score below threshold", {
      similarity: similarityResult.similarity,
      alignedScore: similarityResult.alignedScore,
      geometryScore: similarityResult.geometryScore,
      legacyScore: similarityResult.legacyScore,
    });
    throw new Error("FACE_ID_MISMATCH");
  }
  if (
    storedDescriptor &&
    !geometryRescueMatch &&
    typeof similarityResult.alignedScore !== "number" &&
    typeof similarityResult.geometryScore === "number" &&
    similarityResult.geometryScore < FACE_ID_V2_GEOMETRY_MATCH_THRESHOLD &&
    similarityResult.similarity < similarityResult.threshold - 0.02
  ) {
    console.warn("FaceID mismatch: geometry fallback score below threshold", {
      similarity: similarityResult.similarity,
      alignedScore: similarityResult.alignedScore,
      geometryScore: similarityResult.geometryScore,
      legacyScore: similarityResult.legacyScore,
    });
    throw new Error("FACE_ID_MISMATCH");
  }
  if (
    storedDescriptor &&
    !geometryRescueMatch &&
    similarityResult.similarity < similarityResult.threshold
  ) {
    console.warn("FaceID mismatch: combined score below threshold", {
      similarity: similarityResult.similarity,
      alignedScore: similarityResult.alignedScore,
      geometryScore: similarityResult.geometryScore,
      legacyScore: similarityResult.legacyScore,
      threshold: similarityResult.threshold,
    });
    throw new Error("FACE_ID_MISMATCH");
  }

  return { challenge, similarity: similarityResult.similarity };
};

const verifyFaceIdSubmissionStrict = async (
  submission: FaceIdEnrollmentSubmission,
  storedDescriptor?: string,
) => {
  const verified = verifyFaceIdSubmission(submission, storedDescriptor);
  const antiSpoof: FaceIdAntiSpoofResult = {
    passed: true,
    spoofScore: 0,
    confidence: 1,
    riskLevel: "low",
    reasons: ["anti-spoof-disabled"],
    modelSource: "disabled",
    modelVersion: "disabled",
  };
  return { ...verified, antiSpoof };
};

const getInternalFaceIdMetadata = (metadata: unknown) => {
  if (!metadata || typeof metadata !== "object") return null;
  const value = (metadata as Record<string, unknown>).faceId;
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
};

const getInternalTransferPinMetadata = (metadata: unknown) => {
  if (!metadata || typeof metadata !== "object") return null;
  const value = (metadata as Record<string, unknown>).transferSecurity;
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
};

const hasStoredTransferPin = (metadata: unknown) => {
  const transferPin = getInternalTransferPinMetadata(metadata);
  return (
    transferPin !== null &&
    typeof transferPin.pinHash === "string" &&
    transferPin.pinHash.length > 0
  );
};

type AccountProfileCategory = "PERSONAL" | "BUSINESS";
type PersonalAccountTier = "BASIC" | "STANDARD" | "PREMIUM";
type BusinessAccountTier = "SMALL_BUSINESS" | "MEDIUM_BUSINESS" | "ENTERPRISE";
type AccountProfileTier = PersonalAccountTier | BusinessAccountTier;
type ResolvedAccountProfile = {
  category: AccountProfileCategory;
  tier: AccountProfileTier;
  segment: "PERSONAL" | "SME" | "ENTERPRISE";
  profileCode:
    | "PERSONAL_BASIC"
    | "PERSONAL_STANDARD"
    | "PERSONAL_PREMIUM"
    | "BUSINESS_SMALL_BUSINESS"
    | "BUSINESS_MEDIUM_BUSINESS"
    | "BUSINESS_ENTERPRISE";
  label: string;
  reviewBias: "strict" | "balanced" | "high_value";
  status: "SYSTEM_ASSIGNED" | "PENDING_REVIEW" | "VERIFIED" | "REQUIRES_REVIEW";
  confidence: number;
  effectiveCategory: AccountProfileCategory;
  effectiveTier: AccountProfileTier;
  declaredCategory: AccountProfileCategory;
  declaredTier: AccountProfileTier;
  requestedCategory: AccountProfileCategory | null;
  requestedTier: AccountProfileTier | null;
  hasPendingRequest: boolean;
};

type AccountProfileAutomationSummary = {
  mode: "AUTOMATIC" | "ADMIN_CONTROLLED";
  reviewWindowDays: number;
  lastEvaluatedAt: string;
  autoUpgradeApplied: boolean;
  eligibleForUpgrade: boolean;
  recommendedCategory: AccountProfileCategory;
  recommendedTier: AccountProfileTier;
  nextTier: AccountProfileTier | null;
  rationale: string[];
  milestones: string[];
  stats: {
    completedCount: number;
    totalVolume: number;
    outgoingVolume: number;
    incomingVolume: number;
    largeTransferCount: number;
    counterpartyCount: number;
    sourceCoverageRatio: number;
    cleanActivityRatio: number;
  };
};

const PERSONAL_ACCOUNT_TIERS = ["BASIC", "STANDARD", "PREMIUM"] as const;
const BUSINESS_ACCOUNT_TIERS = [
  "SMALL_BUSINESS",
  "MEDIUM_BUSINESS",
  "ENTERPRISE",
] as const;
const ACCOUNT_PROFILE_AUTO_REVIEW_WINDOW_DAYS = 30;
const PERSONAL_ACCOUNT_TIER_ORDER: PersonalAccountTier[] = [
  "BASIC",
  "STANDARD",
  "PREMIUM",
];

const normalizeAccountProfileCategory = (
  value: unknown,
  fallbackSegment?: unknown,
): AccountProfileCategory => {
  const normalized = String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, "");
  if (
    normalized === "BUSINESS" ||
    normalized === "ENTERPRISE" ||
    normalized === "SME" ||
    normalized === "CORPORATE" ||
    normalized === "SMALLBUSINESS"
  ) {
    return "BUSINESS";
  }
  if (normalized === "PERSONAL") return "PERSONAL";
  const segment = String(fallbackSegment || "")
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, "");
  return segment === "SME" || segment === "ENTERPRISE"
    ? "BUSINESS"
    : "PERSONAL";
};

const normalizeAccountProfileTier = (
  category: AccountProfileCategory,
  value: unknown,
  fallbackSegment?: unknown,
): AccountProfileTier => {
  const normalized = String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, "");
  const normalizedTier =
    normalized === "PRIVATE"
      ? "PREMIUM"
      : normalized === "SME" || normalized === "SMALLBUSINESS"
        ? "SMALL_BUSINESS"
        : normalized === "MEDIUMBUSINESS" || normalized === "B2MEDIUMBUSINESS"
          ? "MEDIUM_BUSINESS"
          : normalized === "B1SMALLBUSINESS"
            ? "SMALL_BUSINESS"
            : normalized === "B3ENTERPRISE"
              ? "ENTERPRISE"
              : normalized === "P1BASIC"
                ? "BASIC"
                : normalized === "P2STANDARD"
                  ? "STANDARD"
                  : normalized === "P3PREMIUM"
                    ? "PREMIUM"
                    : normalized;
  if (
    category === "PERSONAL" &&
    PERSONAL_ACCOUNT_TIERS.includes(normalizedTier as PersonalAccountTier)
  ) {
    return normalizedTier as PersonalAccountTier;
  }
  if (
    category === "BUSINESS" &&
    BUSINESS_ACCOUNT_TIERS.includes(normalizedTier as BusinessAccountTier)
  ) {
    return normalizedTier as BusinessAccountTier;
  }
  const fallback = String(fallbackSegment || "")
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, "");
  if (category === "BUSINESS") {
    if (fallback === "ENTERPRISE") return "ENTERPRISE";
    if (fallback === "SME") return "MEDIUM_BUSINESS";
    return "SMALL_BUSINESS";
  }
  return "STANDARD";
};

const deriveAccountProfileSegment = (
  category: AccountProfileCategory,
  tier: AccountProfileTier,
): ResolvedAccountProfile["segment"] => {
  if (category === "BUSINESS") {
    return tier === "ENTERPRISE" ? "ENTERPRISE" : "SME";
  }
  return "PERSONAL";
};

const buildAccountProfileLabel = (
  category: AccountProfileCategory,
  tier: AccountProfileTier,
) => {
  if (category === "BUSINESS") {
    if (tier === "ENTERPRISE") return "Business Enterprise";
    if (tier === "MEDIUM_BUSINESS") return "Business Medium";
    return "Business Small";
  }
  if (tier === "BASIC") return "Personal Basic";
  if (tier === "PREMIUM") return "Personal Premium";
  return "Personal Standard";
};

const buildAccountProfileReviewBias = (
  category: AccountProfileCategory,
  tier: AccountProfileTier,
): ResolvedAccountProfile["reviewBias"] => {
  if (category === "BUSINESS") return "high_value";
  return tier === "BASIC" ? "strict" : "balanced";
};

const comparePersonalAccountTiers = (
  left: PersonalAccountTier,
  right: PersonalAccountTier,
) =>
  PERSONAL_ACCOUNT_TIER_ORDER.indexOf(left) -
  PERSONAL_ACCOUNT_TIER_ORDER.indexOf(right);

const buildPersonalAccountAutoMilestones = (input: {
  currentTier: PersonalAccountTier;
  recommendedTier: PersonalAccountTier;
  stats: AccountProfileAutomationSummary["stats"];
}) => {
  const milestones: string[] = [];
  if (input.recommendedTier === "BASIC") {
    milestones.push(
      input.stats.completedCount >= 6
        ? "Monthly activity is active enough for the next tier."
        : `Complete at least 6 clean transactions in ${ACCOUNT_PROFILE_AUTO_REVIEW_WINDOW_DAYS} days.`,
    );
    milestones.push(
      input.stats.totalVolume >= 3000
        ? "Monthly transaction value already meets the P2 volume target."
        : "Build at least $3,000 in completed monthly volume.",
    );
    milestones.push(
      input.stats.sourceCoverageRatio >= 0.65
        ? "Incoming funds already explain most outgoing transfers."
        : "Maintain incoming funds that cover at least 65% of outgoing value.",
    );
    return milestones;
  }
  if (input.recommendedTier === "STANDARD") {
    milestones.push(
      input.stats.completedCount >= 16
        ? "Activity count is already close to premium review volume."
        : `Build toward 16 or more completed transactions in ${ACCOUNT_PROFILE_AUTO_REVIEW_WINDOW_DAYS} days.`,
    );
    milestones.push(
      input.stats.totalVolume >= 15000
        ? "Monthly transaction value already meets the premium volume target."
        : "Reach at least $15,000 in total completed monthly volume.",
    );
    milestones.push(
      input.stats.largeTransferCount >= 3
        ? "Large-transfer history is already established."
        : "Maintain at least 3 larger clean transfers for premium review.",
    );
    milestones.push(
      input.stats.counterpartyCount >= 4
        ? "Counterparty diversity already supports a broader baseline."
        : "Build a stable history with at least 4 counterparties.",
    );
    return milestones;
  }
  milestones.push("You are already at the highest automatic personal tier.");
  milestones.push(
    "Continue maintaining clean, explainable flow so AI can keep using a stable premium baseline.",
  );
  return milestones;
};

const normalizeAccountProfileRequestContext = (
  value: unknown,
  category?: AccountProfileCategory,
) => {
  const source =
    value && typeof value === "object"
      ? (value as Record<string, unknown>)
      : {};
  const usagePurpose =
    typeof source.usagePurpose === "string" ? source.usagePurpose.trim() : "";
  const expectedTransactionLevel =
    typeof source.expectedTransactionLevel === "string"
      ? source.expectedTransactionLevel.trim().toUpperCase()
      : "";
  const expectedTransactionFrequency =
    typeof source.expectedTransactionFrequency === "string"
      ? source.expectedTransactionFrequency.trim().toUpperCase()
      : "";
  const businessSize =
    typeof source.businessSize === "string"
      ? source.businessSize.trim().toUpperCase()
      : "";
  const justification =
    typeof source.justification === "string"
      ? source.justification.trim().slice(0, 280)
      : "";

  return {
    ...(usagePurpose ? { usagePurpose } : {}),
    ...(expectedTransactionLevel ? { expectedTransactionLevel } : {}),
    ...(expectedTransactionFrequency ? { expectedTransactionFrequency } : {}),
    ...(category === "BUSINESS" && businessSize ? { businessSize } : {}),
    ...(justification ? { justification } : {}),
  };
};

const normalizeAccountProfileStatus = (
  value: unknown,
): ResolvedAccountProfile["status"] => {
  const normalized = String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, "_");
  if (
    normalized === "PENDING_REVIEW" ||
    normalized === "VERIFIED" ||
    normalized === "REQUIRES_REVIEW"
  ) {
    return normalized;
  }
  return "SYSTEM_ASSIGNED";
};

const defaultAccountProfileConfidence = (
  status: ResolvedAccountProfile["status"],
) => {
  if (status === "VERIFIED") return 0.92;
  if (status === "PENDING_REVIEW") return 0.45;
  if (status === "REQUIRES_REVIEW") return 0.35;
  return 0.6;
};

const buildResolvedAccountProfile = (
  metadata: unknown,
): ResolvedAccountProfile => {
  const root =
    metadata && typeof metadata === "object"
      ? (metadata as Record<string, unknown>)
      : {};
  const accountProfile =
    root.accountProfile && typeof root.accountProfile === "object"
      ? (root.accountProfile as Record<string, unknown>)
      : {};
  const businessProfile =
    root.businessProfile && typeof root.businessProfile === "object"
      ? (root.businessProfile as Record<string, unknown>)
      : {};
  const rawSegment =
    accountProfile.effectiveSegment ??
    accountProfile.segment ??
    root.accountSegment ??
    root.segment ??
    businessProfile.segment ??
    businessProfile.accountType ??
    root.accountType;
  const effectiveCategory = normalizeAccountProfileCategory(
    accountProfile.effectiveCategory ??
      accountProfile.category ??
      root.accountCategory ??
      root.accountType,
    rawSegment,
  );
  const effectiveTier = normalizeAccountProfileTier(
    effectiveCategory,
    accountProfile.effectiveTier ??
      accountProfile.tier ??
      root.accountTier ??
      businessProfile.tier ??
      businessProfile.segment,
    rawSegment,
  );
  const segment = deriveAccountProfileSegment(effectiveCategory, effectiveTier);
  const declaredCategory = normalizeAccountProfileCategory(
    accountProfile.declaredCategory ?? effectiveCategory,
    segment,
  );
  const declaredTier = normalizeAccountProfileTier(
    declaredCategory,
    accountProfile.declaredTier ?? effectiveTier,
    segment,
  );
  const requestedCategoryRaw = accountProfile.requestedCategory;
  const requestedTierRaw = accountProfile.requestedTier;
  const requestedCategory =
    requestedCategoryRaw === undefined || requestedCategoryRaw === null
      ? null
      : normalizeAccountProfileCategory(requestedCategoryRaw, segment);
  const requestedTier =
    requestedCategory === null
      ? null
      : normalizeAccountProfileTier(
          requestedCategory,
          requestedTierRaw,
          segment,
        );
  const status = normalizeAccountProfileStatus(
    accountProfile.status ??
      (requestedCategory && requestedTier
        ? "PENDING_REVIEW"
        : "SYSTEM_ASSIGNED"),
  );
  const confidence = clamp(
    typeof accountProfile.confidence === "number"
      ? accountProfile.confidence
      : defaultAccountProfileConfidence(status),
    0.1,
    0.99,
  );
  const profileCode =
    `${effectiveCategory}_${effectiveTier}` as ResolvedAccountProfile["profileCode"];
  const label = buildAccountProfileLabel(effectiveCategory, effectiveTier);
  const reviewBias = buildAccountProfileReviewBias(
    effectiveCategory,
    effectiveTier,
  );

  return {
    category: effectiveCategory,
    tier: effectiveTier,
    segment,
    profileCode,
    label,
    reviewBias,
    status,
    confidence,
    effectiveCategory,
    effectiveTier,
    declaredCategory,
    declaredTier,
    requestedCategory,
    requestedTier,
    hasPendingRequest:
      requestedCategory !== null &&
      requestedTier !== null &&
      (requestedCategory !== effectiveCategory ||
        requestedTier !== effectiveTier),
  };
};

const evaluateAutomaticAccountProfileForUser = async (input: {
  userId: string;
  metadata: unknown;
}): Promise<{
  metadata: Record<string, unknown>;
  accountProfile: ResolvedAccountProfile;
  automation: AccountProfileAutomationSummary;
}> => {
  const currentProfile = buildResolvedAccountProfile(input.metadata);
  const baseMetadata =
    input.metadata && typeof input.metadata === "object"
      ? { ...(input.metadata as Record<string, unknown>) }
      : {};
  const nowIso = new Date().toISOString();

  if (currentProfile.category !== "PERSONAL") {
    const automation: AccountProfileAutomationSummary = {
      mode: "ADMIN_CONTROLLED",
      reviewWindowDays: ACCOUNT_PROFILE_AUTO_REVIEW_WINDOW_DAYS,
      lastEvaluatedAt: nowIso,
      autoUpgradeApplied: false,
      eligibleForUpgrade: false,
      recommendedCategory: currentProfile.category,
      recommendedTier: currentProfile.tier,
      nextTier: null,
      rationale: [
        "Business profiles stay under admin control so enterprise-like behavior can be reviewed manually for demos and investigations.",
      ],
      milestones: [
        "Admin can still set business tiers directly for scenario-based demonstrations.",
      ],
      stats: {
        completedCount: 0,
        totalVolume: 0,
        outgoingVolume: 0,
        incomingVolume: 0,
        largeTransferCount: 0,
        counterpartyCount: 0,
        sourceCoverageRatio: 0,
        cleanActivityRatio: 1,
      },
    };
    return {
      metadata: {
        ...baseMetadata,
        accountProfile: {
          ...(baseMetadata.accountProfile &&
          typeof baseMetadata.accountProfile === "object"
            ? (baseMetadata.accountProfile as Record<string, unknown>)
            : {}),
          automation,
        },
      },
      accountProfile: currentProfile,
      automation,
    };
  }

  const reviewWindowStart = new Date(
    Date.now() - ACCOUNT_PROFILE_AUTO_REVIEW_WINDOW_DAYS * 24 * 60 * 60 * 1000,
  );
  const walletIds = (
    await prisma.wallet.findMany({
      where: { userId: input.userId },
      select: { id: true },
    })
  ).map((wallet: { id: string }) => wallet.id);

  const transactionWhere: Prisma.TransactionWhereInput = {
    status: "COMPLETED",
    createdAt: { gte: reviewWindowStart },
    OR: [
      { fromUserId: input.userId },
      { toUserId: input.userId },
      ...(walletIds.length
        ? [
            { walletId: { in: walletIds } },
            { counterpartyWalletId: { in: walletIds } },
          ]
        : []),
    ],
  };

  const transactionRows = await prisma.transaction.findMany({
    where: transactionWhere,
    select: {
      id: true,
      amount: true,
      type: true,
      fromUserId: true,
      toUserId: true,
      counterpartyWalletId: true,
      metadata: true,
    },
  });
  const uniqueTransactions: Array<(typeof transactionRows)[number]> =
    Array.from(
      new Map<string, (typeof transactionRows)[number]>(
        transactionRows.map(
          (row: (typeof transactionRows)[number]) => [row.id, row] as const,
        ),
      ).values(),
    );

  let totalVolume = 0;
  let outgoingVolume = 0;
  let incomingVolume = 0;
  let largeTransferCount = 0;
  const counterpartyKeys = new Set<string>();
  for (const tx of uniqueTransactions) {
    const amount = Math.abs(Number(tx.amount || 0));
    totalVolume += amount;
    const metadata = normalizeRecord(tx.metadata);
    const outbound =
      tx.fromUserId === input.userId ||
      metadata.entry === "DEBIT" ||
      tx.type === "WITHDRAW";
    const inbound =
      tx.toUserId === input.userId ||
      metadata.entry === "CREDIT" ||
      tx.type === "DEPOSIT";

    if (outbound) {
      outgoingVolume += amount;
      if (tx.type === "TRANSFER" && amount >= 3000) {
        largeTransferCount += 1;
      }
      const counterparty =
        asStringOrNull(metadata.toAccount) ??
        asStringOrNull(metadata.counterpartyAccount) ??
        asStringOrNull(tx.toUserId) ??
        asStringOrNull(tx.counterpartyWalletId);
      if (counterparty) {
        counterpartyKeys.add(counterparty);
      }
    }
    if (inbound) {
      incomingVolume += amount;
    }
  }

  const recentAlerts = await prisma.auditLog.findMany({
    where: {
      userId: input.userId,
      action: "AI_TRANSACTION_ALERT",
      createdAt: { gte: reviewWindowStart },
    },
    select: {
      details: true,
      metadata: true,
    },
  });
  let confirmedRiskCount = 0;
  for (const alert of recentAlerts) {
    const details = normalizeRecord(alert.details);
    const metadata = normalizeRecord(alert.metadata);
    const adminStatus = normalizeAdminAlertStatus(
      details.adminStatus ?? metadata.adminStatus,
    );
    if (adminStatus === "confirmed_risk" || adminStatus === "escalated") {
      confirmedRiskCount += 1;
    }
  }

  const completedCount = uniqueTransactions.length;
  const sourceCoverageRatio =
    outgoingVolume > 0
      ? clamp(incomingVolume / outgoingVolume, 0, 3)
      : incomingVolume > 0
        ? 1
        : 0;
  const cleanActivityRatio =
    completedCount > 0
      ? clamp(1 - confirmedRiskCount / completedCount, 0, 1)
      : 1;

  let recommendedTier: PersonalAccountTier = "BASIC";
  const rationale: string[] = [];
  if (
    completedCount >= 6 &&
    totalVolume >= 3000 &&
    outgoingVolume >= 1200 &&
    sourceCoverageRatio >= 0.65 &&
    cleanActivityRatio >= 0.9
  ) {
    recommendedTier = "STANDARD";
    rationale.push(
      "Completed activity over the last 30 days is strong enough for a broader personal baseline.",
    );
  }
  if (
    completedCount >= 16 &&
    totalVolume >= 15000 &&
    outgoingVolume >= 8000 &&
    largeTransferCount >= 3 &&
    counterpartyKeys.size >= 4 &&
    sourceCoverageRatio >= 0.85 &&
    cleanActivityRatio >= 0.96
  ) {
    recommendedTier = "PREMIUM";
    rationale.push(
      "High-value behavior is sustained, counterparties are diverse, and incoming funds explain the transfer pattern cleanly enough for premium treatment.",
    );
  }
  if (rationale.length === 0) {
    rationale.push(
      "Automatic tiering is still collecting enough clean monthly activity before widening the AI baseline.",
    );
  }

  const currentTier = currentProfile.tier as PersonalAccountTier;
  const upgradeEligible =
    comparePersonalAccountTiers(recommendedTier, currentTier) > 0 &&
    !currentProfile.hasPendingRequest;
  const nextTier =
    currentTier === "BASIC"
      ? "STANDARD"
      : currentTier === "STANDARD"
        ? "PREMIUM"
        : null;
  const milestones = buildPersonalAccountAutoMilestones({
    currentTier,
    recommendedTier,
    stats: {
      completedCount,
      totalVolume,
      outgoingVolume,
      incomingVolume,
      largeTransferCount,
      counterpartyCount: counterpartyKeys.size,
      sourceCoverageRatio,
      cleanActivityRatio,
    },
  });

  let effectiveMetadata = baseMetadata;
  let effectiveProfile = currentProfile;
  if (upgradeEligible) {
    effectiveMetadata = setEffectiveAccountProfileMetadata(
      baseMetadata,
      {
        category: "PERSONAL",
        tier: recommendedTier,
        status: "VERIFIED",
        confidence:
          recommendedTier === "PREMIUM"
            ? Math.max(currentProfile.confidence, 0.95)
            : Math.max(currentProfile.confidence, 0.88),
      },
      "automatic-tiering",
    );
    effectiveProfile = buildResolvedAccountProfile(effectiveMetadata);
    rationale.unshift(
      `FPIPay automatically upgraded this account to ${buildAccountProfileLabel("PERSONAL", recommendedTier)} based on the last ${ACCOUNT_PROFILE_AUTO_REVIEW_WINDOW_DAYS} days of clean activity.`,
    );
  }

  const automation: AccountProfileAutomationSummary = {
    mode: "AUTOMATIC",
    reviewWindowDays: ACCOUNT_PROFILE_AUTO_REVIEW_WINDOW_DAYS,
    lastEvaluatedAt: nowIso,
    autoUpgradeApplied: upgradeEligible,
    eligibleForUpgrade: upgradeEligible,
    recommendedCategory: "PERSONAL",
    recommendedTier,
    nextTier,
    rationale,
    milestones,
    stats: {
      completedCount,
      totalVolume,
      outgoingVolume,
      incomingVolume,
      largeTransferCount,
      counterpartyCount: counterpartyKeys.size,
      sourceCoverageRatio,
      cleanActivityRatio,
    },
  };

  return {
    metadata: {
      ...effectiveMetadata,
      accountProfile: {
        ...(effectiveMetadata.accountProfile &&
        typeof effectiveMetadata.accountProfile === "object"
          ? (effectiveMetadata.accountProfile as Record<string, unknown>)
          : {}),
        automation,
      },
    },
    accountProfile: effectiveProfile,
    automation,
  };
};

const setEffectiveAccountProfileMetadata = (
  existingMetadata: unknown,
  input: {
    category?: unknown;
    tier?: unknown;
    status?: ResolvedAccountProfile["status"];
    confidence?: unknown;
    clearPendingRequest?: boolean;
  },
  updatedBy: string,
) => {
  const root =
    existingMetadata && typeof existingMetadata === "object"
      ? { ...(existingMetadata as Record<string, unknown>) }
      : {};
  const currentAccountProfileRoot =
    root.accountProfile && typeof root.accountProfile === "object"
      ? (root.accountProfile as Record<string, unknown>)
      : {};
  const current = buildResolvedAccountProfile(root);
  const category = normalizeAccountProfileCategory(
    input.category ?? current.effectiveCategory,
    current.segment,
  );
  const tier = normalizeAccountProfileTier(
    category,
    input.tier ?? current.effectiveTier,
    current.segment,
  );
  const segment = deriveAccountProfileSegment(category, tier);
  const status = input.status ?? "VERIFIED";
  const confidence = clamp(
    typeof input.confidence === "number"
      ? input.confidence
      : status === "VERIFIED"
        ? Math.max(current.confidence, 0.9)
        : defaultAccountProfileConfidence(status),
    0.1,
    0.99,
  );

  return {
    ...root,
    accountCategory: category,
    accountTier: tier,
    accountSegment: segment,
    accountType: category === "BUSINESS" ? "business" : "personal",
    segment,
    accountProfile: {
      ...currentAccountProfileRoot,
      category,
      tier,
      segment,
      effectiveCategory: category,
      effectiveTier: tier,
      effectiveSegment: segment,
      declaredCategory: category,
      declaredTier: tier,
      requestedCategory:
        input.clearPendingRequest === false ? current.requestedCategory : null,
      requestedTier:
        input.clearPendingRequest === false ? current.requestedTier : null,
      requestContext:
        input.clearPendingRequest === false
          ? typeof currentAccountProfileRoot.requestContext === "object"
            ? (currentAccountProfileRoot.requestContext as Record<
                string,
                unknown
              >)
            : null
          : null,
      requestedAt:
        input.clearPendingRequest === false
          ? typeof currentAccountProfileRoot.requestedAt === "string"
            ? currentAccountProfileRoot.requestedAt
            : null
          : null,
      requestedBy:
        input.clearPendingRequest === false
          ? typeof currentAccountProfileRoot.requestedBy === "string"
            ? currentAccountProfileRoot.requestedBy
            : null
          : null,
      status,
      confidence,
      profileCode: `${category}_${tier}`,
      label: buildAccountProfileLabel(category, tier),
      reviewBias: buildAccountProfileReviewBias(category, tier),
      reviewedAt: new Date().toISOString(),
      reviewedBy: updatedBy,
      updatedAt: new Date().toISOString(),
      updatedBy,
    },
  };
};

const requestAccountProfileChangeMetadata = (
  existingMetadata: unknown,
  input: {
    category?: unknown;
    tier?: unknown;
    requestContext?: unknown;
  },
  requestedBy: string,
) => {
  const root =
    existingMetadata && typeof existingMetadata === "object"
      ? { ...(existingMetadata as Record<string, unknown>) }
      : {};
  const current = buildResolvedAccountProfile(root);
  const requestedCategory = normalizeAccountProfileCategory(
    input.category ?? current.declaredCategory,
    current.segment,
  );
  const requestedTier = normalizeAccountProfileTier(
    requestedCategory,
    input.tier ?? current.declaredTier,
    current.segment,
  );
  const noMaterialChange =
    requestedCategory === current.effectiveCategory &&
    requestedTier === current.effectiveTier;
  const requestContext = normalizeAccountProfileRequestContext(
    input.requestContext,
    requestedCategory,
  );

  return {
    ...root,
    accountProfile: {
      ...(root.accountProfile && typeof root.accountProfile === "object"
        ? (root.accountProfile as Record<string, unknown>)
        : {}),
      declaredCategory: requestedCategory,
      declaredTier: requestedTier,
      requestedCategory: noMaterialChange ? null : requestedCategory,
      requestedTier: noMaterialChange ? null : requestedTier,
      status: noMaterialChange ? current.status : "PENDING_REVIEW",
      confidence: noMaterialChange
        ? current.confidence
        : Math.min(current.confidence, 0.45),
      requestContext: noMaterialChange ? null : requestContext,
      requestedAt: noMaterialChange ? null : new Date().toISOString(),
      requestedBy: noMaterialChange ? null : requestedBy,
      updatedAt: new Date().toISOString(),
      updatedBy: requestedBy,
    },
  };
};

const buildPublicUserMetadata = (metadata: unknown) => {
  const source =
    metadata && typeof metadata === "object"
      ? { ...(metadata as Record<string, unknown>) }
      : {};
  delete source.faceId;
  delete source.transferSecurity;
  delete source.budgetAssistant;
  const faceId = getInternalFaceIdMetadata(metadata);
  source.faceIdEnabled =
    faceId && typeof faceId.enabled === "boolean" ? faceId.enabled : false;
  source.faceIdEnrolledAt =
    faceId && typeof faceId.enrolledAt === "string" ? faceId.enrolledAt : null;
  source.faceIdVerifiedAt =
    faceId && typeof faceId.lastVerifiedAt === "string"
      ? faceId.lastVerifiedAt
      : null;
  source.transferPinEnabled = hasStoredTransferPin(metadata);
  const accountProfile = buildResolvedAccountProfile(metadata);
  source.accountCategory = accountProfile.category;
  source.accountTier = accountProfile.tier;
  source.accountSegment = accountProfile.segment;
  source.accountProfile = {
    ...(source.accountProfile && typeof source.accountProfile === "object"
      ? (source.accountProfile as Record<string, unknown>)
      : {}),
    category: accountProfile.category,
    tier: accountProfile.tier,
    segment: accountProfile.segment,
    profileCode: accountProfile.profileCode,
    label: accountProfile.label,
    reviewBias: accountProfile.reviewBias,
    status: accountProfile.status,
    confidence: accountProfile.confidence,
    declaredCategory: accountProfile.declaredCategory,
    declaredTier: accountProfile.declaredTier,
    effectiveCategory: accountProfile.effectiveCategory,
    effectiveTier: accountProfile.effectiveTier,
    requestedCategory: accountProfile.requestedCategory,
    requestedTier: accountProfile.requestedTier,
    hasPendingRequest: accountProfile.hasPendingRequest,
  };
  source.budgetPlan = buildPublicBudgetPlanSummary(
    getStoredBudgetPlan(metadata),
  );
  source.budgetPlanActive =
    source.budgetPlan &&
    typeof source.budgetPlan === "object" &&
    (source.budgetPlan as PublicBudgetPlanSummary).status === "ACTIVE";
  source.budgetAssistantPreferences = getBudgetAssistantPreferences(metadata);
  return source;
};

const resolveUserAccountSegment = (metadata: unknown) => {
  return buildResolvedAccountProfile(metadata).segment;
};

type AccountProfileTransferThresholds = {
  mediumAmount: number;
  highAmount: number;
  newRecipientAmount: number;
  extremeMultiplier: number;
};

const ACCOUNT_PROFILE_TRANSFER_THRESHOLDS: Record<
  ResolvedAccountProfile["profileCode"],
  AccountProfileTransferThresholds
> = {
  PERSONAL_BASIC: {
    mediumAmount: 1500,
    highAmount: 5000,
    newRecipientAmount: 1000,
    extremeMultiplier: 8,
  },
  PERSONAL_STANDARD: {
    mediumAmount: 3000,
    highAmount: 10000,
    newRecipientAmount: 2000,
    extremeMultiplier: 8,
  },
  PERSONAL_PREMIUM: {
    mediumAmount: 7000,
    highAmount: 25000,
    newRecipientAmount: 5000,
    extremeMultiplier: 7,
  },
  BUSINESS_SMALL_BUSINESS: {
    mediumAmount: 75000,
    highAmount: 400000,
    newRecipientAmount: 40000,
    extremeMultiplier: 8,
  },
  BUSINESS_MEDIUM_BUSINESS: {
    mediumAmount: 250000,
    highAmount: 1200000,
    newRecipientAmount: 125000,
    extremeMultiplier: 6,
  },
  BUSINESS_ENTERPRISE: {
    mediumAmount: 500000,
    highAmount: 3000000,
    newRecipientAmount: 250000,
    extremeMultiplier: 6,
  },
};

const getAccountProfileTransferThresholds = (
  accountProfile: ResolvedAccountProfile,
): AccountProfileTransferThresholds =>
  ACCOUNT_PROFILE_TRANSFER_THRESHOLDS[accountProfile.profileCode];

const TRANSFER_ACTION_ORDER: NonNullable<AnomalyResponse["finalAction"]>[] = [
  "ALLOW",
  "ALLOW_WITH_WARNING",
  "REQUIRE_OTP",
  "REQUIRE_OTP_FACE_ID",
  "HOLD_REVIEW",
];

const rankTransferFinalAction = (
  value: AnomalyResponse["finalAction"] | null | undefined,
) => {
  const normalized = value || "ALLOW";
  const index = TRANSFER_ACTION_ORDER.indexOf(normalized);
  return index >= 0 ? index : 0;
};

const promoteTransferRiskLevel = (
  current: AnomalyResponse["riskLevel"],
  target: AnomalyResponse["riskLevel"],
): AnomalyResponse["riskLevel"] => {
  const order: Record<AnomalyResponse["riskLevel"], number> = {
    low: 0,
    medium: 1,
    high: 2,
  };
  return order[target] > order[current] ? target : current;
};

const hardenTransferAiResultForAccountProfile = (input: {
  aiResult: AnomalyResponse;
  amount: number;
  senderBalance: number;
  accountProfile: ResolvedAccountProfile;
  recipientKnown: boolean;
  faceIdRequired: boolean;
  sessionRestrictLargeTransfers: boolean;
  spendProfile: TransferSpendProfile;
  behaviorProfile: TransferBehaviorProfile;
  transferNoteLlm: TransferNoteLlmAnalysis;
}): AnomalyResponse => {
  const amount = Math.max(0, Number(input.amount) || 0);
  if (amount <= 0) return input.aiResult;

  const thresholds = getAccountProfileTransferThresholds(input.accountProfile);
  const senderBalance = Math.max(0, Number(input.senderBalance) || 0);
  const drainRatio = amount / Math.max(senderBalance, 1);
  const amountVsAverage =
    input.spendProfile.dailySpendAvg30d > 0
      ? amount / Math.max(input.spendProfile.dailySpendAvg30d, 1)
      : null;
  const aiUnavailable =
    input.aiResult.modelSource === "fallback" ||
    input.aiResult.modelSource === "api-profile-guard-fallback" ||
    input.aiResult.reasons.some((reason) =>
      /ai monitoring unavailable/i.test(reason),
    );
  const isBusinessProfile = input.accountProfile.category === "BUSINESS";
  const exceedsMediumBand = amount >= thresholds.mediumAmount;
  const exceedsHighBand = amount >= thresholds.highAmount;
  const exceedsExtremeBand =
    amount >= thresholds.highAmount * thresholds.extremeMultiplier;
  const isLargeNewRecipientTransfer =
    !input.recipientKnown && amount >= thresholds.newRecipientAmount;
  const isStrictPersonalTier =
    input.accountProfile.category === "PERSONAL" &&
    input.accountProfile.tier === "BASIC";
  const hasStrongSpendBreak =
    amountVsAverage !== null &&
    amountVsAverage >=
      (isStrictPersonalTier
        ? 8
        : input.accountProfile.reviewBias === "balanced"
          ? 10
          : 12);
  const rapidCashOutSignal =
    input.behaviorProfile.rapidCashOutRiskScore >= 0.7 &&
    amount >= Math.max(1000, thresholds.mediumAmount * 0.5);
  const recentTopUpCashOutSignal =
    (input.behaviorProfile.recentAdminTopUpAmount24h > 0 ||
      input.behaviorProfile.recentSelfDepositAmount24h > 0) &&
    amount >=
      Math.max(
        1000,
        input.behaviorProfile.recentInboundAmount24h * 0.75,
        thresholds.mediumAmount * 0.5,
      );
  const hasHousingPurposeTag = input.transferNoteLlm.purposeTags.some((tag) =>
    [
      "home_purchase",
      "property_deposit",
      "mortgage_closing",
      "real_estate_settlement",
    ].includes(tag),
  );
  const qualifiesForAiPurposeException =
    !isBusinessProfile &&
    hasHousingPurposeTag &&
    input.transferNoteLlm.purposeConfidence >= 0.72 &&
    input.transferNoteLlm.riskLevel === "low" &&
    !aiUnavailable &&
    !rapidCashOutSignal &&
    !recentTopUpCashOutSignal &&
    input.behaviorProfile.probeThenLargeRiskScore < 0.7 &&
    input.behaviorProfile.smallProbeCount24h === 0 &&
    !input.aiResult.reasons.some((reason) =>
      /known scam pattern|otp theft|remote access|refund scam|tax scam|investment scam/i.test(
        reason,
      ),
    );
  const shouldForceHardReview =
    (exceedsExtremeBand &&
      !qualifiesForAiPurposeException &&
      (!isBusinessProfile ||
        !input.recipientKnown ||
        drainRatio >= 0.95 ||
        aiUnavailable)) ||
    (isStrictPersonalTier &&
      exceedsHighBand &&
      !qualifiesForAiPurposeException &&
      (!input.recipientKnown || drainRatio >= 0.75)) ||
    (aiUnavailable &&
      exceedsHighBand &&
      (!input.recipientKnown ||
        drainRatio >= (isBusinessProfile ? 0.9 : 0.75))) ||
    (exceedsHighBand &&
      drainRatio >= (isBusinessProfile ? 0.97 : 0.9) &&
      !qualifiesForAiPurposeException) ||
    rapidCashOutSignal ||
    recentTopUpCashOutSignal;

  if (
    !exceedsMediumBand &&
    !isLargeNewRecipientTransfer &&
    !hasStrongSpendBreak &&
    !shouldForceHardReview
  ) {
    return input.aiResult;
  }

  let riskLevel = input.aiResult.riskLevel;
  let finalAction = input.aiResult.finalAction || "ALLOW";
  let finalScore =
    typeof input.aiResult.finalScore === "number"
      ? input.aiResult.finalScore
      : 0;
  let baseScore =
    typeof input.aiResult.baseScore === "number"
      ? input.aiResult.baseScore
      : finalScore;

  const reasons = dedupeStringList([
    ...input.aiResult.reasons,
    exceedsHighBand
      ? `Amount exceeds the normal high-value band for a ${input.accountProfile.label.toLowerCase()} account.`
      : exceedsMediumBand
        ? `Amount is elevated for a ${input.accountProfile.label.toLowerCase()} account and should not pass under passive monitoring.`
        : null,
    isLargeNewRecipientTransfer
      ? "Large transfer is being sent to a recipient outside the user's established completed-transfer history."
      : null,
    drainRatio >= 0.75
      ? `This payment would consume ${Math.round(drainRatio * 100)}% of the current wallet balance.`
      : null,
    hasStrongSpendBreak
      ? "Transfer amount is materially above the user's recent clean spending baseline."
      : null,
    rapidCashOutSignal
      ? "A large amount of funds entered this wallet recently and the current transfer would move most of it back out quickly."
      : null,
    input.behaviorProfile.recentAdminTopUpAmount24h > 0 &&
    recentTopUpCashOutSignal
      ? "Recent admin top-up is being cashed out unusually quickly, which matches a source-in/source-out laundering pattern."
      : null,
    aiUnavailable
      ? "AI scoring was unavailable, so the platform applied strict account-tier protection instead of silently allowing the transfer."
      : null,
    qualifiesForAiPurposeException
      ? "AI recognized a plausible high-value life-event purpose in the transfer note, so the payment can move to enhanced verification instead of an automatic hold."
      : null,
  ]).slice(0, 6);

  if (shouldForceHardReview && !qualifiesForAiPurposeException) {
    riskLevel = "high";
    finalAction = "HOLD_REVIEW";
    finalScore = Math.max(finalScore, 92);
    baseScore = Math.max(baseScore, 92);
  } else if (qualifiesForAiPurposeException && exceedsHighBand) {
    riskLevel = promoteTransferRiskLevel(riskLevel, "high");
    finalAction =
      rankTransferFinalAction(finalAction) >=
      rankTransferFinalAction("REQUIRE_OTP_FACE_ID")
        ? finalAction
        : "REQUIRE_OTP_FACE_ID";
    finalScore = Math.max(finalScore, 82);
    baseScore = Math.max(baseScore, 82);
  } else if (
    exceedsHighBand ||
    isLargeNewRecipientTransfer ||
    hasStrongSpendBreak
  ) {
    riskLevel = promoteTransferRiskLevel(riskLevel, "high");
    finalAction =
      rankTransferFinalAction(finalAction) >=
      rankTransferFinalAction("REQUIRE_OTP_FACE_ID")
        ? finalAction
        : input.faceIdRequired || amount >= thresholds.highAmount
          ? "REQUIRE_OTP_FACE_ID"
          : "REQUIRE_OTP";
    finalScore = Math.max(finalScore, 78);
    baseScore = Math.max(baseScore, 78);
  } else if (exceedsMediumBand) {
    riskLevel = promoteTransferRiskLevel(riskLevel, "medium");
    finalAction =
      rankTransferFinalAction(finalAction) >=
      rankTransferFinalAction("REQUIRE_OTP")
        ? finalAction
        : "REQUIRE_OTP";
    finalScore = Math.max(finalScore, 58);
    baseScore = Math.max(baseScore, 58);
  }

  const mitigationScore =
    typeof input.aiResult.mitigationScore === "number"
      ? input.aiResult.mitigationScore
      : Math.max(0, baseScore - finalScore);

  return {
    ...input.aiResult,
    riskLevel,
    reasons,
    modelSource: aiUnavailable
      ? "api-profile-guard-fallback"
      : input.aiResult.modelSource || "api-profile-guard",
    monitoringOnly: false,
    requireOtp:
      finalAction === "REQUIRE_OTP" ||
      finalAction === "REQUIRE_OTP_FACE_ID" ||
      finalAction === "HOLD_REVIEW",
    otpChannel: input.aiResult.otpChannel || "email",
    otpReason:
      finalAction === "REQUIRE_OTP" || finalAction === "REQUIRE_OTP_FACE_ID"
        ? `the transfer exceeds the protection band for a ${input.accountProfile.label.toLowerCase()} account`
        : input.aiResult.otpReason,
    headline: qualifiesForAiPurposeException
      ? "High-value personal transfer requires enhanced verification"
      : shouldForceHardReview
        ? `Transfer exceeds the safe operating band for ${input.accountProfile.label}`
        : exceedsHighBand
          ? `${input.accountProfile.label} account requires step-up for this amount`
          : input.aiResult.headline,
    summary: qualifiesForAiPurposeException
      ? "AI found a plausible legitimate purpose such as a property or home-payment event, so the transfer can continue only with stronger verification and review."
      : shouldForceHardReview
        ? "The transfer is too large for the current account tier to pass automatically and must be reviewed before completion."
        : exceedsHighBand
          ? "The transfer materially exceeds the current account tier baseline, so passive AI monitoring is not enough."
          : input.aiResult.summary,
    nextStep: qualifiesForAiPurposeException
      ? "Require OTP and FaceID, then ask the sender to re-check the recipient, property/payment purpose, and destination account before completion."
      : finalAction === "HOLD_REVIEW"
        ? "Place the transfer on hold and require admin review before any funds leave the wallet."
        : finalAction === "REQUIRE_OTP_FACE_ID"
          ? "Require OTP and FaceID, then re-check the recipient and amount before completion."
          : finalAction === "REQUIRE_OTP"
            ? "Require OTP and review the recipient, amount, and note again before sending."
            : input.aiResult.nextStep,
    recommendedActions: dedupeStringList([
      ...(input.aiResult.recommendedActions || []),
      "Confirm the recipient and payment purpose independently before continuing.",
      qualifiesForAiPurposeException
        ? "Require a precise note such as property deposit, escrow, or mortgage closing before releasing the transfer."
        : null,
      shouldForceHardReview
        ? "Do not release this transfer automatically while the account remains on the current tier."
        : "Escalate the transfer with stronger verification because it sits outside the normal tier baseline.",
    ]).slice(0, 4),
    finalAction,
    finalScore,
    baseScore,
    mitigationScore,
    stepUpLevel:
      finalAction === "HOLD_REVIEW"
        ? "manual_review"
        : finalAction === "REQUIRE_OTP_FACE_ID"
          ? "otp_faceid"
          : finalAction === "REQUIRE_OTP"
            ? "otp"
            : input.aiResult.stepUpLevel,
    analysisSignals: {
      ...(input.aiResult.analysisSignals || {}),
      accountProfileGuardTriggered: true,
      accountProfileCode: input.accountProfile.profileCode,
      accountProfileLabel: input.accountProfile.label,
      profileThresholds: thresholds,
      amountVsTierMedium: roundMoney(
        amount / Math.max(thresholds.mediumAmount, 1),
      ),
      amountVsTierHigh: roundMoney(amount / Math.max(thresholds.highAmount, 1)),
      aiUnavailable,
      aiPurposeExceptionApplied: qualifiesForAiPurposeException,
      aiPurposeTags: input.transferNoteLlm.purposeTags,
      aiPurposeConfidence: input.transferNoteLlm.purposeConfidence,
      balanceDrainRatio: Number(drainRatio.toFixed(3)),
      recentInboundAmount24h: input.behaviorProfile.recentInboundAmount24h,
      recentAdminTopUpAmount24h:
        input.behaviorProfile.recentAdminTopUpAmount24h,
      recentSelfDepositAmount24h:
        input.behaviorProfile.recentSelfDepositAmount24h,
      rapidCashOutRiskScore: input.behaviorProfile.rapidCashOutRiskScore,
    },
  };
};

const normalizeRecentTransferRecipients = (value: unknown) => {
  if (!Array.isArray(value)) return [] as RecentTransferRecipient[];

  const normalized = value.reduce<RecentTransferRecipient[]>((acc, item) => {
    const record = normalizeMetadataRecord(item);
    const accountNumber =
      typeof record.accountNumber === "string"
        ? record.accountNumber.replace(/\D/g, "").slice(0, 19)
        : "";
    const holderName =
      typeof record.holderName === "string" ? record.holderName.trim() : "";
    const userId =
      typeof record.userId === "string" && record.userId.trim()
        ? record.userId.trim()
        : undefined;
    const lastTransferredAt =
      typeof record.lastTransferredAt === "string" &&
      !Number.isNaN(Date.parse(record.lastTransferredAt))
        ? record.lastTransferredAt
        : "";
    const transferCountRaw =
      typeof record.transferCount === "number"
        ? record.transferCount
        : Number(record.transferCount);
    const transferCount =
      Number.isFinite(transferCountRaw) && transferCountRaw > 0
        ? Math.trunc(transferCountRaw)
        : 1;

    if (!accountNumber || !holderName || !lastTransferredAt) return acc;

    acc.push({
      accountNumber,
      holderName,
      userId,
      lastTransferredAt,
      transferCount,
    });
    return acc;
  }, []);

  return normalized
    .sort(
      (left, right) =>
        Date.parse(right.lastTransferredAt) -
        Date.parse(left.lastTransferredAt),
    )
    .slice(0, MAX_RECENT_TRANSFER_RECIPIENTS);
};

const upsertRecentTransferRecipientMetadata = (
  metadata: unknown,
  input: {
    accountNumber: string;
    holderName: string;
    userId?: string;
    occurredAt: string;
  },
) => {
  const root = normalizeMetadataRecord(metadata);
  const accountNumber = input.accountNumber.replace(/\D/g, "").slice(0, 19);
  const holderName = input.holderName.trim();
  if (!accountNumber || !holderName) return root;

  const existing = normalizeRecentTransferRecipients(
    root[RECENT_TRANSFER_RECIPIENTS_KEY],
  );
  const matched = existing.find((item) => item.accountNumber === accountNumber);
  const next = [
    {
      accountNumber,
      holderName,
      userId: input.userId?.trim() || matched?.userId,
      lastTransferredAt: input.occurredAt,
      transferCount: (matched?.transferCount || 0) + 1,
    } satisfies RecentTransferRecipient,
    ...existing.filter((item) => item.accountNumber !== accountNumber),
  ].slice(0, MAX_RECENT_TRANSFER_RECIPIENTS);

  return {
    ...root,
    [RECENT_TRANSFER_RECIPIENTS_KEY]: next,
  };
};

const buildFaceEnrollmentRequiredNotice = (
  userDoc: UserEntity,
  baseNotice?: string,
) => {
  const faceId = getInternalFaceIdMetadata(userDoc.metadata);
  const hasFaceEnrollment = faceId && faceId.enabled === true;
  if (hasFaceEnrollment) {
    return baseNotice;
  }

  const reminder =
    "Security update: add your 5-second FaceID verification video after sign-in to keep this account protected.";
  return baseNotice ? `${baseNotice} ${reminder}` : reminder;
};

const buildSliderCaptchaChallenge = () => {
  const stageWidthPx = Math.max(220, CAPTCHA_TRACK_WIDTH_PX);
  const pieceWidthPx = Math.min(
    Math.max(40, CAPTCHA_PIECE_WIDTH_PX),
    stageWidthPx - 32,
  );
  const maxOffsetPx = stageWidthPx - pieceWidthPx;
  const tolerancePx = Math.max(6, CAPTCHA_TOLERANCE_PX);
  const minOffsetPx = Math.max(28, Math.round(maxOffsetPx * 0.18));
  const maxTargetPx = Math.max(minOffsetPx + tolerancePx * 2, maxOffsetPx - 28);
  const targetOffsetPx = crypto.randomInt(minOffsetPx, maxTargetPx + 1);
  const issuedAt = Date.now();
  const payload: SliderCaptchaPayload = {
    kind: "slider_v1",
    nonce: crypto.randomUUID(),
    issuedAt,
    expiresAt: issuedAt + CAPTCHA_TTL_MS,
    targetOffsetPx,
    maxOffsetPx,
    tolerancePx,
  };

  return {
    captchaToken: encodeSliderCaptchaToken(payload),
    targetOffsetPx,
    tolerancePx,
    stageWidthPx,
    pieceWidthPx,
    expiresAt: new Date(payload.expiresAt).toISOString(),
  };
};

const readSliderCaptchaSubmission = (body: unknown) => {
  const payload =
    body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const captchaToken =
    typeof payload.captchaToken === "string" ? payload.captchaToken.trim() : "";
  const rawOffset =
    typeof payload.captchaOffset === "number" ||
    typeof payload.captchaOffset === "string"
      ? Number(payload.captchaOffset)
      : Number.NaN;
  return {
    captchaToken,
    captchaOffset: Number.isFinite(rawOffset) ? Math.round(rawOffset) : NaN,
  };
};

const verifySliderCaptchaSubmission = (
  captchaToken: string,
  captchaOffset: number,
) => {
  if (!captchaToken) {
    throw new Error("MISSING_CAPTCHA");
  }
  if (!Number.isFinite(captchaOffset)) {
    throw new Error("INVALID_CAPTCHA");
  }

  const payload = decodeSliderCaptchaToken(captchaToken);
  if (captchaOffset < 0 || captchaOffset > payload.maxOffsetPx) {
    throw new Error("INVALID_CAPTCHA");
  }

  return (
    Math.abs(captchaOffset - payload.targetOffsetPx) <= payload.tolerancePx
  );
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
  security?: SessionSecurityState;
}) => {
  const nextSessionId = crypto.randomUUID();
  const previousSession = input.authState.activeSession;
  const nextAuthState = activateAuthSession(input.authState, {
    sessionId: nextSessionId,
    ipAddress: input.ipAddress,
    userAgent: input.userAgent,
    security: input.security,
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
  const userRepository = createUserRepository();
  const windowStart = new Date(Date.now() - minutes * 60 * 1000);
  const user = await userRepository.findByEmail(email);
  const lockoutResetAtRaw =
    user?.metadata &&
    typeof user.metadata === "object" &&
    typeof (user.metadata as Record<string, unknown>).lockoutResetAt ===
      "string"
      ? ((user.metadata as Record<string, unknown>).lockoutResetAt as string)
      : "";
  const lockoutResetAt = !lockoutResetAtRaw
    ? null
    : Number.isNaN(Date.parse(lockoutResetAtRaw))
      ? null
      : new Date(lockoutResetAtRaw);
  const effectiveWindowStart =
    lockoutResetAt && lockoutResetAt.getTime() > windowStart.getTime()
      ? lockoutResetAt
      : windowStart;
  return loginEventRepository.countRecentFailures(email, effectiveWindowStart);
};

const buildLoginFailureMessage = (input: {
  remainingAttempts: number;
  lockoutMinutes: number;
}) => {
  if (input.remainingAttempts <= 0) {
    return `Incorrect password. Your account has been temporarily locked for ${input.lockoutMinutes} minute${input.lockoutMinutes === 1 ? "" : "s"} after repeated failed attempts.`;
  }

  return `Incorrect password. ${input.remainingAttempts} attempt${input.remainingAttempts === 1 ? "" : "s"} remaining before a temporary ${input.lockoutMinutes}-minute lock.`;
};

const getRecentUserTransferRows = async (
  userId: string,
  since: Date,
  take = 500,
) => {
  const wallets = await prisma.wallet.findMany({
    where: { userId },
    select: { id: true },
    take: 10,
  });
  const walletIds = wallets
    .map((wallet: { id: string }) => wallet.id)
    .filter(
      (value): value is string => typeof value === "string" && value.length > 0,
    );
  if (walletIds.length === 0) return [];

  return prisma.transaction.findMany({
    where: {
      walletId: { in: walletIds },
      createdAt: {
        gte: since,
      },
    },
    orderBy: { createdAt: "desc" },
    take,
  });
};

const countRecentFailedTransfers = async (userId: string, hours: number) => {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  const rows = await getRecentUserTransferRows(userId, since, 200);
  let count = 0;
  for (const row of rows) {
    const tx = safelyDecryptTransaction(row, "countRecentFailedTransfers");
    if (!tx) continue;
    if (tx.type !== "TRANSFER" || tx.status !== "FAILED") continue;
    if (tx.fromUserId !== userId) continue;
    count += 1;
  }
  return count;
};

const countRecentTransferVelocity = async (userId: string, hours: number) => {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  const rows = await getRecentUserTransferRows(userId, since, 200);
  let count = 0;
  for (const row of rows) {
    const tx = safelyDecryptTransaction(row, "countRecentTransferVelocity");
    if (!tx) continue;
    if (tx.type !== "TRANSFER") continue;
    if (tx.fromUserId !== userId) continue;
    const metadata = normalizeMetadataRecord(tx.metadata);
    if (metadata.entry && metadata.entry !== "DEBIT") continue;
    count += 1;
  }
  return count;
};

const getTransferSpendProfile = async (
  userId: string,
  pendingAmount: number,
): Promise<TransferSpendProfile> => {
  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const rows = await getRecentUserTransferRows(userId, since, 500);

  const dailyTotals = new Map<string, number>();
  for (const row of rows) {
    const tx = safelyDecryptTransaction(row, "getTransferSpendProfile");
    if (!tx) continue;
    if (tx.type !== "TRANSFER" || tx.status !== "COMPLETED") continue;
    if (tx.fromUserId !== userId) continue;
    const metadata =
      tx.metadata && typeof tx.metadata === "object"
        ? (tx.metadata as Record<string, unknown>)
        : {};
    if (metadata.entry !== "DEBIT") continue;
    const dayKey = tx.createdAt.toISOString().slice(0, 10);
    dailyTotals.set(
      dayKey,
      (dailyTotals.get(dayKey) || 0) + Number(tx.amount || 0),
    );
  }

  const activeDayTotals = [...dailyTotals.values()].filter(
    (value) => value > 0,
  );
  const todayKey = new Date().toISOString().slice(0, 10);
  const todaySpendBefore = dailyTotals.get(todayKey) || 0;
  const dailySpendAvg30d = activeDayTotals.length
    ? activeDayTotals.reduce((sum, value) => sum + value, 0) /
      activeDayTotals.length
    : 0;
  const projectedDailySpend = todaySpendBefore + Math.max(0, pendingAmount);
  const spendSurgeRatio =
    dailySpendAvg30d > 0 ? projectedDailySpend / dailySpendAvg30d : null;

  return {
    todaySpendBefore,
    dailySpendAvg30d,
    projectedDailySpend,
    spendSurgeRatio,
  };
};

const getTransferRecipientProfile = async (input: {
  userId: string;
  toUserId: string;
  toAccount: string;
}): Promise<TransferRecipientProfile> => {
  const since = new Date(
    Date.now() - KNOWN_RECIPIENT_LOOKBACK_DAYS * 24 * 60 * 60 * 1000,
  );
  const rows = await getRecentUserTransferRows(input.userId, since, 500);

  let completedTransfers = 0;
  let totalSent = 0;
  let lastTransferAt: string | null = null;

  for (const row of rows) {
    const tx = safelyDecryptTransaction(row, "getTransferRecipientProfile");
    if (!tx) continue;
    if (tx.type !== "TRANSFER" || tx.status !== "COMPLETED") continue;
    if (tx.fromUserId !== input.userId) continue;
    const metadata = normalizeMetadataRecord(tx.metadata);
    if (metadata.entry !== "DEBIT") continue;
    const txToAccount =
      typeof metadata.toAccount === "string" ? metadata.toAccount : "";
    const isSameRecipient =
      (input.toAccount && txToAccount === input.toAccount) ||
      (input.toUserId && tx.toUserId === input.toUserId);
    if (!isSameRecipient) continue;
    completedTransfers += 1;
    totalSent += Number(tx.amount || 0);
    if (!lastTransferAt) {
      lastTransferAt = tx.createdAt.toISOString();
    }
  }

  return {
    isKnownRecipient: completedTransfers > 0,
    completedTransfers,
    totalSent: roundMoney(totalSent),
    lastTransferAt,
  };
};

const getTransferBehaviorProfile = async (input: {
  userId: string;
  toAccount: string;
  amount: number;
}): Promise<TransferBehaviorProfile> => {
  const since90d = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const similarAmountTolerance = Math.max(5, Math.min(75, input.amount * 0.25));

  const rows = await prisma.auditLog.findMany({
    where: {
      userId: input.userId,
      action: "FUNDS_FLOW_EVENT",
      createdAt: { gte: since90d },
    },
    orderBy: { createdAt: "desc" },
    take: 400,
    select: {
      id: true,
      actor: true,
      userId: true,
      ipAddress: true,
      createdAt: true,
      metadata: true,
    },
  });

  let recentReviewCount30d = 0;
  let recentBlockedCount30d = 0;
  let recentPendingOtpCount7d = 0;
  let completedOutflowSum90d = 0;
  let completedOutflowCount90d = 0;
  let maxCompletedOutflow90d = 0;
  let similarFlaggedAmountCount90d = 0;
  let sameRecipientFlaggedCount90d = 0;
  let recentInboundAmount24h = 0;
  let recentAdminTopUpAmount24h = 0;
  let recentSelfDepositAmount24h = 0;
  let smallProbeCount24h = 0;
  let smallProbeTotal24h = 0;
  let sameRecipientSmallProbeCount24h = 0;
  let newRecipientSmallProbeCount24h = 0;
  const distinctSmallProbeRecipients24h = new Set<string>();
  const since24hMs = Date.now() - 24 * 60 * 60 * 1000;

  for (const row of rows) {
    const event = toFundsFlowDatasetRow(row);
    if (
      !event ||
      (event.channel !== "WALLET_TRANSFER" &&
        event.channel !== "WALLET_DEPOSIT" &&
        event.channel !== "ADMIN_TOPUP")
    ) {
      continue;
    }

    const createdAtMs = new Date(event.createdAt).getTime();
    if (
      createdAtMs >= since24hMs &&
      event.lifecycle === "COMPLETED" &&
      event.direction === "INFLOW"
    ) {
      recentInboundAmount24h += event.amount;
      if (event.sourceLabel === "ADMIN_TOPUP") {
        recentAdminTopUpAmount24h += event.amount;
      }
      if (event.sourceLabel === "SELF_DEPOSIT") {
        recentSelfDepositAmount24h += event.amount;
      }
    }

    if (event.channel !== "WALLET_TRANSFER" || event.direction !== "OUTFLOW") {
      continue;
    }

    const amountDelta = Math.abs(event.amount - input.amount);
    const sameRecipient =
      Boolean(input.toAccount) &&
      Boolean(event.toAccount) &&
      event.toAccount === input.toAccount;
    const isProbeSizedAmount =
      event.amount > 0 && event.amount <= TRANSFER_PROBE_SMALL_AMOUNT_MAX;
    const isProbeLifecycle =
      event.lifecycle === "COMPLETED" ||
      event.lifecycle === "PENDING_OTP" ||
      event.lifecycle === "REVIEW_REQUIRED" ||
      event.lifecycle === "BLOCKED";

    if (event.lifecycle === "COMPLETED") {
      completedOutflowSum90d += event.amount;
      completedOutflowCount90d += 1;
      if (event.amount > maxCompletedOutflow90d) {
        maxCompletedOutflow90d = event.amount;
      }
    }

    if (createdAtMs >= since24hMs && isProbeLifecycle && isProbeSizedAmount) {
      smallProbeCount24h += 1;
      smallProbeTotal24h += event.amount;
      if (event.toAccount) {
        distinctSmallProbeRecipients24h.add(event.toAccount);
      }
      if (sameRecipient) {
        sameRecipientSmallProbeCount24h += 1;
      }
      if (event.recipientKnown === false) {
        newRecipientSmallProbeCount24h += 1;
      }
    }

    if (
      createdAtMs >= since30d.getTime() &&
      event.lifecycle === "REVIEW_REQUIRED"
    ) {
      recentReviewCount30d += 1;
    }
    if (createdAtMs >= since30d.getTime() && event.lifecycle === "BLOCKED") {
      recentBlockedCount30d += 1;
    }
    if (createdAtMs >= since7d.getTime() && event.lifecycle === "PENDING_OTP") {
      recentPendingOtpCount7d += 1;
    }

    if (
      (event.lifecycle === "REVIEW_REQUIRED" ||
        event.lifecycle === "BLOCKED") &&
      amountDelta <= similarAmountTolerance
    ) {
      similarFlaggedAmountCount90d += 1;
    }
    if (
      sameRecipient &&
      (event.lifecycle === "REVIEW_REQUIRED" || event.lifecycle === "BLOCKED")
    ) {
      sameRecipientFlaggedCount90d += 1;
    }
  }

  const probeThenLargeRiskScore = clamp(
    (input.amount >= TRANSFER_PROBE_LARGE_ESCALATION_MIN_AMOUNT ? 0.35 : 0) +
      Math.min(0.3, smallProbeCount24h * 0.08) +
      Math.min(0.15, distinctSmallProbeRecipients24h.size * 0.05) +
      Math.min(0.2, sameRecipientSmallProbeCount24h * 0.1) +
      Math.min(0.15, newRecipientSmallProbeCount24h * 0.05),
    0,
    0.99,
  );
  const rapidCashOutRiskScore = clamp(
    (recentInboundAmount24h > 0 &&
    input.amount >= Math.max(500, recentInboundAmount24h * 0.7)
      ? 0.45
      : 0) +
      (recentInboundAmount24h > 0 &&
      input.amount >= Math.max(1000, recentInboundAmount24h * 0.9)
        ? 0.2
        : 0) +
      (recentAdminTopUpAmount24h > 0 &&
      input.amount >= Math.max(1000, recentAdminTopUpAmount24h * 0.75)
        ? 0.25
        : 0) +
      (recentSelfDepositAmount24h > 0 &&
      input.amount >= Math.max(1000, recentSelfDepositAmount24h * 0.85)
        ? 0.15
        : 0),
    0,
    0.99,
  );

  return {
    recentReviewCount30d,
    recentBlockedCount30d,
    recentPendingOtpCount7d,
    averageCompletedOutflow90d:
      completedOutflowCount90d > 0
        ? roundMoney(completedOutflowSum90d / completedOutflowCount90d)
        : 0,
    maxCompletedOutflow90d: roundMoney(maxCompletedOutflow90d),
    similarFlaggedAmountCount90d,
    sameRecipientFlaggedCount90d,
    recentInboundAmount24h: roundMoney(recentInboundAmount24h),
    recentAdminTopUpAmount24h: roundMoney(recentAdminTopUpAmount24h),
    recentSelfDepositAmount24h: roundMoney(recentSelfDepositAmount24h),
    smallProbeCount24h,
    smallProbeTotal24h: roundMoney(smallProbeTotal24h),
    distinctSmallProbeRecipients24h: distinctSmallProbeRecipients24h.size,
    sameRecipientSmallProbeCount24h,
    newRecipientSmallProbeCount24h,
    probeThenLargeRiskScore: Number(probeThenLargeRiskScore.toFixed(3)),
    rapidCashOutRiskScore: Number(rapidCashOutRiskScore.toFixed(3)),
  };
};

const evaluateTransferStepUpPolicy = async (input: {
  userId: string;
  amount: number;
  currency: string;
  toAccount?: string | null;
}) => {
  const now = Date.now();
  const fundsFlowWindowMinutes = Math.max(
    SMALL_TRANSFER_BURST_WINDOW_MINUTES,
    CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES,
    CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES,
  );
  const since = new Date(now - fundsFlowWindowMinutes * 60 * 1000);
  const rows = await prisma.auditLog.findMany({
    where: {
      action: "FUNDS_FLOW_EVENT",
      userId: input.userId,
      createdAt: { gte: since },
    },
    orderBy: { createdAt: "desc" },
  });

  let completedOutflowWindow = 0;
  let recentLargeCompletedCount = 0;
  let latestLargeCompletedAt: Date | null = null;
  let recentSmallTransferCount = 0;
  let recentSmallTransferSameRecipientCount = 0;
  let latestSmallTransferAt: Date | null = null;
  const largeTransferSince = new Date(
    now - CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_SECONDS * 1000,
  ).getTime();
  const smallTransferBurstSince = new Date(
    now - SMALL_TRANSFER_BURST_WINDOW_MINUTES * 60 * 1000,
  ).getTime();

  for (const row of rows) {
    const event = toFundsFlowDatasetRow(row);
    if (!event) continue;
    if (
      event.channel !== "WALLET_TRANSFER" ||
      event.lifecycle !== "COMPLETED" ||
      event.direction !== "OUTFLOW" ||
      event.currency !== input.currency
    ) {
      continue;
    }

    const txAmount = Number(event.amount || 0);
    const isSmallTransfer =
      txAmount > 0 && txAmount <= TRANSFER_PROBE_SMALL_AMOUNT_MAX;
    const sameRecipient =
      Boolean(input.toAccount) &&
      Boolean(event.toAccount) &&
      event.toAccount === input.toAccount;
    completedOutflowWindow += txAmount;
    if (
      txAmount > TRANSFER_FACE_ID_THRESHOLD &&
      row.createdAt.getTime() >= largeTransferSince
    ) {
      recentLargeCompletedCount += 1;
      if (
        !latestLargeCompletedAt ||
        row.createdAt.getTime() > latestLargeCompletedAt.getTime()
      ) {
        latestLargeCompletedAt = row.createdAt;
      }
    }
    if (
      row.createdAt.getTime() >= smallTransferBurstSince &&
      isSmallTransfer &&
      (event.lifecycle === "COMPLETED" ||
        event.lifecycle === "PENDING_OTP" ||
        event.lifecycle === "OTP_VERIFIED" ||
        event.lifecycle === "REVIEW_REQUIRED" ||
        event.lifecycle === "BLOCKED")
    ) {
      recentSmallTransferCount += 1;
      if (sameRecipient) {
        recentSmallTransferSameRecipientCount += 1;
      }
      if (
        !latestSmallTransferAt ||
        row.createdAt.getTime() > latestSmallTransferAt.getTime()
      ) {
        latestSmallTransferAt = row.createdAt;
      }
    }
  }

  completedOutflowWindow = roundMoney(completedOutflowWindow);
  const projectedOutflowWindow = roundMoney(
    completedOutflowWindow + input.amount,
  );

  let faceIdRequired = input.amount > TRANSFER_FACE_ID_THRESHOLD;
  let faceIdReason: string | null =
    input.amount > TRANSFER_FACE_ID_THRESHOLD
      ? `Single transfers above ${formatMoneyAmount(
          input.currency,
          TRANSFER_FACE_ID_THRESHOLD,
        )} require FaceID verification.`
      : null;

  if (!faceIdRequired && projectedOutflowWindow >= TRANSFER_FACE_ID_THRESHOLD) {
    faceIdRequired = true;
    faceIdReason = `Your total outgoing transfers in the last ${CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES} minutes would reach ${formatMoneyAmount(
      input.currency,
      projectedOutflowWindow,
    )}, so FaceID verification is required.`;
  }

  const shouldBlockContinuousLargeTransfer =
    input.amount > TRANSFER_FACE_ID_THRESHOLD &&
    recentLargeCompletedCount >= CONTINUOUS_LARGE_TRANSFER_BLOCK_COUNT;
  const shouldBlockSmallTransferBurst =
    input.amount > 0 &&
    input.amount <= TRANSFER_PROBE_SMALL_AMOUNT_MAX &&
    (recentSmallTransferCount >= SMALL_TRANSFER_BURST_COUNT ||
      recentSmallTransferSameRecipientCount >=
        SMALL_TRANSFER_BURST_SAME_RECIPIENT_COUNT);
  const blockedUntilDate =
    shouldBlockContinuousLargeTransfer && latestLargeCompletedAt
      ? new Date(
          latestLargeCompletedAt.getTime() +
            CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_SECONDS * 1000,
        )
      : shouldBlockSmallTransferBurst && latestSmallTransferAt
        ? new Date(
            latestSmallTransferAt.getTime() +
              SMALL_TRANSFER_BURST_BLOCK_MINUTES * 60 * 1000,
          )
        : null;
  const retryAfterSeconds = blockedUntilDate
    ? Math.max(1, Math.ceil((blockedUntilDate.getTime() - Date.now()) / 1000))
    : null;
  const blockReason = shouldBlockContinuousLargeTransfer
    ? `Another transfer above ${formatMoneyAmount(
        input.currency,
        TRANSFER_FACE_ID_THRESHOLD,
      )} was completed less than ${formatRetryWait(
        CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_SECONDS,
      )} ago. Please wait ${formatRetryWait(
        retryAfterSeconds ?? CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_SECONDS,
      )} before sending another high-value transfer.`
    : shouldBlockSmallTransferBurst
      ? `Too many small transfers were attempted in the last ${SMALL_TRANSFER_BURST_WINDOW_MINUTES} minutes. Please wait ${formatRetryWait(
          retryAfterSeconds ?? SMALL_TRANSFER_BURST_BLOCK_MINUTES * 60,
        )} before sending another small transfer.`
      : null;

  return {
    faceIdRequired,
    faceIdReason,
    rollingOutflowAmount: projectedOutflowWindow,
    recentLargeCompletedCount,
    shouldBlockContinuousLargeTransfer,
    shouldBlockSmallTransferBurst,
    recentSmallTransferCount,
    recentSmallTransferSameRecipientCount,
    blockReason,
    blockedUntil: blockedUntilDate?.toISOString() || null,
    retryAfterSeconds,
  } satisfies TransferStepUpPolicy;
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
  const location = normalizeLocationLabelValue(input.location);
  if (location) return location;
  const ipAddress = normalizeIpAddress(input.ipAddress);
  if (!ipAddress) return "Unknown location";
  if (ipAddress === "127.0.0.1") return "Local device";
  if (isPrivateOrLoopbackIpAddress(ipAddress)) return "Private network";
  return `IP ${ipAddress}`;
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

const isSyntheticAiLoginEvent = (event: LoginEventEntity) => {
  if (event.id.startsWith("ai-login-")) {
    return true;
  }

  const metadata =
    event.metadata && typeof event.metadata === "object"
      ? (event.metadata as Record<string, unknown>)
      : null;

  if (!metadata) {
    return false;
  }

  return (
    typeof metadata.requestKey === "string" &&
    !("aiResult" in metadata) &&
    !("deviceContext" in metadata)
  );
};

const isFallbackMonitoringLoginEvent = (event: LoginEventEntity) => {
  const metadata =
    event.metadata && typeof event.metadata === "object"
      ? (event.metadata as Record<string, unknown>)
      : null;
  const aiResult =
    metadata?.aiResult && typeof metadata.aiResult === "object"
      ? (metadata.aiResult as Record<string, unknown>)
      : null;
  if (!aiResult) return false;

  const monitoringOnly = Boolean(aiResult.monitoringOnly);
  const modelSource =
    typeof aiResult.modelSource === "string" ? aiResult.modelSource : "";
  const reasons = Array.isArray(aiResult.reasons)
    ? aiResult.reasons.filter(
        (reason): reason is string => typeof reason === "string",
      )
    : [];

  return (
    monitoringOnly &&
    (modelSource === "fallback" ||
      reasons.some((reason) =>
        reason.toLowerCase().includes("ai monitoring unavailable"),
      ))
  );
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

const formatCardNumberGroups = (digits: string) =>
  digits
    .replace(/\D/g, "")
    .replace(/(.{4})/g, "$1 ")
    .trim();

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
  aiMonitoring?: AnomalyResponse;
  transferAdvisory?: TransferSafetyAdvisory | null;
}) => {
  return prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    const senderWallet = await tx.wallet.findFirst({
      where: { userId: input.senderUserId },
    });
    if (!senderWallet) throw new Error("SENDER_WALLET_NOT_FOUND");
    const senderBalanceBefore = Number(senderWallet.balance);

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

    const debitResult = await tx.wallet.updateMany({
      where: {
        id: senderWallet.id,
        balance: {
          gte: new Prisma.Decimal(input.amount),
        },
      },
      data: { balance: { decrement: input.amount } },
    });
    if (debitResult.count !== 1) {
      throw new Error("INSUFFICIENT_BALANCE");
    }
    await tx.wallet.update({
      where: { id: receiverWallet.id },
      data: { balance: { increment: input.amount } },
    });
    const senderWalletAfter = await tx.wallet.findUnique({
      where: { id: senderWallet.id },
      select: { balance: true },
    });
    const receiverWalletAfter = await tx.wallet.findUnique({
      where: { id: receiverWallet.id },
      select: { balance: true },
    });
    const senderBalanceAfter = senderWalletAfter
      ? Number(senderWalletAfter.balance)
      : Math.max(senderBalanceBefore - input.amount, 0);
    const receiverBalanceAfter = receiverWalletAfter
      ? Number(receiverWalletAfter.balance)
      : input.amount;

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
                transferAdvisory: input.transferAdvisory || undefined,
                aiMonitoring: input.aiMonitoring
                  ? buildStoredAiMonitoring(input.aiMonitoring)
                  : undefined,
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
              transferAdvisory: input.transferAdvisory
                ? {
                    ...input.transferAdvisory,
                    perspective: "receiver_credit",
                  }
                : undefined,
              aiMonitoring: input.aiMonitoring
                ? {
                    ...buildStoredAiMonitoring(input.aiMonitoring),
                    perspective: "receiver_credit",
                  }
                : undefined,
            },
          },
        }),
      },
    });

    return {
      transaction: debitTx,
      reconciliationId,
      receiverAccountNumber: input.receiverAccountNumber,
      senderBalance: senderBalanceAfter,
      receiverBalance: receiverBalanceAfter,
      currency: senderWallet.currency,
    };
  });
};

const verifyTransferPinForUser = async (
  user: UserEntity,
  transferPin: string,
) => {
  const normalizedPin = transferPin.replace(/\D/g, "");
  if (!/^\d{6}$/.test(normalizedPin)) {
    return false;
  }

  const transferPinMetadata = getInternalTransferPinMetadata(user.metadata);
  const storedHash =
    transferPinMetadata && typeof transferPinMetadata.pinHash === "string"
      ? transferPinMetadata.pinHash
      : "";
  if (!storedHash) {
    return false;
  }

  return verifyPassword(normalizedPin, storedHash);
};

const qualifiesForStoredTransferPurposeException = (input: {
  aiResult: AnomalyResponse;
  note?: string | null;
  accountProfile?: ResolvedAccountProfile | null;
}) => {
  const note = typeof input.note === "string" ? input.note.trim() : "";
  const accountCategory =
    input.accountProfile?.category ||
    (input.aiResult.accountCategory === "business" ? "BUSINESS" : "PERSONAL");
  if (accountCategory !== "PERSONAL") {
    return false;
  }
  if (getSuspiciousTransferNoteReasons(note).length > 0) {
    return false;
  }
  if (getLegitimateTransferPurposeTags(note).length === 0) {
    return false;
  }
  if (
    input.aiResult.reasons.some((reason) =>
      /known scam pattern|otp theft|remote access|refund scam|tax scam|investment scam/i.test(
        reason,
      ),
    )
  ) {
    return false;
  }
  const analysisSignals =
    input.aiResult.analysisSignals &&
    typeof input.aiResult.analysisSignals === "object" &&
    !Array.isArray(input.aiResult.analysisSignals)
      ? input.aiResult.analysisSignals
      : null;
  const probeThenLargeRiskScore = Number(
    analysisSignals?.probeThenLargeRiskScore ??
      analysisSignals?.probe_then_large_risk_score ??
      0,
  );
  const rapidCashOutRiskScore = Number(
    analysisSignals?.rapidCashOutRiskScore ??
      analysisSignals?.rapid_cash_out_risk_score ??
      0,
  );
  const smallProbeCount24h = Number(
    analysisSignals?.smallProbeCount24h ??
      analysisSignals?.small_probe_count_24h ??
      0,
  );
  return (
    Number.isFinite(probeThenLargeRiskScore) &&
    probeThenLargeRiskScore < 0.7 &&
    Number.isFinite(rapidCashOutRiskScore) &&
    rapidCashOutRiskScore < 0.7 &&
    Number.isFinite(smallProbeCount24h) &&
    smallProbeCount24h === 0
  );
};

const resolveEffectiveTransferFinalAction = (
  aiResult: AnomalyResponse,
  options?: {
    note?: string | null;
    accountProfile?: ResolvedAccountProfile | null;
  },
) => {
  const analysisSignals =
    aiResult.analysisSignals &&
    typeof aiResult.analysisSignals === "object" &&
    !Array.isArray(aiResult.analysisSignals)
      ? aiResult.analysisSignals
      : null;
  if (
    analysisSignals?.aiPurposeExceptionApplied === true &&
    aiResult.finalAction === "HOLD_REVIEW"
  ) {
    return "REQUIRE_OTP_FACE_ID" as const;
  }
  if (
    aiResult.finalAction === "HOLD_REVIEW" &&
    qualifiesForStoredTransferPurposeException({
      aiResult,
      note: options?.note,
      accountProfile: options?.accountProfile,
    })
  ) {
    return "REQUIRE_OTP_FACE_ID" as const;
  }
  return aiResult.finalAction || "ALLOW";
};

const verifyRequiredTransferFaceId = async (input: {
  senderUser: UserEntity;
  transferFaceEnrollment?: FaceIdEnrollmentSubmission | null;
}) => {
  const storedFaceId = getInternalFaceIdMetadata(input.senderUser.metadata);
  const storedDescriptor =
    storedFaceId && typeof storedFaceId.descriptor === "string"
      ? storedFaceId.descriptor
      : "";
  const storedDescriptorIsLegacy =
    !!storedDescriptor &&
    !storedDescriptor.startsWith(FACE_ID_DESCRIPTOR_V2_PREFIX);
  if (storedFaceId?.enabled !== true || !storedDescriptor) {
    throw new Error("TRANSFER_FACE_ID_ENROLLMENT_REQUIRED");
  }
  if (!input.transferFaceEnrollment) {
    throw new Error("TRANSFER_FACE_ID_VERIFICATION_REQUIRED");
  }
  try {
    await verifyFaceIdSubmissionStrict(
      input.transferFaceEnrollment,
      storedDescriptor,
    );
  } catch (err) {
    if (err instanceof Error && err.message === "FACE_ID_MISMATCH") {
      if (storedDescriptorIsLegacy) {
        throw new Error("TRANSFER_FACE_ID_LEGACY_REENROLL_REQUIRED");
      }
    }
    throw err;
  }
};

const completeAuthorizedTransfer = async (input: {
  req: Request;
  senderUser: UserEntity;
  senderUserId: string;
  amount: number;
  toAccount: string;
  toUserId: string;
  note: string;
  transferAiResult: AnomalyResponse;
  transferAdvisory: TransferSafetyAdvisory | null;
  transferSpendProfile?: Record<string, unknown>;
  transferRequestKey?: string | null;
  verificationMethod: "pin" | "otp";
  verifiedChallengeId?: string | null;
  faceIdRequired: boolean;
  faceIdReason?: string | null;
  transferFaceEnrollment?: FaceIdEnrollmentSubmission | null;
  faceIdPreverified?: boolean;
}) => {
  if (!input.amount || (!input.toAccount && !input.toUserId)) {
    throw new Error("INVALID_TRANSFER_PAYLOAD");
  }

  const effectiveFinalAction = resolveEffectiveTransferFinalAction(
    input.transferAiResult,
    {
      note: input.note,
      accountProfile: buildResolvedAccountProfile(input.senderUser.metadata),
    },
  );
  if (effectiveFinalAction === "HOLD_REVIEW") {
    throw new Error("TRANSFER_MANUAL_REVIEW_REQUIRED");
  }
  if (
    input.verificationMethod === "pin" &&
    (effectiveFinalAction === "REQUIRE_OTP" ||
      effectiveFinalAction === "REQUIRE_OTP_FACE_ID")
  ) {
    throw new Error("TRANSFER_OTP_VERIFICATION_REQUIRED");
  }

  const effectiveFaceIdRequired =
    input.faceIdRequired || effectiveFinalAction === "REQUIRE_OTP_FACE_ID";
  if (effectiveFaceIdRequired && input.faceIdPreverified !== true) {
    await verifyRequiredTransferFaceId({
      senderUser: input.senderUser,
      transferFaceEnrollment: input.transferFaceEnrollment,
    });
  }

  const userRepository = createUserRepository();
  const context = await resolveTransferContext({
    senderUserId: input.senderUserId,
    toUserId: input.toUserId,
    toAccount: input.toAccount,
    amount: input.amount,
    note: input.note,
  });
  const receiverUser = await userRepository.findValidatedById(
    context.resolvedReceiverUserId,
  );
  if (!receiverUser) {
    throw new Error("RECIPIENT_NOT_FOUND");
  }

  const transferResult = await executeTransfer({
    senderUserId: input.senderUserId,
    resolvedReceiverUserId: context.resolvedReceiverUserId,
    amount: context.amount,
    note: context.note,
    senderAccountNumber: context.senderAccountNumber,
    receiverAccountNumber: context.receiverAccountNumber,
    receiverWalletByAccount: context.receiverWalletByAccount,
    aiMonitoring: input.transferAiResult,
    transferAdvisory: input.transferAdvisory,
  });
  const effectiveRequestKey =
    input.transferRequestKey ||
    input.transferAiResult.requestKey ||
    input.transferAdvisory?.requestKey ||
    null;
  const auditClientMetadata = buildAuditClientMetadata(
    input.req,
    input.req.body,
  );

  await logAuditEvent({
    actor: input.req.user?.email,
    userId: input.senderUserId,
    action:
      input.verificationMethod === "otp"
        ? "TRANSFER_OTP_VERIFIED"
        : "TRANSFER_PIN_VERIFIED",
    details: {
      challengeId: input.verifiedChallengeId || null,
      transactionId: transferResult.transaction.id,
      txRiskLevel: input.transferAiResult.riskLevel,
      txScore: input.transferAiResult.score,
      transferAdvisorySeverity: input.transferAdvisory?.severity || null,
    },
    metadata: {
      ...auditClientMetadata,
      requestKey: effectiveRequestKey,
      spendProfile: input.transferSpendProfile,
      transferAdvisory: input.transferAdvisory || undefined,
      aiMonitoring: buildStoredAiMonitoring(input.transferAiResult),
      verificationMethod: input.verificationMethod,
    },
    ipAddress: getRequestIp(input.req),
  });

  await logFundsFlowEvent({
    actor: input.req.user?.email,
    userId: input.senderUserId,
    ipAddress: getRequestIp(input.req),
    channel: "WALLET_TRANSFER",
    lifecycle: "COMPLETED",
    direction: "OUTFLOW",
    amount: context.amount,
    currency: transferResult.currency,
    fromAccount: context.senderAccountNumber,
    toAccount: context.receiverAccountNumber,
    fromUserId: input.senderUserId,
    toUserId: context.resolvedReceiverUserId,
    transactionId: transferResult.transaction.id,
    reconciliationId: transferResult.reconciliationId,
    challengeId: input.verifiedChallengeId || null,
    requestKey: effectiveRequestKey,
    note: context.note,
    riskLevel: input.transferAiResult.riskLevel,
    riskScore: input.transferAiResult.score,
    transferAdvisory: input.transferAdvisory || null,
    aiMonitoring: input.transferAiResult,
    balanceBefore: transferResult.senderBalance + context.amount,
    balanceAfter: transferResult.senderBalance,
    sourceLabel:
      input.verificationMethod === "otp"
        ? "TRANSFER_CONFIRMED"
        : "TRANSFER_PIN_CONFIRMED",
  });

  await logFundsFlowEvent({
    actor: input.req.user?.email,
    userId: context.resolvedReceiverUserId,
    ipAddress: getRequestIp(input.req),
    channel: "WALLET_TRANSFER",
    lifecycle: "COMPLETED",
    direction: "INFLOW",
    amount: context.amount,
    currency: transferResult.currency,
    fromAccount: context.senderAccountNumber,
    toAccount: context.receiverAccountNumber,
    fromUserId: input.senderUserId,
    toUserId: context.resolvedReceiverUserId,
    transactionId: transferResult.transaction.id,
    reconciliationId: transferResult.reconciliationId,
    challengeId: input.verifiedChallengeId || null,
    requestKey: effectiveRequestKey,
    note: context.note,
    riskLevel: input.transferAiResult.riskLevel,
    riskScore: input.transferAiResult.score,
    transferAdvisory: input.transferAdvisory
      ? {
          ...input.transferAdvisory,
          severity:
            input.transferAdvisory.severity === "blocked"
              ? "warning"
              : input.transferAdvisory.severity,
        }
      : null,
    aiMonitoring: input.transferAiResult,
    balanceBefore: transferResult.receiverBalance - context.amount,
    balanceAfter: transferResult.receiverBalance,
    sourceLabel: "TRANSFER_RECEIVED",
  });

  notifyBalanceChange({
    to: input.senderUser.email,
    recipientName: getRecipientName(input.senderUser),
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

  runAsyncSideEffect("monitorBudgetPlanAfterDebit", () =>
    monitorBudgetPlanAfterDebit({
      userId: input.senderUserId,
      amount: context.amount,
      currency: transferResult.currency,
      description:
        transferResult.transaction.description ??
        `Transfer to ${transferResult.receiverAccountNumber}`,
      occurredAt: transferResult.transaction.createdAt.toISOString(),
      actor: input.req.user?.email || input.senderUser.email,
      ipAddress: getRequestIp(input.req),
    }),
  );
  runAsyncSideEffect("runBudgetAssistantAutomation:debit", () =>
    runBudgetAssistantAutomation({
      userId: input.senderUserId,
      actor: input.req.user?.email || input.senderUser.email,
      ipAddress: getRequestIp(input.req),
      trigger: "debit",
    }),
  );

  await userRepository.updateMetadata(
    input.senderUserId,
    upsertRecentTransferRecipientMetadata(input.senderUser.metadata, {
      accountNumber: context.receiverAccountNumber,
      holderName: getRecipientName(receiverUser),
      userId: context.resolvedReceiverUserId,
      occurredAt: transferResult.transaction.createdAt.toISOString(),
    }),
  );

  notifyBalanceChange({
    to: receiverUser.email,
    recipientName: getRecipientName(receiverUser),
    direction: "credit",
    amount: context.amount,
    balance: transferResult.receiverBalance,
    currency: transferResult.currency,
    transactionType: "TRANSFER",
    description: context.note || `Receive from ${context.senderAccountNumber}`,
    occurredAt: transferResult.transaction.createdAt.toISOString(),
    counterpartyLabel: getRecipientName(input.senderUser),
  });

  invalidateUserResponseCache(input.senderUserId, [
    "auth",
    "wallet",
    "transactions",
    "security",
  ]);
  invalidateUserResponseCache(context.resolvedReceiverUserId, [
    "wallet",
    "transactions",
  ]);

  return {
    reconciliationId: transferResult.reconciliationId,
    anomaly: input.transferAiResult,
    transaction: {
      id: transferResult.transaction.id,
      amount: transferResult.transaction.amount,
      type: transferResult.transaction.type,
      description: transferResult.transaction.description ?? undefined,
      createdAt: transferResult.transaction.createdAt.toISOString(),
      toAccount: transferResult.receiverAccountNumber,
    },
  };
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

let aiServiceSpawnRequested = false;

const probeAiServiceHealth = async () => {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    const response = await fetch(`${AI_URL}/health`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!response.ok) return false;
    const data = (await response.json().catch(() => null)) as {
      service?: unknown;
    } | null;
    return data?.service === "ai";
  } catch {
    return false;
  }
};

const ensureLocalAiService = async () => {
  if (!AUTO_START_LOCAL_AI_SERVICE || !isLocalAiServiceUrl(AI_URL)) {
    return;
  }
  if (await probeAiServiceHealth()) {
    return;
  }
  await sleep(2000);
  if (await probeAiServiceHealth()) {
    return;
  }
  if (aiServiceSpawnRequested) {
    return;
  }

  aiServiceSpawnRequested = true;
  try {
    const child = spawn(process.execPath, ["dev.mjs"], {
      cwd: AI_SERVICE_WORKDIR,
      env: process.env,
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    });
    child.unref();
    console.log(
      `[ai-service] Starting local AI runtime from ${AI_SERVICE_WORKDIR}...`,
    );

    for (let attempt = 1; attempt <= 8; attempt += 1) {
      await sleep(1000);
      if (await probeAiServiceHealth()) {
        console.log(`[ai-service] Local AI runtime is ready at ${AI_URL}.`);
        return;
      }
    }
    console.warn(
      `[ai-service] Local AI runtime did not become healthy at ${AI_URL}.`,
    );
  } catch (err) {
    console.warn("[ai-service] Failed to auto-start local AI runtime.", err);
  }
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

app.get("/ai/overview", requireAuth, async (_req, res) => {
  const fallback: AiOverviewResponse = {
    status: {
      modelLoaded: false,
      modelVersion: null,
      modelSource: "unavailable",
      txModelLoaded: false,
      txModelVersion: null,
      txModelSource: "unavailable",
      mongoConnected: false,
      authMode: null,
    },
    stats: {
      windowHours: 24,
      loginRiskCounts: { LOW: 0, MEDIUM: 0, HIGH: 0 },
      txRiskCounts: { LOW: 0, MEDIUM: 0, HIGH: 0 },
      combinedRiskCounts: { LOW: 0, MEDIUM: 0, HIGH: 0 },
    },
  };

  try {
    const [statusResp, statsResp] = await Promise.all([
      fetch(`${AI_URL}/ai/status`, {
        headers: buildAiServiceHeaders(),
      }),
      fetch(`${AI_URL}/ai/admin/stats`, {
        headers: buildAiServiceHeaders(),
      }),
    ]);

    const statusData = (await statusResp.json().catch(() => null)) as Record<
      string,
      unknown
    > | null;
    const statsData = (await statsResp.json().catch(() => null)) as Record<
      string,
      unknown
    > | null;

    return res.json({
      status: {
        modelLoaded: Boolean(statusData?.model_loaded),
        modelVersion:
          typeof statusData?.model_version === "string"
            ? statusData.model_version
            : null,
        modelSource:
          typeof statusData?.model_source === "string"
            ? statusData.model_source
            : null,
        txModelLoaded: Boolean(statusData?.tx_model_loaded),
        txModelVersion:
          typeof statusData?.tx_model_version === "string"
            ? statusData.tx_model_version
            : null,
        txModelSource:
          typeof statusData?.tx_model_source === "string"
            ? statusData.tx_model_source
            : null,
        mongoConnected: Boolean(
          statusData?.postgres_connected ?? statusData?.mongo_connected,
        ),
        authMode:
          typeof statusData?.auth_mode === "string"
            ? statusData.auth_mode
            : null,
      },
      stats: {
        windowHours:
          typeof statsData?.window_hours === "number"
            ? statsData.window_hours
            : 24,
        loginRiskCounts:
          statsData?.risk_counts && typeof statsData.risk_counts === "object"
            ? (statsData.risk_counts as Record<string, number>)
            : fallback.stats.loginRiskCounts,
        txRiskCounts:
          statsData?.tx_risk_counts &&
          typeof statsData.tx_risk_counts === "object"
            ? (statsData.tx_risk_counts as Record<string, number>)
            : fallback.stats.txRiskCounts,
        combinedRiskCounts:
          statsData?.combined_risk_counts &&
          typeof statsData.combined_risk_counts === "object"
            ? (statsData.combined_risk_counts as Record<string, number>)
            : fallback.stats.combinedRiskCounts,
      },
    } satisfies AiOverviewResponse);
  } catch (err) {
    console.warn("Cannot load AI overview from ai-service", err);
    return res.json(fallback);
  }
});

app.post("/ai/deposit-agent", requireAuth, async (req, res) => {
  const body = req.body as {
    goal?: unknown;
    currentBalance?: unknown;
    currency?: unknown;
    monthlyIncome?: unknown;
    monthlyExpenses?: unknown;
  };
  const goal = typeof body.goal === "string" ? body.goal.trim() : "";
  if (!goal) {
    return res.status(400).json({ error: "Goal is required" });
  }

  const plan = buildHeuristicDepositPlan({
    goal,
    currentBalance: Number(body.currentBalance || 0),
    currency:
      typeof body.currency === "string" && body.currency.trim()
        ? body.currency.trim().toUpperCase()
        : "USD",
    monthlyIncome: Number(body.monthlyIncome || 0),
    monthlyExpenses: Number(body.monthlyExpenses || 0),
  });

  return res.json(plan);
});

app.get("/ai/copilot-history", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userRecord = await prisma.user.findUnique({
    where: { id: userId },
    select: { metadata: true },
  });

  return res.json(readStoredCopilotWorkspaceFromMetadata(userRecord?.metadata));
});

app.put("/ai/copilot-history", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const body = req.body as {
    activeSessionId?: unknown;
    sessions?: unknown;
  };

  const nextWorkspace = sanitizeStoredCopilotWorkspace({
    activeSessionId: body.activeSessionId,
    sessions: body.sessions,
  });

  const currentUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { metadata: true },
  });
  const nextMetadata = isPlainObject(currentUser?.metadata)
    ? { ...currentUser.metadata }
    : {};
  nextMetadata.copilotWorkspace = nextWorkspace;
  delete nextMetadata.copilotSession;

  await prisma.user.update({
    where: { id: userId },
    data: { metadata: nextMetadata },
  });

  return res.json(nextWorkspace);
});

app.post("/ai/copilot-chat", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const body = req.body as {
    currency?: unknown;
    currentBalance?: unknown;
    monthlyIncome?: unknown;
    monthlyExpenses?: unknown;
    recentTransactions?: unknown;
    messages?: unknown;
  };

  const messages = Array.isArray(body.messages)
    ? body.messages.filter(
        (item): item is CopilotMessagePayload =>
          Boolean(item) &&
          typeof item === "object" &&
          (item as { role?: unknown }).role !== undefined &&
          typeof (item as { content?: unknown }).content === "string",
      )
    : [];

  const latestUserMessage = [...messages]
    .reverse()
    .find((message) => message.role === "user");
  if (!latestUserMessage?.content?.trim()) {
    return res.status(400).json({ error: "A user message is required" });
  }
  const language = detectCopilotLanguage(latestUserMessage.content);

  const currency =
    typeof body.currency === "string" && body.currency.trim()
      ? body.currency.trim().toUpperCase()
      : "USD";
  let sourceTruth = buildFallbackCopilotSourceTruthContext({
    preferredCurrency: currency,
  });
  try {
    sourceTruth = await buildCopilotSourceTruthContext({
      userId,
      preferredCurrency: currency,
    });
  } catch (err) {
    console.warn("Copilot source-truth context failed, using empty fallback", {
      userId,
      error: err instanceof Error ? err.message : String(err),
    });
  }
  const effectiveCurrency = sourceTruth.currency;

  const copilotBaseInput = {
    currency: effectiveCurrency,
    currentBalance: sourceTruth.currentBalance,
    monthlyIncome: sourceTruth.monthlyIncome,
    monthlyExpenses: sourceTruth.monthlyExpenses,
    recentTransactions: sourceTruth.recentTransactions,
    messages,
    language,
  };

  const intentClassification = await classifyCopilotIntent(copilotBaseInput);

  if (
    req.user?.sub &&
    intentClassification.intent === "transaction_review" &&
    isWeeklyTransactionReportIntent(latestUserMessage.content)
  ) {
    const weeklyReport = await buildWeeklyTransactionReportResponse({
      userId: req.user.sub,
      currency: effectiveCurrency,
      language,
    });
    return res.json(weeklyReport);
  }

  if (
    req.user?.sub &&
    intentClassification.intent === "transaction_review" &&
    isTodayTransactionReportIntent(latestUserMessage.content)
  ) {
    const todayReport = await buildTodayTransactionReportResponse({
      userId: req.user.sub,
      currency: effectiveCurrency,
      language,
    });
    return res.json(todayReport);
  }

  if (
    req.user?.sub &&
    intentClassification.intent === "transaction_review" &&
    isMonthlyTransactionReportIntent(latestUserMessage.content)
  ) {
    const monthlyReport = await buildMonthlyTransactionReportResponse({
      userId: req.user.sub,
      currency: effectiveCurrency,
      language,
    });
    return res.json(monthlyReport);
  }

  if (req.user?.sub && intentClassification.intent === "transaction_review") {
    const recentReview = await buildRecentTransactionReviewResponse({
      userId: req.user.sub,
      currency: effectiveCurrency,
      language,
    });
    return res.json(recentReview);
  }

  if (req.user?.sub && intentClassification.intent === "spending_analysis") {
    const spendingComparison = await buildSpendingComparisonResponse({
      userId: req.user.sub,
      currency: effectiveCurrency,
      language,
    });
    return res.json(spendingComparison);
  }

  if (req.user?.sub && intentClassification.intent === "budgeting_help") {
    const budgetResponse = await buildBudgetPlanCopilotResponse({
      req,
      userId: req.user.sub,
      currency: effectiveCurrency,
      language,
      messages,
      currentBalance: sourceTruth.currentBalance,
      monthlyIncome: sourceTruth.monthlyIncome,
      monthlyExpenses: sourceTruth.monthlyExpenses,
      recentTransactions: sourceTruth.recentTransactions,
    });
    return res.json(budgetResponse);
  }

  if (intentClassification.intent === "market_data") {
    const marketResponse = await buildLiveMarketCopilotResponse(
      latestUserMessage.content,
    );
    if (marketResponse) {
      return res.json(marketResponse);
    }
    return res.json(buildMarketDataUnavailableCopilotResponse({ language }));
  }

  if (intentClassification.intent === "anomaly_check") {
    const scamProtectionResponse = buildHeuristicScamProtectionResponse({
      latestMessage: latestUserMessage.content,
      language,
    });
    if (scamProtectionResponse) {
      return res.json(scamProtectionResponse);
    }
    if (req.user?.sub) {
      const anomalyReview = await buildTransactionAnomalyReviewResponse({
        userId: req.user.sub,
        currency: effectiveCurrency,
        language,
      });
      return res.json(anomalyReview);
    }
  }

  if (intentClassification.intent === "unsupported") {
    return res.json(buildUnsupportedCopilotResponse({ language }));
  }

  if (intentClassification.intent === "portfolio_analysis") {
    const liveMarketAnalysis = await buildPortfolioAnalysisWithLiveDataResponse(
      {
        latestMessage: latestUserMessage.content,
        language,
      },
    );
    if (liveMarketAnalysis) {
      return res.json(liveMarketAnalysis);
    }

    const deterministicMarketAnalysis =
      buildDeterministicPortfolioAnalysisResponse({
        latestMessage: latestUserMessage.content,
        language,
      });
    if (deterministicMarketAnalysis) {
      return res.json(deterministicMarketAnalysis);
    }
  }

  const copilotInput = {
    ...copilotBaseInput,
    classification: intentClassification,
  };

  const ollamaResult = await callOllamaCopilot(copilotInput);
  if (ollamaResult.status === "ok") {
    return res.json(ollamaResult.payload);
  }

  const openAiResult = await callOpenAiCopilot(copilotInput);
  if (openAiResult.status === "ok") {
    return res.json(openAiResult.payload);
  }
  if (
    ollamaResult.status === "error" &&
    (ollamaResult.code === "ollama_unreachable" ||
      ollamaResult.code === "ollama_timeout" ||
      ollamaResult.code === "ollama_model_not_found")
  ) {
    return res.json({
      reply: localizeCopilotText(
        language,
        "Local copilot chua san sang. Hay cai Ollama, tai model local, sau do khoi dong lai API. Trong luc do, app van co the tra loi cac luong co dinh va quote thi truong realtime.",
        "Local copilot is not ready yet. Install Ollama, pull a local model, then restart the API. Until then, the app can still answer fixed wallet and live quote flows.",
      ),
      topic: "ollama-setup-required",
      suggestedActions:
        language === "vi"
          ? [
              "Cai Ollama tu https://ollama.com/download",
              `Chay: ollama pull ${OLLAMA_MODEL || "qwen2.5:3b"}`,
              `Dat OLLAMA_MODEL=${OLLAMA_MODEL || "qwen2.5:3b"} trong file .env cua backend va khoi dong lai apps/api`,
            ]
          : [
              "Install Ollama from https://ollama.com/download",
              `Run: ollama pull ${OLLAMA_MODEL || "qwen2.5:3b"}`,
              `Set OLLAMA_MODEL=${OLLAMA_MODEL || "qwen2.5:3b"} in the backend .env file and restart apps/api`,
            ],
      suggestedDepositAmount: null,
      riskLevel: "low",
      confidence: 0.97,
      followUpQuestion: localizeCopilotText(
        language,
        "Sau khi Ollama chay xong, hay hoi lai va toi se xu ly cac cau hoi mo bang local AI.",
        "After Ollama is running, ask me again and I should handle open-ended questions locally.",
      ),
    } satisfies CopilotResponsePayload);
  }
  if (openAiResult.status === "error") {
    if (openAiResult.code === "insufficient_quota") {
      return res.json({
        reply: localizeCopilotText(
          language,
          "OpenAI copilot da duoc cau hinh, nhung project API nay hien khong con quota kha dung. Hay nap them credits hoac bat billing tren OpenAI, sau do khoi dong lai API neu can.",
          "OpenAI copilot is configured, but this API project has no usable quota right now. Add credits or enable billing in OpenAI, then restart the API if needed.",
        ),
        topic: "openai-quota-required",
        suggestedActions:
          language === "vi"
            ? [
                "Mo OpenAI Usage/Billing va nap credits cho project hien tai.",
                "Tao secret key moi sau khi billing da hoat dong neu key cu da bi lo.",
                "Tam thoi van dung live market quotes; chat tu do se hoat dong lai sau khi co quota.",
              ]
            : [
                "Open OpenAI Usage/Billing and add credits to the current project.",
                "Create a fresh secret key after billing is active if this key was exposed.",
                "Keep using live market quotes here; broader free-form chat will work again after quota is available.",
              ],
        suggestedDepositAmount: null,
        riskLevel: "medium",
        confidence: 0.98,
        followUpQuestion: localizeCopilotText(
          language,
          "Sau khi nap credits, hay hoi lai va toi se tra loi duoc ngoai cac luong co dinh.",
          "After you add credits, ask me again and I should answer outside the fixed wallet flows.",
        ),
      } satisfies CopilotResponsePayload);
    }
    if (openAiResult.code === "invalid_api_key") {
      return res.json({
        reply: localizeCopilotText(
          language,
          "OpenAI copilot da duoc bat trong code, nhung API key hien tai khong hop le. Hay thay OPENAI_API_KEY bang secret key moi hop le va khoi dong lai API server.",
          "OpenAI copilot is enabled in code, but the current API key is invalid. Replace OPENAI_API_KEY with a new valid secret key and restart the API server.",
        ),
        topic: "openai-key-invalid",
        suggestedActions:
          language === "vi"
            ? [
                "Tao secret key moi trong OpenAI Platform.",
                "Cap nhat OPENAI_API_KEY trong file .env cua backend.",
                "Khoi dong lai apps/api sau khi luu key moi.",
              ]
            : [
                "Create a new secret key in OpenAI Platform.",
                "Update OPENAI_API_KEY in the backend .env file.",
                "Restart apps/api after saving the new key.",
              ],
        suggestedDepositAmount: null,
        riskLevel: "medium",
        confidence: 0.98,
        followUpQuestion: localizeCopilotText(
          language,
          "Khi key da hop le, ban co muon toi test lai route copilot khong?",
          "Once the key is valid, do you want me to retest the copilot route?",
        ),
      } satisfies CopilotResponsePayload);
    }
  }

  const response = buildHeuristicCopilotResponse({
    currency: effectiveCurrency,
    currentBalance: sourceTruth.currentBalance,
    monthlyIncome: sourceTruth.monthlyIncome,
    monthlyExpenses: sourceTruth.monthlyExpenses,
    recentTransactions: sourceTruth.recentTransactions,
    latestMessage: latestUserMessage.content,
  });

  return res.json(response);
});

app.get("/auth/captcha/slider", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.json(buildSliderCaptchaChallenge());
});

app.get("/auth/face/challenge", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.json(buildFaceIdChallenge());
});

app.post("/auth/register", async (req, res) => {
  type RegisterReq = components["schemas"]["RegisterRequest"];
  const { captchaToken, captchaOffset } = readSliderCaptchaSubmission(req.body);
  const faceEnrollment = readFaceIdEnrollment(req.body);
  const parsed = registerSchema.safeParse(req.body as RegisterReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  if (!captchaToken || !Number.isFinite(captchaOffset)) {
    return res.status(400).json({ error: "Complete the slider captcha first" });
  }
  if (!faceEnrollment) {
    return res.status(400).json({
      error: "Complete FaceID enrollment before creating the account",
    });
  }

  const userRepository = createUserRepository();
  const email = normalizeEmail(parsed.data.email);

  try {
    const captchaVerified = verifySliderCaptchaSubmission(
      captchaToken,
      captchaOffset,
    );
    if (!captchaVerified) {
      return res
        .status(403)
        .json({ error: "Slider captcha verification failed" });
    }

    const verifiedFace = await verifyFaceIdSubmissionStrict(faceEnrollment);
    const faceVideoHash = faceEnrollment.videoEvidence
      ? crypto
          .createHash("sha256")
          .update(faceEnrollment.videoEvidence)
          .digest("hex")
      : null;

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
      metadata: setEffectiveAccountProfileMetadata(
        {
          ...(parsed.data.userName
            ? { userName: parsed.data.userName.trim() }
            : {}),
          faceId: {
            enabled: true,
            enrolledAt: new Date().toISOString(),
            challengeNonce: verifiedFace.challenge.nonce,
            challengeSteps: verifiedFace.challenge.steps,
            descriptor: faceEnrollment.descriptor,
            descriptorHash: crypto
              .createHash("sha256")
              .update(faceEnrollment.descriptor)
              .digest("hex"),
            livenessScore: faceEnrollment.livenessScore,
            motionScore: faceEnrollment.motionScore,
            eyeMotionScore: faceEnrollment.eyeMotionScore,
            faceCoverage: faceEnrollment.faceCoverage,
            sampleCount: faceEnrollment.sampleCount,
            previewImage: faceEnrollment.previewImage,
            videoEvidenceHash: faceVideoHash,
            videoDurationMs:
              typeof faceEnrollment.videoDurationMs === "number"
                ? Math.round(faceEnrollment.videoDurationMs)
                : null,
            videoMimeType: faceEnrollment.videoMimeType || null,
            antiSpoof: {
              spoofScore: verifiedFace.antiSpoof.spoofScore,
              confidence: verifiedFace.antiSpoof.confidence,
              riskLevel: verifiedFace.antiSpoof.riskLevel,
              reasons: verifiedFace.antiSpoof.reasons,
              modelSource: verifiedFace.antiSpoof.modelSource,
              modelVersion: verifiedFace.antiSpoof.modelVersion,
            },
            lastVerifiedAt: new Date().toISOString(),
          },
        },
        { category: "PERSONAL", tier: "STANDARD" },
        "register",
      ),
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

    runAsyncSideEffect("sendRegisterOtpEmail", () =>
      sendRegisterOtpEmail({
        to: email,
        recipientName: pendingUser.fullName || email.split("@")[0] || "User",
        otpCode: otpChallenge.otpCode,
        expiresInMinutes: REGISTER_OTP_TTL_MINUTES,
      }),
    );

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
    if (err instanceof Error && err.message === "CAPTCHA_EXPIRED") {
      return res
        .status(400)
        .json({ error: "Slider captcha expired. Please drag again." });
    }
    if (err instanceof Error && err.message === "INVALID_CAPTCHA") {
      return res.status(400).json({ error: "Invalid slider captcha payload" });
    }
    if (err instanceof Error && err.message === "FACE_ID_EXPIRED") {
      return res
        .status(400)
        .json({ error: "FaceID challenge expired. Scan again." });
    }
    if (err instanceof Error && err.message === "INVALID_FACE_ID") {
      return res
        .status(400)
        .json({ error: "Invalid FaceID challenge payload" });
    }
    if (err instanceof Error && err.message === "INVALID_FACE_ID_DESCRIPTOR") {
      return res.status(400).json({ error: "Invalid FaceID biometric sample" });
    }
    if (err instanceof Error && err.message === "FACE_ID_STEP_MISMATCH") {
      return res
        .status(400)
        .json({ error: "FaceID challenge was not completed correctly" });
    }
    if (
      err instanceof Error &&
      err.message === "FACE_ID_STEP_EVIDENCE_MISSING"
    ) {
      return res.status(400).json({
        error:
          "FaceID live challenge evidence was incomplete. Please scan again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_REQUIRED") {
      return res.status(400).json({
        error: "A 5-second FaceID verification video is required.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_TOO_SHORT") {
      return res.status(400).json({
        error:
          "FaceID video was too short. Record the full 5 seconds and try again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_INVALID") {
      return res.status(400).json({
        error:
          "FaceID video evidence is invalid. Please record a new 5-second clip.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_LIVENESS_TOO_LOW") {
      return res.status(400).json({
        error:
          "FaceID liveness check was too weak. Please scan again with your real face centered in frame.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_MOTION_TOO_LOW") {
      return res.status(400).json({
        error:
          "Face motion was too limited. Move naturally while recording and try again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_EYE_MOTION_TOO_LOW") {
      return res.status(400).json({
        error:
          "Eye landmark motion was too limited. Blink or keep your eyes moving naturally and scan again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_PREVIEW_REQUIRED") {
      return res
        .status(400)
        .json({ error: "Face image is required for FaceID enrollment." });
    }
    if (err instanceof Error && err.message === "FACE_ID_FACE_TOO_SMALL") {
      return res
        .status(400)
        .json({ error: "Move closer to the camera for FaceID enrollment." });
    }
    if (err instanceof Error && err.message === "FACE_ID_TOO_FEW_SAMPLES") {
      return res
        .status(400)
        .json({ error: "FaceID capture was too short. Please scan again." });
    }
    if (err instanceof Error && err.message === "FACE_ID_ANTI_SPOOF_FAILED") {
      return res.status(403).json({
        error: "FaceID anti-spoof check failed. A real live face is required.",
      });
    }
    if (
      err instanceof Error &&
      err.message === "FACE_ID_ANTI_SPOOF_UNAVAILABLE"
    ) {
      return res.status(503).json({
        error:
          "FaceID security service is temporarily unavailable. Please try again.",
      });
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

    await verifyAndConsumeEmailOtpChallenge({
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
  const { captchaToken, captchaOffset } = readSliderCaptchaSubmission(req.body);
  const parsed = loginSchema.safeParse(req.body as LoginReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  if (!captchaToken || !Number.isFinite(captchaOffset)) {
    return res.status(400).json({ error: "Complete the slider captcha first" });
  }

  const userRepository = createUserRepository();
  const loginEventRepository = createLoginEventRepository();
  const email = normalizeEmail(parsed.data.email);
  const policy = await getSecurityPolicy();
  const clientDeviceContext = readClientDeviceContext(req.body);

  const userAgent =
    typeof req.headers["user-agent"] === "string"
      ? req.headers["user-agent"]
      : "unknown";

  try {
    const captchaVerified = verifySliderCaptchaSubmission(
      captchaToken,
      captchaOffset,
    );
    if (!captchaVerified) {
      return res
        .status(403)
        .json({ error: "Slider captcha verification failed" });
    }

    const userDoc = await userRepository.findByEmail(email);
    const failedBefore = await countRecentFailedAttempts(
      email,
      policy.lockoutMinutes,
    );
    const isPasswordValid = userDoc
      ? await verifyPassword(parsed.data.password, userDoc.passwordHash)
      : false;
    const currentIp = getRequestIp(req);
    const currentUserAgent = userAgent !== "unknown" ? userAgent : undefined;
    const authSecurityState = getAuthSecurityState(userDoc?.metadata);
    const wasTrustedIp = isTrustedIp(authSecurityState, currentIp);
    const previousTrustedIp = getLatestDifferentTrustedIp(
      authSecurityState,
      currentIp,
    );
    const loginEventPayload = {
      userId: userDoc?.id || email,
      email,
      ipAddress: currentIp,
      location: getRequestLocation(req),
      userAgent,
      timestamp: new Date().toISOString(),
      success: isPasswordValid ? 1 : 0,
      failed10m: failedBefore,
      botScore: 0.1,
    };

    let aiResult = DEFAULT_AI_RESPONSE;
    try {
      const resp = await fetch(`${AI_URL}/ai/score`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-AI-API-KEY": AI_API_KEY,
        },
        body: JSON.stringify(loginEventPayload),
      });
      const rawResult = (await resp.json().catch(() => null)) as unknown;
      if (!resp.ok) {
        throw new Error(
          `AI scoring failed with status ${resp.status}${
            rawResult && typeof rawResult === "object" && "detail" in rawResult
              ? `: ${String((rawResult as { detail?: unknown }).detail || "")}`
              : ""
          }`,
        );
      }
      aiResult = normalizeAiResponse(rawResult);
    } catch (err) {
      console.warn("AI service not reachable, using default", err);
      aiResult = buildHeuristicLoginAiResponse({
        currentIp,
        wasTrustedIp,
        previousTrustedIp: previousTrustedIp?.ipAddress,
        failedBefore,
        isPasswordValid,
      });
    }

    const score = aiResult.score;

    if (userDoc?.status === "DISABLED") {
      await loginEventRepository.createLoginEvent({
        userId: userDoc.id,
        email,
        ipAddress: getRequestIp(req),
        userAgent,
        success: false,
        anomaly: score,
        metadata: {
          aiResult,
          reason: "ACCOUNT_DISABLED",
          ...(clientDeviceContext
            ? { deviceContext: clientDeviceContext }
            : {}),
        },
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
        metadata: {
          aiResult,
          reason: "LOCKOUT_THRESHOLD",
          ...(clientDeviceContext
            ? { deviceContext: clientDeviceContext }
            : {}),
        },
      });
      return res.status(423).json({
        error: `Too many incorrect password attempts. Your account has been temporarily locked for ${policy.lockoutMinutes} minute${policy.lockoutMinutes === 1 ? "" : "s"}.`,
        attemptsRemaining: 0,
        maxAttempts: policy.maxLoginAttempts,
        lockoutMinutes: policy.lockoutMinutes,
      });
    }

    await loginEventRepository.createLoginEvent({
      userId: userDoc?.id,
      email,
      ipAddress: getRequestIp(req),
      userAgent,
      success: isPasswordValid,
      anomaly: score,
      metadata: {
        aiResult,
        ...(clientDeviceContext ? { deviceContext: clientDeviceContext } : {}),
      },
    });

    if (score >= policy.anomalyAlertThreshold) {
      await logAuditEvent({
        actor: email,
        userId: userDoc?.id,
        action: "AI_ALERT",
        details: {
          score,
          riskLevel: aiResult.riskLevel,
          reasons: aiResult.reasons,
        },
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
          error: buildLoginFailureMessage({
            remainingAttempts: 0,
            lockoutMinutes: policy.lockoutMinutes,
          }),
          anomaly: aiResult,
          attemptsRemaining: 0,
          maxAttempts: policy.maxLoginAttempts,
          lockoutMinutes: policy.lockoutMinutes,
        });
      }

      if (userDoc?.id && !isPasswordValid) {
        const attemptsRemaining = Math.max(
          policy.maxLoginAttempts - failedAttempts,
          0,
        );
        return res.status(401).json({
          error: buildLoginFailureMessage({
            remainingAttempts: attemptsRemaining,
            lockoutMinutes: policy.lockoutMinutes,
          }),
          anomaly: aiResult,
          attemptsRemaining,
          maxAttempts: policy.maxLoginAttempts,
          lockoutMinutes: policy.lockoutMinutes,
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

    const effectiveRiskLevel =
      aiResult.riskLevel === "high" && wasTrustedIp
        ? "low"
        : aiResult.riskLevel;
    const effectiveAiResult =
      effectiveRiskLevel === aiResult.riskLevel
        ? aiResult
        : {
            ...aiResult,
            riskLevel: effectiveRiskLevel,
            requireOtp: false,
            otpChannel: null,
            otpReason: null,
          };
    const reviewReason =
      aiResult.reasons[0] ||
      (wasTrustedIp
        ? "Trusted sign-in"
        : "New or unusual device detected for this sign-in");
    const requiresNewIpOtp = !wasTrustedIp;

    if (requiresNewIpOtp) {
      const otpChallenge = await createEmailOtpChallenge({
        userId: userDoc.id,
        purpose: "LOGIN_HIGH_RISK",
        destination: userDoc.email,
        ttlMinutes: LOGIN_OTP_TTL_MINUTES,
        maxAttempts: HIGH_RISK_LOGIN_OTP_MAX_ATTEMPTS,
        metadata: {
          anomalyScore: score,
          aiReasons: Array.isArray(aiResult?.reasons) ? aiResult.reasons : [],
          currentIp,
          previousTrustedIp: previousTrustedIp?.ipAddress,
          deviceContext: clientDeviceContext,
          sessionSecurity: buildSessionSecurityState("high", {
            reviewReason,
            verificationMethod: "email_otp",
            restrictLargeTransfers: true,
          }),
        },
      });
      runAsyncSideEffect("sendLoginOtpEmail", () =>
        sendLoginOtpEmail({
          to: userDoc.email,
          recipientName:
            userDoc.fullName || userDoc.email.split("@")[0] || "User",
          otpCode: otpChallenge.otpCode,
          expiresInMinutes: LOGIN_OTP_TTL_MINUTES,
        }),
      );
      runAsyncSideEffect("sendLoginRiskAlertEmail", () =>
        sendLoginRiskAlertEmail({
          to: userDoc.email,
          recipientName:
            userDoc.fullName || userDoc.email.split("@")[0] || "User",
          ipAddress: currentIp,
          userAgent: currentUserAgent,
          reason: reviewReason,
        }),
      );

      await logAuditEvent({
        actor: email,
        action: "LOGIN_HIGH_RISK_EMAIL_OTP_SENT",
        userId: userDoc.id,
        details: {
          anomaly: score,
          challengeId: otpChallenge.challengeId,
          currentIp,
          previousTrustedIp: previousTrustedIp?.ipAddress,
        },
        ipAddress: currentIp,
      });

      return res.json({
        status: "otp_required",
        challengeId: otpChallenge.challengeId,
        destination: maskEmail(userDoc.email),
        expiresAt: otpChallenge.expiresAt.toISOString(),
        retryAfterSeconds: otpChallenge.retryAfterSeconds,
        notice:
          "New device or VPN sign-in detected. A verification code has been sent to your email.",
        anomaly: effectiveAiResult,
      });
    }

    const sessionSecurity = buildSessionSecurityState(effectiveRiskLevel, {
      reviewReason,
    });
    const nextAuthState = recordSuccessfulLoginIp(
      authSecurityState,
      currentIp,
      {
        trustIp: effectiveRiskLevel === "low",
      },
    );

    await userRepository.touchLastLogin(userDoc.id);
    const sessionResult = await issueExclusiveUserSession({
      userRepository,
      userDoc,
      authState: nextAuthState,
      ipAddress: currentIp,
      userAgent: currentUserAgent,
      security: sessionSecurity,
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

    let notice: string | undefined;
    if (effectiveRiskLevel === "medium") {
      notice = `New or unusual device detected. Large transfers above $${MEDIUM_RISK_TRANSFER_LIMIT.toLocaleString("en-US")} are temporarily restricted for this session.`;
      runAsyncSideEffect("sendLoginRiskAlertEmail", () =>
        sendLoginRiskAlertEmail({
          to: userDoc.email,
          recipientName:
            userDoc.fullName || userDoc.email.split("@")[0] || "User",
          ipAddress: currentIp,
          userAgent: currentUserAgent,
          reason: reviewReason,
        }),
      );
      await logAuditEvent({
        actor: email,
        action: "LOGIN_MEDIUM_RISK",
        userId: userDoc.id,
        details: {
          anomaly: score,
          transferLimit: MEDIUM_RISK_TRANSFER_LIMIT,
          currentIp,
        },
        ipAddress: currentIp,
      });
    } else if (wasTrustedIp) {
      notice = buildRecentIpNotice(authSecurityState, currentIp, APP_TIMEZONE);
      await logAuditEvent({
        actor: email,
        action: "LOGIN_TRUSTED_IP",
        userId: userDoc.id,
        details: {
          anomaly: score,
          trustedIp: currentIp,
        },
        ipAddress: currentIp,
      });
    }

    notice = buildFaceEnrollmentRequiredNotice(userDoc, notice);

    return res.json({
      ...buildAuthPayload(userDoc, sessionResult.sessionId, {
        notice,
        security: sessionSecurity,
      }),
      anomaly: effectiveAiResult,
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
    if (err instanceof Error && err.message === "CAPTCHA_EXPIRED") {
      return res
        .status(400)
        .json({ error: "Slider captcha expired. Please drag again." });
    }
    if (err instanceof Error && err.message === "INVALID_CAPTCHA") {
      return res.status(400).json({ error: "Invalid slider captcha payload" });
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
  const { captchaToken, captchaOffset } = readSliderCaptchaSubmission(req.body);
  const challengeId =
    typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.replace(/\D/g, "") : "";
  if (!challengeId || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: "Invalid login OTP payload" });
  }
  if (!captchaToken || !Number.isFinite(captchaOffset)) {
    return res.status(400).json({ error: "Complete the slider captcha first" });
  }

  let challengeUserId = "";
  let challengePurpose = "";
  let challengeEmail = "";
  try {
    const captchaVerified = verifySliderCaptchaSubmission(
      captchaToken,
      captchaOffset,
    );
    if (!captchaVerified) {
      return res
        .status(403)
        .json({ error: "Slider captcha verification failed" });
    }

    const challenge = await prisma.otpChallenge.findUnique({
      where: { id: challengeId },
    });
    if (
      !challenge ||
      (challenge.purpose !== "LOGIN" &&
        challenge.purpose !== "LOGIN_HIGH_RISK") ||
      challenge.channel !== "EMAIL"
    ) {
      return res.status(404).json({ error: "OTP challenge not found" });
    }

    challengeUserId = challenge.userId;
    challengePurpose = challenge.purpose;
    const loginPurpose = challenge.purpose;
    const metadata =
      challenge.metadata && typeof challenge.metadata === "object"
        ? (challenge.metadata as Record<string, unknown>)
        : {};
    await verifyAndConsumeEmailOtpChallenge({
      userId: challengeUserId,
      purpose: loginPurpose,
      challengeId,
      otp,
    });

    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(challengeUserId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });
    challengeEmail = userDoc.email;
    if (userDoc.status !== "ACTIVE") {
      return res.status(423).json({ error: "Account is not active" });
    }

    await userRepository.touchLastLogin(userDoc.id);
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
    const sessionSecurity =
      loginPurpose === "LOGIN_HIGH_RISK"
        ? buildSessionSecurityState("high", {
            reviewReason: "New-device sign-in verified by email OTP",
            verificationMethod: "email_otp",
            restrictLargeTransfers: true,
          })
        : buildSessionSecurityState("low");
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
      security: sessionSecurity,
    });

    const notice =
      loginPurpose === "LOGIN_HIGH_RISK"
        ? `Email verification successful. Large transfers above $${MEDIUM_RISK_TRANSFER_LIMIT.toLocaleString(
            "en-US",
          )} remain temporarily restricted for this session.`
        : verifiedIp
          ? previousTrustedIp && previousTrustedIp !== verifiedIp
            ? `IP ${verifiedIp} is now trusted. Previous trusted IP: ${previousTrustedIp}.`
            : `IP ${verifiedIp} is now trusted for future sign-ins.`
          : undefined;
    const loginNotice = buildFaceEnrollmentRequiredNotice(userDoc, notice);

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

    invalidateUserResponseCache(userDoc.id, ["auth", "security"]);

    return res.json(
      buildAuthPayload(userDoc, sessionResult.sessionId, {
        notice: loginNotice,
        security: sessionSecurity,
      }),
    );
  } catch (err) {
    if (err instanceof Error && err.message === "CAPTCHA_EXPIRED") {
      return res
        .status(400)
        .json({ error: "Slider captcha expired. Please drag again." });
    }
    if (err instanceof Error && err.message === "INVALID_CAPTCHA") {
      return res.status(400).json({ error: "Invalid slider captcha payload" });
    }
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
      if (
        challengeUserId &&
        (challengePurpose === "LOGIN" || challengePurpose === "LOGIN_HIGH_RISK")
      ) {
        await lockUserAccount(
          challengeUserId,
          challengeEmail || "system",
          challengePurpose === "LOGIN_HIGH_RISK"
            ? "Exceeded high-risk OTP attempts after IP change"
            : "Exceeded login OTP attempts",
          getRequestIp(req),
        );
      }
      return res.status(423).json({
        error:
          challengePurpose === "LOGIN_HIGH_RISK"
            ? "Account locked after 3 incorrect OTP attempts on a new IP."
            : "Account locked after too many incorrect OTP attempts.",
        remainingAttempts:
          "remainingAttempts" in err
            ? ((err as { remainingAttempts?: number }).remainingAttempts ?? 0)
            : 0,
      });
    }
    if (err instanceof Error && err.message === "OTP_INCORRECT") {
      const remainingAttempts =
        "remainingAttempts" in err
          ? ((err as { remainingAttempts?: number }).remainingAttempts ?? null)
          : null;
      return res.status(400).json({
        error:
          remainingAttempts === null
            ? "Incorrect OTP."
            : `Incorrect OTP. ${remainingAttempts} attempt${remainingAttempts === 1 ? "" : "s"} remaining.`,
        remainingAttempts,
      });
    }
    console.error("Failed to login user", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/auth/password/otp/send", async (req, res) => {
  const email =
    typeof req.body?.email === "string" ? normalizeEmail(req.body.email) : "";
  const { captchaToken, captchaOffset } = readSliderCaptchaSubmission(req.body);
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }
  if (!captchaToken || !Number.isFinite(captchaOffset)) {
    return res.status(400).json({ error: "Complete the slider captcha first" });
  }

  try {
    const captchaVerified = verifySliderCaptchaSubmission(
      captchaToken,
      captchaOffset,
    );
    if (!captchaVerified) {
      return res
        .status(403)
        .json({ error: "Slider captcha verification failed" });
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

    runAsyncSideEffect("sendPasswordResetOtpEmail", () =>
      sendPasswordResetOtpEmail({
        to: userDoc.email,
        recipientName:
          userDoc.fullName || userDoc.email.split("@")[0] || "User",
        otpCode: otpChallenge.otpCode,
        expiresInMinutes: RESET_PASSWORD_OTP_TTL_MINUTES,
      }),
    );

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
    if (err instanceof Error && err.message === "CAPTCHA_EXPIRED") {
      return res
        .status(400)
        .json({ error: "Slider captcha expired. Please drag again." });
    }
    if (err instanceof Error && err.message === "INVALID_CAPTCHA") {
      return res.status(400).json({ error: "Invalid slider captcha payload" });
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
    typeof body.newPassword === "string" ? body.newPassword : "";

  if (
    !email ||
    !challengeId ||
    !/^\d{6}$/.test(otp) ||
    newPassword.length < PROFESSIONAL_PASSWORD_MIN_LENGTH ||
    !meetsProfessionalPasswordPolicy(newPassword)
  ) {
    return res.status(400).json({
      error:
        "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
    });
  }

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findByEmail(email);
    if (!userDoc) return res.status(404).json({ error: "Email not found" });

    await verifyAndConsumeEmailOtpChallenge({
      userId: userDoc.id,
      purpose: "RESET_PASSWORD",
      challengeId,
      otp,
    });

    const passwordHash = await hashPassword(newPassword);
    await userRepository.updatePassword(userDoc.id, passwordHash);
    const authSecurityState = clearActiveAuthSession(
      getAuthSecurityState(userDoc.metadata),
    );
    await persistAuthSecurityState(userRepository, userDoc, authSecurityState);

    await logAuditEvent({
      actor: userDoc.email,
      userId: userDoc.id,
      action: "RESET_PASSWORD",
      details: {
        revokedActiveSession:
          authSecurityState.activeSession?.sessionId ?? null,
      },
      ipAddress: getRequestIp(req),
    });
    invalidateUserResponseCache(userDoc.id, ["auth", "security"]);

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

app.post("/auth/logout", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const userRepository = createUserRepository();
  const userDoc = await userRepository.findValidatedById(userId);
  if (!userDoc) return res.status(404).json({ error: "User not found" });

  const currentSid = typeof req.user?.sid === "string" ? req.user.sid : "";
  const authSecurityState = getAuthSecurityState(userDoc.metadata);
  const activeSession = authSecurityState.activeSession;

  if (activeSession?.sessionId && activeSession.sessionId === currentSid) {
    await persistAuthSecurityState(
      userRepository,
      userDoc,
      clearActiveAuthSession(authSecurityState),
    );
  }

  await logAuditEvent({
    actor: req.user?.email || userDoc.email,
    userId: userDoc.id,
    action: "LOGOUT",
    details: {
      sessionId: currentSid || null,
      clearedActiveSession:
        activeSession?.sessionId === currentSid ? currentSid : null,
    },
    ipAddress: getRequestIp(req),
  });

  invalidateUserResponseCache(userDoc.id, ["auth", "security"]);

  return res.status(204).send();
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

      runAsyncSideEffect("sendPasswordResetOtpEmail", () =>
        sendPasswordResetOtpEmail({
          to: userDoc.email,
          recipientName:
            userDoc.fullName || userDoc.email.split("@")[0] || "User",
          otpCode: otpChallenge.otpCode,
          expiresInMinutes: RESET_PASSWORD_OTP_TTL_MINUTES,
        }),
      );

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
  if (
    newPassword.length < PROFESSIONAL_PASSWORD_MIN_LENGTH ||
    !meetsProfessionalPasswordPolicy(newPassword)
  ) {
    return res.status(400).json({
      error:
        "New password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
    });
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

  invalidateUserResponseCache(userDoc.id, ["auth", "security"]);

  return res.status(204).send();
});

app.post("/auth/face/enroll", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const faceEnrollment = readFaceIdEnrollment(req.body);
  const auditClientMetadata = buildAuditClientMetadata(req, req.body);
  if (!faceEnrollment) {
    return res.status(400).json({ error: "FaceID enrollment is required" });
  }

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });
    if (userDoc.status !== "ACTIVE") {
      return res.status(423).json({ error: "Account is not active" });
    }

    const verifiedFace = await verifyFaceIdSubmissionStrict(faceEnrollment);
    const faceVideoHash = faceEnrollment.videoEvidence
      ? crypto
          .createHash("sha256")
          .update(faceEnrollment.videoEvidence)
          .digest("hex")
      : null;
    const existingFaceId = getInternalFaceIdMetadata(userDoc.metadata);
    const nowIso = new Date().toISOString();
    const nextMetadata = {
      ...(userDoc.metadata ?? {}),
      faceId: {
        ...(existingFaceId ?? {}),
        enabled: true,
        enrolledAt:
          typeof existingFaceId?.enrolledAt === "string"
            ? existingFaceId.enrolledAt
            : nowIso,
        updatedAt: nowIso,
        challengeNonce: verifiedFace.challenge.nonce,
        challengeSteps: verifiedFace.challenge.steps,
        descriptor: faceEnrollment.descriptor,
        descriptorHash: crypto
          .createHash("sha256")
          .update(faceEnrollment.descriptor)
          .digest("hex"),
        livenessScore: faceEnrollment.livenessScore,
        motionScore: faceEnrollment.motionScore,
        eyeMotionScore: faceEnrollment.eyeMotionScore,
        faceCoverage: faceEnrollment.faceCoverage,
        sampleCount: faceEnrollment.sampleCount,
        previewImage: faceEnrollment.previewImage,
        videoEvidenceHash: faceVideoHash,
        videoDurationMs:
          typeof faceEnrollment.videoDurationMs === "number"
            ? Math.round(faceEnrollment.videoDurationMs)
            : null,
        videoMimeType: faceEnrollment.videoMimeType || null,
        antiSpoof: {
          spoofScore: verifiedFace.antiSpoof.spoofScore,
          confidence: verifiedFace.antiSpoof.confidence,
          riskLevel: verifiedFace.antiSpoof.riskLevel,
          reasons: verifiedFace.antiSpoof.reasons,
          modelSource: verifiedFace.antiSpoof.modelSource,
          modelVersion: verifiedFace.antiSpoof.modelVersion,
        },
        lastVerifiedAt: nowIso,
      },
    };

    const updatedUser = await userRepository.updateMetadata(
      userDoc.id,
      nextMetadata,
    );

    await logAuditEvent({
      actor: req.user?.email,
      userId: userDoc.id,
      action:
        existingFaceId && existingFaceId.enabled === true
          ? "FACE_ID_UPDATED"
          : "FACE_ID_ENROLLED",
      details: {
        sampleCount: faceEnrollment.sampleCount,
        motionScore: faceEnrollment.motionScore,
        livenessScore: faceEnrollment.livenessScore,
        eyeMotionScore: faceEnrollment.eyeMotionScore,
      },
      metadata: auditClientMetadata,
      ipAddress: getRequestIp(req),
    });

    invalidateUserResponseCache(userId, ["auth", "security"]);

    return res.json({
      status: "ok",
      message:
        existingFaceId && existingFaceId.enabled === true
          ? "FaceID updated successfully."
          : "FaceID enrolled successfully.",
      metadata: buildPublicUserMetadata(updatedUser.metadata),
    });
  } catch (err) {
    console.warn("FaceID enroll rejected", {
      userId,
      code: err instanceof Error ? err.message : "UNKNOWN",
      sampleCount: faceEnrollment.sampleCount,
      faceCoverage: faceEnrollment.faceCoverage,
      motionScore: faceEnrollment.motionScore,
      livenessScore: faceEnrollment.livenessScore,
      eyeMotionScore: faceEnrollment.eyeMotionScore,
      hasPreviewImage: Boolean(faceEnrollment.previewImage),
      hasVideoEvidence: Boolean(faceEnrollment.videoEvidence),
      videoDurationMs: faceEnrollment.videoDurationMs,
    });
    if (err instanceof Error && err.message === "FACE_ID_EXPIRED") {
      return res.status(400).json({
        error: "FaceID challenge expired. Start a new live scan.",
      });
    }
    if (err instanceof Error && err.message === "INVALID_FACE_ID") {
      return res
        .status(400)
        .json({ error: "Invalid FaceID challenge payload" });
    }
    if (err instanceof Error && err.message === "INVALID_FACE_ID_DESCRIPTOR") {
      return res.status(400).json({ error: "Invalid FaceID biometric sample" });
    }
    if (err instanceof Error && err.message === "FACE_ID_STEP_MISMATCH") {
      return res.status(400).json({
        error: "FaceID challenge steps were not completed in order",
      });
    }
    if (
      err instanceof Error &&
      err.message === "FACE_ID_STEP_EVIDENCE_MISSING"
    ) {
      return res.status(400).json({
        error:
          "FaceID live challenge evidence was incomplete. Please scan again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_REQUIRED") {
      return res.status(400).json({
        error: "A 5-second FaceID verification video is required.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_TOO_SHORT") {
      return res.status(400).json({
        error:
          "FaceID video was too short. Record the full 5 seconds and try again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_INVALID") {
      return res.status(400).json({
        error:
          "FaceID video evidence is invalid. Please record a new 5-second clip.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_LIVENESS_TOO_LOW") {
      return res.status(400).json({
        error:
          "FaceID liveness check was too weak. Please scan again with your real face centered in frame.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_MOTION_TOO_LOW") {
      return res.status(400).json({
        error:
          "Face motion was too limited. Move naturally while recording and try again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_EYE_MOTION_TOO_LOW") {
      return res.status(400).json({
        error:
          "Eye landmark motion was too limited. Blink or keep your eyes moving naturally and scan again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_PREVIEW_REQUIRED") {
      return res.status(400).json({
        error: "Face image is required for FaceID enrollment.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_FACE_TOO_SMALL") {
      return res.status(400).json({
        error: "Move closer to the camera so your face fills the scan area.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_TOO_FEW_SAMPLES") {
      return res.status(400).json({
        error: "Face sample was too short. Hold steady and try again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_ANTI_SPOOF_FAILED") {
      return res.status(403).json({
        error:
          "Server anti-spoof checks rejected this scan. Please use a real live face.",
      });
    }
    if (
      err instanceof Error &&
      err.message === "FACE_ID_ANTI_SPOOF_UNAVAILABLE"
    ) {
      return res.status(503).json({
        error:
          "FaceID anti-spoof service is temporarily unavailable. Please try again.",
      });
    }
    console.error("Failed to enroll FaceID", err);
    return res.status(500).json({ error: "Failed to enroll FaceID" });
  }
});

app.post("/security/transfer-pin", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    currentPin?: unknown;
    newPin?: unknown;
    otpChallengeId?: unknown;
    otp?: unknown;
  };
  const currentPin =
    typeof body.currentPin === "string"
      ? body.currentPin.replace(/\D/g, "")
      : "";
  const newPin =
    typeof body.newPin === "string" ? body.newPin.replace(/\D/g, "") : "";
  const otpChallengeId =
    typeof body.otpChallengeId === "string" ? body.otpChallengeId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.replace(/\D/g, "") : "";
  if (!/^\d{6}$/.test(newPin)) {
    return res.status(400).json({
      error: "Transfer password must be exactly 6 digits",
    });
  }
  if (!otpChallengeId || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({
      error:
        "Email OTP confirmation is required before creating or changing the transfer PIN.",
    });
  }

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });
    if (userDoc.status !== "ACTIVE") {
      return res.status(423).json({ error: "Account is not active" });
    }

    if (hasStoredTransferPin(userDoc.metadata)) {
      const isCurrentPinValid = await verifyTransferPinForUser(
        userDoc,
        currentPin,
      );
      if (!isCurrentPinValid) {
        return res.status(400).json({
          error: "Current transfer PIN is incorrect",
        });
      }
    }

    try {
      await verifyAndConsumeEmailOtpChallenge({
        userId,
        purpose: "TRANSFER_PIN",
        challengeId: otpChallengeId,
        otp,
      });
    } catch (err) {
      if (err instanceof Error && err.message === "OTP_CHALLENGE_NOT_FOUND") {
        return res.status(400).json({ error: "Transfer PIN OTP is invalid." });
      }
      if (
        err instanceof Error &&
        err.message === "OTP_CHALLENGE_ALREADY_USED"
      ) {
        return res.status(409).json({
          error:
            "This transfer PIN OTP was already used. Request a new code and try again.",
        });
      }
      if (err instanceof Error && err.message === "OTP_EXPIRED") {
        return res.status(400).json({
          error: "Transfer PIN OTP expired. Request a new code.",
        });
      }
      if (err instanceof Error && err.message === "OTP_TOO_MANY_ATTEMPTS") {
        return res.status(429).json({
          error:
            "Too many incorrect transfer PIN OTP attempts. Request a new code.",
        });
      }
      if (err instanceof Error && err.message === "OTP_INCORRECT") {
        return res.status(400).json({
          error: "Transfer PIN OTP is incorrect.",
        });
      }
      throw err;
    }

    const nowIso = new Date().toISOString();
    const nextMetadata = {
      ...(userDoc.metadata ?? {}),
      transferSecurity: {
        ...(getInternalTransferPinMetadata(userDoc.metadata) ?? {}),
        enabled: true,
        pinHash: await hashPassword(newPin),
        updatedAt: nowIso,
      },
    };
    const updatedUser = await userRepository.updateMetadata(
      userDoc.id,
      nextMetadata,
    );

    await logAuditEvent({
      actor: req.user?.email,
      userId: userDoc.id,
      action: hasStoredTransferPin(userDoc.metadata)
        ? "TRANSFER_PIN_UPDATED"
        : "TRANSFER_PIN_CREATED",
      details: {
        transferPinEnabled: true,
        otpChallengeId,
      },
      ipAddress: getRequestIp(req),
    });

    invalidateUserResponseCache(userId, ["auth", "security"]);

    return res.json({
      status: "ok",
      message: hasStoredTransferPin(userDoc.metadata)
        ? "Transfer PIN updated successfully."
        : "Transfer PIN created successfully.",
      metadata: buildPublicUserMetadata(updatedUser.metadata),
    });
  } catch (err) {
    console.error("Failed to update transfer PIN", err);
    return res.status(500).json({ error: "Failed to update transfer PIN" });
  }
});

app.post("/security/transfer-pin/otp/send", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });
    if (userDoc.status !== "ACTIVE") {
      return res.status(423).json({ error: "Account is not active" });
    }

    const otpChallenge = await createEmailOtpChallenge({
      userId,
      purpose: "TRANSFER_PIN",
      destination: userDoc.email,
      ttlMinutes: TRANSFER_PIN_OTP_TTL_MINUTES,
      maxAttempts: OTP_MAX_ATTEMPTS,
    });

    runAsyncSideEffect("sendTransferPinOtpEmail", () =>
      sendTransferPinOtpEmail({
        to: userDoc.email,
        recipientName: getRecipientName(userDoc),
        otpCode: otpChallenge.otpCode,
        expiresInMinutes: TRANSFER_PIN_OTP_TTL_MINUTES,
      }),
    );

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action: "TRANSFER_PIN_OTP_SENT",
      details: {
        challengeId: otpChallenge.challengeId,
      },
      ipAddress: getRequestIp(req),
    });

    return res.json({
      status: "ok",
      challengeId: otpChallenge.challengeId,
      expiresAt: otpChallenge.expiresAt.toISOString(),
      retryAfterSeconds: otpChallenge.retryAfterSeconds,
      destination: maskEmail(userDoc.email),
      message: "Transfer PIN OTP sent successfully.",
    });
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_COOLDOWN_ACTIVE") {
      return res.status(429).json({
        error:
          "A transfer PIN OTP was sent recently. Please wait before retrying.",
        retryAfterSeconds:
          "retryAfterSeconds" in err
            ? (err as { retryAfterSeconds: number }).retryAfterSeconds
            : 60,
      });
    }
    console.error("Failed to send transfer PIN OTP", err);
    return res.status(500).json({ error: "Failed to send transfer PIN OTP" });
  }
});

app.get("/auth/me", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const payload = await getCachedUserResponse(userId, "auth", async () => {
      const userRepository = createUserRepository();
      const userDoc = await userRepository.findValidatedById(userId);
      if (!userDoc) {
        throw new Error("AUTH_USER_NOT_FOUND");
      }

      const evaluatedProfile = await evaluateAutomaticAccountProfileForUser({
        userId,
        metadata: userDoc.metadata,
      });
      const previousProfile = buildResolvedAccountProfile(userDoc.metadata);
      let metadata = evaluatedProfile.metadata;
      if (JSON.stringify(metadata) !== JSON.stringify(userDoc.metadata ?? {})) {
        const updatedUser = await userRepository.updateMetadata(
          userId,
          metadata,
        );
        metadata =
          updatedUser.metadata && typeof updatedUser.metadata === "object"
            ? (updatedUser.metadata as Record<string, unknown>)
            : {};
        if (
          previousProfile.category !==
            evaluatedProfile.accountProfile.category ||
          previousProfile.tier !== evaluatedProfile.accountProfile.tier
        ) {
          await logAuditEvent({
            actor: "automatic-tiering",
            userId,
            action: "ACCOUNT_PROFILE_AUTO_UPGRADED",
            details: {
              previousProfile,
              upgradedProfile: evaluatedProfile.accountProfile,
              automation: evaluatedProfile.automation,
            },
            ipAddress: getRequestIp(req),
          });
        }
      }
      const authSecurityState = getAuthSecurityState(metadata);
      const publicMetadata = buildPublicUserMetadata(metadata);
      const publicAccountProfile =
        publicMetadata.accountProfile &&
        typeof publicMetadata.accountProfile === "object"
          ? (publicMetadata.accountProfile as Record<string, unknown>)
          : {};
      publicMetadata.accountProfile = {
        ...publicAccountProfile,
        automation: evaluatedProfile.automation,
      };

      return {
        id: userDoc.id,
        email: userDoc.email,
        role: userDoc.role,
        fullName: userDoc.fullName ?? "",
        phone: typeof userDoc.phone === "string" ? userDoc.phone : "",
        address: typeof userDoc.address === "string" ? userDoc.address : "",
        dob: typeof userDoc.dob === "string" ? userDoc.dob : "",
        avatar:
          typeof metadata.avatar === "string" ? metadata.avatar : undefined,
        metadata: publicMetadata,
        security:
          authSecurityState.activeSession?.security ??
          buildSessionSecurityState("low"),
      };
    });

    runAsyncSideEffect("runBudgetAssistantAutomation:auth_me", () =>
      runBudgetAssistantAutomation({
        userId,
        actor: req.user?.email,
        ipAddress: getRequestIp(req),
        trigger: "auth_me",
      }),
    );

    return res.json(payload);
  } catch (err) {
    if (err instanceof Error && err.message === "AUTH_USER_NOT_FOUND") {
      return res.status(404).json({ error: "User not found" });
    }
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
  let avatar: string | undefined;
  try {
    avatar = parseSafeAvatarDataUrl(metadata.avatar);
  } catch (err) {
    if (err instanceof Error) {
      if (err.message === "AVATAR_TOO_LARGE") {
        return res.status(400).json({
          error: "Avatar image is too large. Please choose a smaller image.",
        });
      }
      if (err.message === "AVATAR_UNSUPPORTED_TYPE") {
        return res
          .status(400)
          .json({ error: "Avatar must be a JPG, PNG, or WebP image." });
      }
      return res.status(400).json({
        error:
          "Avatar content is invalid. Please upload a real JPG, PNG, or WebP image.",
      });
    }
    return res.status(400).json({ error: "Invalid avatar payload." });
  }
  const safeMetadata = {
    ...metadata,
    ...(avatar ? { avatar } : {}),
  };
  delete (safeMetadata as Record<string, unknown>).faceId;
  delete (safeMetadata as Record<string, unknown>).transferSecurity;
  delete (safeMetadata as Record<string, unknown>).accountCategory;
  delete (safeMetadata as Record<string, unknown>).accountTier;
  delete (safeMetadata as Record<string, unknown>).accountSegment;
  delete (safeMetadata as Record<string, unknown>).accountType;
  delete (safeMetadata as Record<string, unknown>).segment;
  delete (safeMetadata as Record<string, unknown>).accountProfile;

  try {
    const userRepository = createUserRepository();
    const existingUser = await userRepository.findValidatedById(userId);
    const normalizedMetadata = {
      ...(existingUser?.metadata ?? {}),
      ...safeMetadata,
    };
    if (avatar) {
      normalizedMetadata.avatar = avatar;
    }
    const updated = await userRepository.updateProfile(userId, {
      fullName: fullName || undefined,
      phone: phone || undefined,
      address: address || undefined,
      dob: dob || undefined,
      metadata: normalizedMetadata,
    });

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action: "PROFILE_UPDATED",
      details: { fullName: Boolean(fullName), phone: Boolean(phone) },
      ipAddress: getRequestIp(req),
    });

    invalidateUserResponseCache(userId, ["auth"]);

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
      metadata: buildPublicUserMetadata(updated.metadata),
    });
  } catch (err) {
    console.error("Failed to update profile", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.put("/auth/me/account-profile", requireAuth, async (req, res) => {
  return res.status(403).json({
    error:
      "Self-service profile changes are disabled. FPIPay now upgrades personal tiers automatically from clean monthly activity, while admins can still set profiles manually for reviews and demos.",
  });
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
    cvv?: unknown;
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
  const cvv = typeof body.cvv === "string" ? body.cvv.replace(/\D/g, "") : "";

  if (
    !type ||
    !bank ||
    !holder ||
    !/^\d{12,19}$/.test(number) ||
    !/^(0[1-9]|1[0-2])$/.test(expiryMonth) ||
    !/^\d{2,4}$/.test(expiryYear) ||
    (cvv.length > 0 && !/^\d{3,4}$/.test(cvv))
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
        rawCvv: cvv,
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

app.post("/card/details/otp/send", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    const otpChallenge = await createEmailOtpChallenge({
      userId,
      purpose: "CARD_DETAILS",
      destination: userDoc.email,
      ttlMinutes: CARD_DETAILS_OTP_TTL_MINUTES,
      maxAttempts: OTP_MAX_ATTEMPTS,
      metadata: {
        action: "CARD_DETAILS_VIEW",
      },
    });

    runAsyncSideEffect("sendCardDetailsOtpEmail", () =>
      sendCardDetailsOtpEmail({
        to: userDoc.email,
        recipientName: getRecipientName(userDoc),
        otpCode: otpChallenge.otpCode,
        expiresInMinutes: CARD_DETAILS_OTP_TTL_MINUTES,
      }),
    );

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action: "CARD_DETAILS_OTP_SENT",
      details: {
        challengeId: otpChallenge.challengeId,
      },
      ipAddress: getRequestIp(req),
    });

    return res.json({
      status: "ok",
      challengeId: otpChallenge.challengeId,
      expiresAt: otpChallenge.expiresAt.toISOString(),
      destination: maskEmail(userDoc.email),
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
    console.error("Failed to send card details OTP", err);
    return res.status(500).json({ error: "Failed to send card details OTP" });
  }
});

app.post("/card/details/otp/verify", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    challengeId?: unknown;
    otp?: unknown;
  };
  const challengeId =
    typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.trim() : "";

  if (!challengeId || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: "Invalid OTP payload" });
  }

  try {
    await verifyAndConsumeEmailOtpChallenge({
      userId,
      purpose: "CARD_DETAILS",
      challengeId,
      otp,
    });

    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });

    const cards = getStoredCards(userDoc.metadata);
    const primaryCard = cards.find((card) => card.isPrimary) ?? cards[0];
    const wallet = await getOrCreateWalletByUserId(userId);
    const walletMetadata =
      wallet.metadata && typeof wallet.metadata === "object"
        ? (wallet.metadata as Record<string, unknown>)
        : {};
    const walletAccountNumber =
      typeof walletMetadata.accountNumber === "string"
        ? walletMetadata.accountNumber
        : "";

    const accountSeed = `${userId}:${walletAccountNumber || wallet.id}`;
    const fullCardDigits =
      (primaryCard && getStoredCardFullNumber(primaryCard)) ||
      deriveVirtualCardNumber(accountSeed);
    const cvv =
      (primaryCard && getStoredCardCvv(primaryCard)) ||
      deriveVirtualCardCvv(accountSeed);
    const cardType = primaryCard
      ? `${primaryCard.type}${primaryCard.bank ? ` - ${primaryCard.bank}` : ""}`
      : "Virtual Debit";
    const expiryYear =
      primaryCard?.expiryYear || String(new Date().getFullYear() + 3);
    const expiryMonth = primaryCard?.expiryMonth || "12";
    const createdAt = primaryCard?.createdAt || wallet.createdAt.toISOString();
    const updatedAt = primaryCard?.updatedAt || wallet.updatedAt.toISOString();

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action: "CARD_DETAILS_OTP_VERIFIED",
      details: {
        challengeId,
      },
      ipAddress: getRequestIp(req),
    });

    return res.json({
      status: "ok",
      verified: true,
      cardDetails: {
        holder: primaryCard?.holder || userDoc.fullName || userDoc.email,
        type: cardType,
        number: formatCardNumberGroups(fullCardDigits),
        expiry: `${expiryMonth}/${expiryYear.slice(-2)}`,
        cvv,
        status:
          primaryCard?.status === "FROZEN"
            ? "Frozen"
            : primaryCard
              ? "Active"
              : "Virtual",
        issuedAt: new Date(createdAt).toLocaleDateString("en-US", {
          month: "short",
          day: "2-digit",
          year: "numeric",
        }),
        linkedAccount: walletAccountNumber
          ? `Wallet ${walletAccountNumber}`
          : `Wallet ${wallet.id}`,
        dailyLimit: "Policy based",
        contactless: primaryCard ? "Enabled" : "Virtual",
        onlinePayment: primaryCard ? "Enabled" : "Virtual",
        lastActivity: new Date(updatedAt).toLocaleString("en-US"),
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
      const remainingAttempts =
        "remainingAttempts" in err
          ? (err as { remainingAttempts?: number }).remainingAttempts
          : undefined;
      return res.status(400).json({
        error:
          typeof remainingAttempts === "number" && remainingAttempts > 0
            ? `Incorrect OTP. ${remainingAttempts} attempt${
                remainingAttempts === 1 ? "" : "s"
              } remaining.`
            : "Incorrect OTP",
      });
    }
    console.error("Failed to verify card details OTP", err);
    return res.status(500).json({ error: "Failed to verify card details OTP" });
  }
});

app.post("/card/details/pin/verify", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    pin?: unknown;
  };
  const pin = typeof body.pin === "string" ? body.pin.trim() : "";
  if (!/^\d{6}$/.test(pin)) {
    return res
      .status(400)
      .json({ error: "6-digit passcode must be exactly 6 digits." });
  }

  try {
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(userId);
    if (!userDoc) return res.status(404).json({ error: "User not found" });
    if (!hasStoredTransferPin(userDoc.metadata)) {
      return res.status(403).json({
        error:
          "Create your 6-digit transfer passcode before viewing full card details.",
      });
    }
    if (!(await verifyTransferPinForUser(userDoc, pin))) {
      return res.status(400).json({ error: "Incorrect 6-digit passcode." });
    }

    const cards = getStoredCards(userDoc.metadata);
    const primaryCard = cards.find((card) => card.isPrimary) ?? cards[0];
    const wallet = await getOrCreateWalletByUserId(userId);
    const walletMetadata =
      wallet.metadata && typeof wallet.metadata === "object"
        ? (wallet.metadata as Record<string, unknown>)
        : {};
    const walletAccountNumber =
      typeof walletMetadata.accountNumber === "string"
        ? walletMetadata.accountNumber
        : "";

    const accountSeed = `${userId}:${walletAccountNumber || wallet.id}`;
    const fullCardDigits =
      (primaryCard && getStoredCardFullNumber(primaryCard)) ||
      deriveVirtualCardNumber(accountSeed);
    const cvv =
      (primaryCard && getStoredCardCvv(primaryCard)) ||
      deriveVirtualCardCvv(accountSeed);
    const cardType = primaryCard
      ? `${primaryCard.type}${primaryCard.bank ? ` - ${primaryCard.bank}` : ""}`
      : "Virtual Debit";
    const expiryYear =
      primaryCard?.expiryYear || String(new Date().getFullYear() + 3);
    const expiryMonth = primaryCard?.expiryMonth || "12";
    const createdAt = primaryCard?.createdAt || wallet.createdAt.toISOString();
    const updatedAt = primaryCard?.updatedAt || wallet.updatedAt.toISOString();

    await logAuditEvent({
      actor: req.user?.email,
      userId,
      action: "CARD_DETAILS_PIN_VERIFIED",
      details: {
        verificationMethod: "transfer_passcode",
      },
      ipAddress: getRequestIp(req),
    });

    return res.json({
      status: "ok",
      verified: true,
      cardDetails: {
        holder: primaryCard?.holder || userDoc.fullName || userDoc.email,
        type: cardType,
        number: formatCardNumberGroups(fullCardDigits),
        expiry: `${expiryMonth}/${expiryYear.slice(-2)}`,
        cvv,
        status:
          primaryCard?.status === "FROZEN"
            ? "Frozen"
            : primaryCard
              ? "Active"
              : "Virtual Active",
        issuedAt: new Date(createdAt).toLocaleDateString("en-US"),
        linkedAccount:
          walletAccountNumber || `Wallet ****${wallet.id.slice(-4)}`,
        dailyLimit: "$25,000",
        contactless:
          primaryCard?.status === "FROZEN" ? "Temporarily disabled" : "Enabled",
        onlinePayment:
          primaryCard?.status === "FROZEN" ? "Temporarily disabled" : "Enabled",
        lastActivity: new Date(updatedAt).toLocaleString("en-US"),
      },
    });
  } catch (err) {
    console.error("Failed to verify card details passcode", err);
    return res
      .status(500)
      .json({ error: "Failed to verify 6-digit passcode." });
  }
});

app.get("/wallet/me", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const payload = await getCachedUserResponse(userId, "wallet", async () => {
      const wallet = await getOrCreateWalletByUserId(userId);
      const metadata =
        wallet.metadata && typeof wallet.metadata === "object"
          ? (wallet.metadata as Record<string, unknown>)
          : {};
      const basePayload: components["schemas"]["Wallet"] = {
        id: wallet.id,
        balance: Number(wallet.balance),
        currency: wallet.currency,
      };

      return {
        ...basePayload,
        accountNumber:
          typeof metadata.accountNumber === "string"
            ? metadata.accountNumber
            : "",
        qrPayload:
          typeof metadata.qrPayload === "string" ? metadata.qrPayload : "",
        qrImageUrl:
          typeof metadata.qrImageUrl === "string" ? metadata.qrImageUrl : "",
      };
    });

    return res.json(payload);
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

    const depositResult = await prisma.$transaction(async (tx) => {
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
      const transaction = decryptStoredTransaction(
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
                metadata: {
                  entry: "CREDIT",
                  source: "SELF_DEPOSIT",
                },
              },
            }),
          },
        }),
      );

      return {
        updated,
        previousBalance: Number(nextWallet.balance),
        transaction,
      };
    });

    notifyBalanceChange({
      to: userDoc.email,
      recipientName: getRecipientName(userDoc),
      direction: "credit",
      amount,
      balance: Number(depositResult.updated.balance),
      currency: depositResult.updated.currency,
      transactionType: "DEPOSIT",
      description: "Wallet deposit",
      occurredAt: new Date().toISOString(),
    });

    await logFundsFlowEvent({
      actor: req.user?.email,
      userId,
      ipAddress: getRequestIp(req),
      channel: "WALLET_DEPOSIT",
      lifecycle: "COMPLETED",
      direction: "INFLOW",
      amount,
      currency: depositResult.updated.currency,
      fromAccount: null,
      toAccount: null,
      fromUserId: userId,
      toUserId: userId,
      transactionId: depositResult.transaction.id,
      sourceLabel: "SELF_DEPOSIT",
      balanceBefore: depositResult.previousBalance,
      balanceAfter: Number(depositResult.updated.balance),
    });

    invalidateUserResponseCache(userId, ["wallet", "transactions"]);

    return res.json({
      id: depositResult.updated.id,
      balance: Number(depositResult.updated.balance),
      currency: depositResult.updated.currency,
    });
  } catch (err) {
    console.error("Failed to deposit", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.post("/transfer/preview", requireAuth, async (req, res) => {
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
    const accountProfile = buildResolvedAccountProfile(user.metadata);

    const storedFaceId = getInternalFaceIdMetadata(user.metadata);
    const hasTransferFaceId =
      storedFaceId?.enabled === true &&
      typeof storedFaceId.descriptor === "string" &&
      storedFaceId.descriptor.length > 0;
    const transferStepUpPolicy = await evaluateTransferStepUpPolicy({
      userId: senderUserId,
      amount: context.amount,
      currency: context.senderWallet.currency,
      toAccount: context.receiverAccountNumber,
    });
    if (transferStepUpPolicy.shouldBlockSmallTransferBurst) {
      const blockedUntil =
        transferStepUpPolicy.blockedUntil ||
        new Date(
          Date.now() + SMALL_TRANSFER_BURST_BLOCK_MINUTES * 60 * 1000,
        ).toISOString();
      const transferAdvisory = buildBlockedTransferAdvisory({
        amount: context.amount,
        currency: context.senderWallet.currency,
        senderBalance: Number(context.senderWallet.balance),
        blockedUntil,
        archetype: "Small Transfer Burst",
        reasons: [
          `You already attempted ${transferStepUpPolicy.recentSmallTransferCount} small transfers in the last ${SMALL_TRANSFER_BURST_WINDOW_MINUTES} minutes.`,
          transferStepUpPolicy.recentSmallTransferSameRecipientCount > 0
            ? `${transferStepUpPolicy.recentSmallTransferSameRecipientCount} of those small transfers targeted this same recipient.`
            : `FPIPay applies a cooldown when small transfers are repeated too quickly.`,
        ],
        timeline: [
          "Repeated low-value transfers were detected in a short time window.",
          "This pattern is commonly used to test account reachability before larger transfers.",
        ],
        recommendedActions: [
          "Wait for the cooldown to finish before trying another low-value transfer.",
          "Only retry sooner if you can explain the burst pattern during manual review.",
        ],
        title: "Small-transfer burst is temporarily blocked",
        message:
          transferStepUpPolicy.blockReason ||
          "Too many low-value transfers were attempted in a short period, so FPIPay applied a temporary cooldown.",
      });
      return res.status(423).json({
        error:
          transferStepUpPolicy.blockReason ||
          "Too many small transfers were attempted in a short period.",
        previewStatus: "blocked",
        anomaly: {
          ...DEFAULT_AI_RESPONSE,
          requestKey: null,
          riskLevel: "high",
          finalAction: "HOLD_REVIEW",
          finalScore: 92,
          reasons: transferAdvisory.reasons,
          archetype: transferAdvisory.archetype,
          headline: transferAdvisory.title,
          summary: transferAdvisory.message,
          nextStep:
            "Wait for the cooldown to finish before starting another low-value transfer.",
        } satisfies AnomalyResponse,
        transferAdvisory,
        faceIdRequired: false,
        faceIdReason: null,
        rollingOutflowAmount: transferStepUpPolicy.rollingOutflowAmount,
        recipient: {
          accountNumber: context.receiverAccountNumber,
          userId: context.resolvedReceiverUserId,
        },
      });
    }
    const [
      failedTx24h,
      velocity1h,
      spendProfile,
      recipientProfile,
      behaviorProfile,
    ] = await Promise.all([
      countRecentFailedTransfers(senderUserId, 24),
      countRecentTransferVelocity(senderUserId, 1),
      getTransferSpendProfile(senderUserId, context.amount),
      getTransferRecipientProfile({
        userId: senderUserId,
        toUserId: context.resolvedReceiverUserId,
        toAccount: context.receiverAccountNumber,
      }),
      getTransferBehaviorProfile({
        userId: senderUserId,
        toAccount: context.receiverAccountNumber,
        amount: context.amount,
      }),
    ]);
    const suspiciousNoteReasons = getSuspiciousTransferNoteReasons(
      context.note,
    );
    const transferNoteLlm = await analyzeTransferNoteWithLlm({
      note: context.note,
      amount: context.amount,
      currency: context.senderWallet.currency,
      accountCategory:
        accountProfile.category.toUpperCase() === "BUSINESS"
          ? "business"
          : "personal",
      accountSegment:
        accountProfile.segment.toUpperCase() === "ENTERPRISE"
          ? "enterprise"
          : accountProfile.segment.toUpperCase() === "SME"
            ? "sme"
            : "personal",
      recipientKnown: recipientProfile.isKnownRecipient,
      balanceImpactRatio:
        Number(context.senderWallet.balance) > 0
          ? context.amount / Number(context.senderWallet.balance)
          : 0,
      sessionRiskLevel: normalizeRiskLevel(
        req.sessionSecurity?.riskLevel || "low",
      ),
      velocity1h,
      recentReviewCount30d: behaviorProfile.recentReviewCount30d,
      recentBlockedCount30d: behaviorProfile.recentBlockedCount30d,
      spendSurgeRatio: spendProfile.spendSurgeRatio,
    });

    let aiResult = DEFAULT_AI_RESPONSE;
    try {
      const aiResp = await fetch(`${AI_URL}/ai/tx/score`, {
        method: "POST",
        headers: buildAiServiceHeaders(),
        body: JSON.stringify({
          ...buildTransferAiScoringPayload({
            senderUserId,
            req,
            amount: context.amount,
            currency: context.senderWallet.currency,
            note: context.note,
            accountProfile,
            failedTx24h,
            velocity1h,
            spendProfile,
            senderBalance: Number(context.senderWallet.balance),
            recipientProfile,
            behaviorProfile,
            transferStepUpPolicy,
            transferNoteLlm,
          }),
          suspiciousNoteCount: suspiciousNoteReasons.length,
        }),
      });
      const rawResult = (await aiResp.json().catch(() => null)) as unknown;
      if (!aiResp.ok) {
        throw new Error(
          `AI transaction scoring failed with status ${aiResp.status}`,
        );
      }
      aiResult = normalizeAiResponse(rawResult);
    } catch (err) {
      console.warn("AI transaction preview not reachable, using default", err);
    }

    aiResult = softenLowValueTransferAiResult({
      aiResult,
      amount: context.amount,
      recipientKnown: recipientProfile.isKnownRecipient,
      suspiciousNoteCount: suspiciousNoteReasons.length,
      failedTx24h,
      velocity1h,
      sessionRestrictLargeTransfers: Boolean(
        req.sessionSecurity?.restrictLargeTransfers,
      ),
      faceIdRequired: transferStepUpPolicy.faceIdRequired,
      behaviorProfile,
    });
    aiResult = hardenTransferAiResultForAccountProfile({
      aiResult,
      amount: context.amount,
      senderBalance: Number(context.senderWallet.balance),
      accountProfile,
      recipientKnown: recipientProfile.isKnownRecipient,
      faceIdRequired: transferStepUpPolicy.faceIdRequired,
      sessionRestrictLargeTransfers: Boolean(
        req.sessionSecurity?.restrictLargeTransfers,
      ),
      spendProfile,
      behaviorProfile,
      transferNoteLlm,
    });

    const transferAdvisory = buildTransferSafetyAdvisory({
      amount: context.amount,
      senderBalance: Number(context.senderWallet.balance),
      currency: context.senderWallet.currency,
      aiResult,
      transferNoteLlm,
      spendProfile,
      recipientProfile,
      behaviorProfile,
      recipientAccount: context.receiverAccountNumber,
      note: context.note,
      requestKey: aiResult.requestKey,
    });
    const shouldForceFaceIdForHighRisk =
      aiResult.finalAction === "REQUIRE_OTP_FACE_ID" &&
      context.amount >= Math.max(500, TRANSFER_PROBE_SMALL_AMOUNT_MAX * 3) &&
      hasTransferFaceId;
    const effectiveFaceIdRequired =
      transferStepUpPolicy.faceIdRequired || shouldForceFaceIdForHighRisk;
    const effectiveFaceIdReason =
      transferStepUpPolicy.faceIdReason ||
      (shouldForceFaceIdForHighRisk
        ? "High-risk transfers require FaceID verification before completion."
        : null);

    return res.json({
      status: "ok",
      previewStatus:
        transferAdvisory?.severity === "blocked"
          ? "blocked"
          : transferAdvisory?.severity === "warning"
            ? "warning"
            : aiResult.riskLevel,
      anomaly: aiResult,
      transferAdvisory,
      faceIdRequired: effectiveFaceIdRequired,
      faceIdReason: effectiveFaceIdReason,
      rollingOutflowAmount: transferStepUpPolicy.rollingOutflowAmount,
      recipient: {
        accountNumber: context.receiverAccountNumber,
        userId: context.resolvedReceiverUserId,
      },
    });
  } catch (err) {
    if (err instanceof Error && err.message === "MISSING_RECIPIENT_ACCOUNT") {
      return res.status(400).json({ error: "Missing recipient account" });
    }
    if (err instanceof Error && err.message === "RECIPIENT_ACCOUNT_NOT_FOUND") {
      return res.status(404).json({ error: "Recipient account not found" });
    }
    console.error("Failed to preview transfer", err);
    return res.status(500).json({ error: "Failed to preview transfer" });
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
    transferPin?: unknown;
    advisoryAcknowledged?: boolean;
    advisoryRequestKey?: string;
  };
  const auditClientMetadata = buildAuditClientMetadata(req, req.body);
  const transferPin =
    typeof body.transferPin === "string"
      ? body.transferPin.replace(/\D/g, "")
      : "";
  const amount = toPositiveAmount(body.amount);
  if (!amount) return res.status(400).json({ error: "Invalid amount" });
  if (
    isTransferBlockedBySessionSecurity({
      amount,
      sessionSecurity: req.sessionSecurity,
    })
  ) {
    await logFundsFlowEvent({
      actor: req.user?.email,
      userId: senderUserId,
      ipAddress: getRequestIp(req),
      channel: "WALLET_TRANSFER",
      lifecycle: "BLOCKED",
      direction: "OUTFLOW",
      amount,
      currency: "USD",
      toAccount:
        typeof body.toAccount === "string" ? body.toAccount.trim() : null,
      sourceLabel: "SESSION_SECURITY_LIMIT",
    });
    return res.status(403).json({
      error: `Large transfers above $${Number(
        req.sessionSecurity?.maxTransferAmount || MEDIUM_RISK_TRANSFER_LIMIT,
      ).toLocaleString("en-US")} are temporarily restricted for this sign-in.`,
    });
  }

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
    const accountProfile = buildResolvedAccountProfile(user.metadata);
    if (!hasStoredTransferPin(user.metadata)) {
      return res.status(403).json({
        error:
          "You must create a 6-digit transfer PIN before making transfers.",
      });
    }
    if (!(await verifyTransferPinForUser(user, transferPin))) {
      return res.status(400).json({
        error: "Transfer PIN is incorrect",
      });
    }
    const storedFaceId = getInternalFaceIdMetadata(user.metadata);
    const hasTransferFaceId =
      storedFaceId?.enabled === true &&
      typeof storedFaceId.descriptor === "string" &&
      storedFaceId.descriptor.length > 0;
    const transferStepUpPolicy = await evaluateTransferStepUpPolicy({
      userId: senderUserId,
      amount: context.amount,
      currency: context.senderWallet.currency,
      toAccount: context.receiverAccountNumber,
    });
    if (transferStepUpPolicy.shouldBlockSmallTransferBurst) {
      await logFundsFlowEvent({
        actor: req.user?.email,
        userId: senderUserId,
        ipAddress: getRequestIp(req),
        channel: "WALLET_TRANSFER",
        lifecycle: "BLOCKED",
        direction: "OUTFLOW",
        amount: context.amount,
        currency: context.senderWallet.currency,
        fromAccount: context.senderAccountNumber,
        toAccount: context.receiverAccountNumber,
        fromUserId: senderUserId,
        toUserId: context.resolvedReceiverUserId,
        balanceBefore: Number(context.senderWallet.balance),
        balanceAfter: Math.max(
          0,
          Number(context.senderWallet.balance) - context.amount,
        ),
        sourceLabel: "SMALL_TRANSFER_BURST_BLOCK",
      });
      return res.status(423).json({
        error:
          transferStepUpPolicy.blockReason ||
          "Too many small transfers were attempted in a short period.",
        blockedUntil: transferStepUpPolicy.blockedUntil,
        retryAfterSeconds: transferStepUpPolicy.retryAfterSeconds,
      });
    }
    if (transferStepUpPolicy.shouldBlockContinuousLargeTransfer) {
      await logFundsFlowEvent({
        actor: req.user?.email,
        userId: senderUserId,
        ipAddress: getRequestIp(req),
        channel: "WALLET_TRANSFER",
        lifecycle: "BLOCKED",
        direction: "OUTFLOW",
        amount: context.amount,
        currency: context.senderWallet.currency,
        fromAccount: context.senderAccountNumber,
        toAccount: context.receiverAccountNumber,
        fromUserId: senderUserId,
        toUserId: context.resolvedReceiverUserId,
        balanceBefore: Number(context.senderWallet.balance),
        balanceAfter: Math.max(
          0,
          Number(context.senderWallet.balance) - context.amount,
        ),
        sourceLabel: "CONTINUOUS_LARGE_TRANSFER_BLOCK",
      });
      runAsyncSideEffect("sendTransferRiskAlertEmail", () =>
        sendTransferRiskAlertEmail({
          to: user.email,
          recipientName: user.fullName || user.email.split("@")[0] || "User",
          amount: context.amount,
          currency: context.senderWallet.currency,
          toAccount: context.receiverAccountNumber,
          reason:
            transferStepUpPolicy.blockReason ||
            "Repeated large outgoing transfers were detected.",
          totalOutflowWindow: transferStepUpPolicy.rollingOutflowAmount,
          windowLabel: formatRetryWait(
            CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_SECONDS,
          ),
          actionRequired: "blocked",
        }),
      );
      return res.status(423).json({
        error:
          transferStepUpPolicy.blockReason ||
          "Repeated high-value transfers are temporarily blocked.",
        blockedUntil: transferStepUpPolicy.blockedUntil,
        retryAfterSeconds: transferStepUpPolicy.retryAfterSeconds,
      });
    }
    if (transferStepUpPolicy.faceIdRequired && !hasTransferFaceId) {
      await logFundsFlowEvent({
        actor: req.user?.email,
        userId: senderUserId,
        ipAddress: getRequestIp(req),
        channel: "WALLET_TRANSFER",
        lifecycle: "BLOCKED",
        direction: "OUTFLOW",
        amount: context.amount,
        currency: context.senderWallet.currency,
        fromAccount: context.senderAccountNumber,
        toAccount: context.receiverAccountNumber,
        fromUserId: senderUserId,
        toUserId: context.resolvedReceiverUserId,
        balanceBefore: Number(context.senderWallet.balance),
        balanceAfter: Math.max(
          0,
          Number(context.senderWallet.balance) - context.amount,
        ),
        sourceLabel: "FACE_ID_REQUIRED",
      });
      runAsyncSideEffect("sendTransferRiskAlertEmail", () =>
        sendTransferRiskAlertEmail({
          to: user.email,
          recipientName: user.fullName || user.email.split("@")[0] || "User",
          amount: context.amount,
          currency: context.senderWallet.currency,
          toAccount: context.receiverAccountNumber,
          reason:
            transferStepUpPolicy.faceIdReason ||
            `Transfers above ${formatMoneyAmount(
              context.senderWallet.currency,
              TRANSFER_FACE_ID_THRESHOLD,
            )} require FaceID verification.`,
          totalOutflowWindow: transferStepUpPolicy.rollingOutflowAmount,
          windowLabel: `${CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES} minutes`,
          actionRequired: "faceid",
        }),
      );
      return res.status(403).json({
        error:
          transferStepUpPolicy.faceIdReason ||
          `Transfers above $${TRANSFER_FACE_ID_THRESHOLD.toLocaleString(
            "en-US",
          )} require FaceID enrollment on this account.`,
      });
    }

    const existingSafetyHold = getTransferSafetyHold(user.metadata);
    const hasMatchingSafetyHold = Boolean(
      existingSafetyHold &&
      matchesTransferSafetyHold(existingSafetyHold, {
        toAccount: context.receiverAccountNumber,
        toUserId: context.resolvedReceiverUserId,
      }),
    );
    if (existingSafetyHold) {
      const isExpired =
        new Date(existingSafetyHold.blockedUntil).getTime() <= Date.now();
      if (isExpired) {
        await userRepository.updateMetadata(
          user.id,
          setTransferSafetyHold(user.metadata, null),
        );
      }
    }

    const [
      failedTx24h,
      velocity1h,
      spendProfile,
      recipientProfile,
      behaviorProfile,
    ] = await Promise.all([
      countRecentFailedTransfers(senderUserId, 24),
      countRecentTransferVelocity(senderUserId, 1),
      getTransferSpendProfile(senderUserId, context.amount),
      getTransferRecipientProfile({
        userId: senderUserId,
        toUserId: context.resolvedReceiverUserId,
        toAccount: context.receiverAccountNumber,
      }),
      getTransferBehaviorProfile({
        userId: senderUserId,
        toAccount: context.receiverAccountNumber,
        amount: context.amount,
      }),
    ]);
    const suspiciousNoteReasons = getSuspiciousTransferNoteReasons(
      context.note,
    );
    const transferNoteLlm = await analyzeTransferNoteWithLlm({
      note: context.note,
      amount: context.amount,
      currency: context.senderWallet.currency,
      accountCategory:
        accountProfile.category.toUpperCase() === "BUSINESS"
          ? "business"
          : "personal",
      accountSegment:
        accountProfile.segment.toUpperCase() === "ENTERPRISE"
          ? "enterprise"
          : accountProfile.segment.toUpperCase() === "SME"
            ? "sme"
            : "personal",
      recipientKnown: recipientProfile.isKnownRecipient,
      balanceImpactRatio:
        Number(context.senderWallet.balance) > 0
          ? context.amount / Number(context.senderWallet.balance)
          : 0,
      sessionRiskLevel: normalizeRiskLevel(
        req.sessionSecurity?.riskLevel || "low",
      ),
      velocity1h,
      recentReviewCount30d: behaviorProfile.recentReviewCount30d,
      recentBlockedCount30d: behaviorProfile.recentBlockedCount30d,
      spendSurgeRatio: spendProfile.spendSurgeRatio,
    });

    let aiResult = DEFAULT_AI_RESPONSE;
    try {
      const aiResp = await fetch(`${AI_URL}/ai/tx/score`, {
        method: "POST",
        headers: buildAiServiceHeaders(),
        body: JSON.stringify({
          ...buildTransferAiScoringPayload({
            senderUserId,
            req,
            amount: context.amount,
            currency: context.senderWallet.currency,
            note: context.note,
            accountProfile,
            failedTx24h,
            velocity1h,
            spendProfile,
            senderBalance: Number(context.senderWallet.balance),
            recipientProfile,
            behaviorProfile,
            transferStepUpPolicy,
            transferNoteLlm,
          }),
          suspiciousNoteCount: suspiciousNoteReasons.length,
        }),
      });
      const rawResult = (await aiResp.json().catch(() => null)) as unknown;
      if (!aiResp.ok) {
        throw new Error(
          `AI transaction scoring failed with status ${aiResp.status}`,
        );
      }
      aiResult = normalizeAiResponse(rawResult);
    } catch (err) {
      console.warn("AI transaction service not reachable, using default", err);
    }

    const isSpendSpikeHigh =
      spendProfile.dailySpendAvg30d > 0 &&
      spendProfile.projectedDailySpend >= spendProfile.dailySpendAvg30d * 100 &&
      spendProfile.projectedDailySpend - spendProfile.dailySpendAvg30d >= 20000;
    aiResult = softenLowValueTransferAiResult({
      aiResult,
      amount: context.amount,
      recipientKnown: recipientProfile.isKnownRecipient,
      suspiciousNoteCount: suspiciousNoteReasons.length,
      failedTx24h,
      velocity1h,
      sessionRestrictLargeTransfers: Boolean(
        req.sessionSecurity?.restrictLargeTransfers,
      ),
      faceIdRequired: transferStepUpPolicy.faceIdRequired,
      behaviorProfile,
    });
    aiResult = hardenTransferAiResultForAccountProfile({
      aiResult,
      amount: context.amount,
      senderBalance: Number(context.senderWallet.balance),
      accountProfile,
      recipientKnown: recipientProfile.isKnownRecipient,
      faceIdRequired: transferStepUpPolicy.faceIdRequired,
      sessionRestrictLargeTransfers: Boolean(
        req.sessionSecurity?.restrictLargeTransfers,
      ),
      spendProfile,
      behaviorProfile,
      transferNoteLlm,
    });

    const transferAdvisory = buildTransferSafetyAdvisory({
      amount: context.amount,
      senderBalance: Number(context.senderWallet.balance),
      currency: context.senderWallet.currency,
      aiResult,
      transferNoteLlm,
      spendProfile,
      recipientProfile,
      behaviorProfile,
      recipientAccount: context.receiverAccountNumber,
      note: context.note,
      requestKey: aiResult.requestKey,
    });
    const transferRequestKey =
      (typeof body.advisoryRequestKey === "string" &&
      body.advisoryRequestKey.trim()
        ? body.advisoryRequestKey.trim()
        : null) ||
      transferAdvisory?.requestKey ||
      aiResult.requestKey ||
      crypto.randomUUID();
    if (hasMatchingSafetyHold && transferAdvisory?.severity !== "blocked") {
      await userRepository.updateMetadata(
        user.id,
        setTransferSafetyHold(user.metadata, null),
      );
    }
    if (aiResult.riskLevel === "high" || isSpendSpikeHigh) {
      await logAuditEvent({
        actor: req.user?.email,
        userId: senderUserId,
        action: "AI_TRANSACTION_ALERT",
        details: {
          message:
            spendProfile.dailySpendAvg30d > 0
              ? `Projected spend ${spendProfile.projectedDailySpend.toLocaleString(
                  "en-US",
                )} is sharply above normal daily behavior (${spendProfile.dailySpendAvg30d.toLocaleString(
                  "en-US",
                  { maximumFractionDigits: 2 },
                )}).`
              : "High-risk transaction detected by transaction monitoring.",
          riskLevel: aiResult.riskLevel,
          amount: context.amount,
          toAccount: context.receiverAccountNumber,
          requestKey: transferRequestKey,
          dailySpendAvg30d: spendProfile.dailySpendAvg30d,
          todaySpendBefore: spendProfile.todaySpendBefore,
          projectedDailySpend: spendProfile.projectedDailySpend,
          spendSurgeRatio: spendProfile.spendSurgeRatio,
          reasons: aiResult.reasons,
        },
        metadata: {
          ...auditClientMetadata,
          requestKey: transferRequestKey,
          spendProfile,
          transferAdvisory: transferAdvisory || undefined,
          aiMonitoring: buildStoredAiMonitoring(aiResult),
        },
        ipAddress: getRequestIp(req),
      });
    }

    const shouldForceFaceIdForHighRisk =
      aiResult.finalAction === "REQUIRE_OTP_FACE_ID" &&
      context.amount >= Math.max(500, TRANSFER_PROBE_SMALL_AMOUNT_MAX * 3) &&
      hasTransferFaceId;
    const effectiveFaceIdRequired =
      transferStepUpPolicy.faceIdRequired || shouldForceFaceIdForHighRisk;
    const effectiveFaceIdReason =
      transferStepUpPolicy.faceIdReason ||
      (shouldForceFaceIdForHighRisk
        ? "High-risk transfers require FaceID verification before completion."
        : null);
    const shouldBlockForHighAiRisk =
      aiResult.riskLevel === "high" && TRANSFER_HIGH_RISK_IMMEDIATE_BLOCK;

    if (transferAdvisory?.severity === "blocked" || shouldBlockForHighAiRisk) {
      const blockedHold: TransferSafetyHold = {
        toAccount: context.receiverAccountNumber,
        toUserId: context.resolvedReceiverUserId,
        amount: context.amount,
        requestKey: transferRequestKey,
        reason:
          transferAdvisory?.reasons[0] ||
          "This transfer matched a high-risk scam pattern.",
        blockedUntil:
          transferAdvisory?.blockedUntil ||
          new Date(Date.now() + TRANSFER_SCAM_HOLD_MS).toISOString(),
        createdAt: new Date().toISOString(),
      };
      await userRepository.updateMetadata(
        user.id,
        setTransferSafetyHold(user.metadata, blockedHold),
      );
      await logAuditEvent({
        actor: req.user?.email,
        userId: senderUserId,
        action: "TRANSFER_SAFETY_BLOCKED",
        details: {
          amount: context.amount,
          toAccount: context.receiverAccountNumber,
          riskLevel: aiResult.riskLevel,
          blockedUntil: blockedHold.blockedUntil,
          reasons: transferAdvisory?.reasons || aiResult.reasons || [],
        },
        metadata: {
          ...auditClientMetadata,
          requestKey: transferRequestKey,
          spendProfile,
          recipientProfile,
          transferAdvisory: transferAdvisory || undefined,
          aiMonitoring: buildStoredAiMonitoring(aiResult),
        },
        ipAddress: getRequestIp(req),
      });

      await logFundsFlowEvent({
        actor: req.user?.email,
        userId: senderUserId,
        ipAddress: getRequestIp(req),
        channel: "WALLET_TRANSFER",
        lifecycle: "BLOCKED",
        direction: "OUTFLOW",
        amount: context.amount,
        currency: context.senderWallet.currency,
        fromAccount: context.senderAccountNumber,
        toAccount: context.receiverAccountNumber,
        fromUserId: senderUserId,
        toUserId: context.resolvedReceiverUserId,
        requestKey: transferRequestKey,
        note: context.note,
        recipientKnown: recipientProfile.isKnownRecipient,
        riskLevel: aiResult.riskLevel,
        riskScore: aiResult.score,
        transferAdvisory: transferAdvisory || null,
        aiMonitoring: aiResult,
        balanceBefore: Number(context.senderWallet.balance),
        balanceAfter: Math.max(
          0,
          Number(context.senderWallet.balance) - context.amount,
        ),
        sourceLabel: "SCAM_PATTERN_BLOCK",
      });

      return res.status(423).json({
        error: shouldBlockForHighAiRisk
          ? "This transfer has been blocked because AI rated it high risk."
          : "This transfer has been temporarily blocked because it matches a high-risk scam pattern.",
        transferAdvisory,
        anomaly: aiResult,
      });
    }

    if (
      transferAdvisory?.severity === "warning" &&
      body.advisoryAcknowledged !== true
    ) {
      await logAuditEvent({
        actor: req.user?.email,
        userId: senderUserId,
        action: "TRANSFER_ADVISORY_PRESENTED",
        details: {
          amount: context.amount,
          toAccount: context.receiverAccountNumber,
          severity: transferAdvisory.severity,
          transferRatio: transferAdvisory.transferRatio,
          remainingBalance: transferAdvisory.remainingBalance,
        },
        metadata: {
          ...auditClientMetadata,
          requestKey: transferRequestKey,
          spendProfile,
          recipientProfile,
          transferAdvisory,
          aiMonitoring: buildStoredAiMonitoring(aiResult),
        },
        ipAddress: getRequestIp(req),
      });

      await logFundsFlowEvent({
        actor: req.user?.email,
        userId: senderUserId,
        ipAddress: getRequestIp(req),
        channel: "WALLET_TRANSFER",
        lifecycle: "REVIEW_REQUIRED",
        direction: "OUTFLOW",
        amount: context.amount,
        currency: context.senderWallet.currency,
        fromAccount: context.senderAccountNumber,
        toAccount: context.receiverAccountNumber,
        fromUserId: senderUserId,
        toUserId: context.resolvedReceiverUserId,
        requestKey: transferAdvisory.requestKey || aiResult.requestKey || null,
        note: context.note,
        recipientKnown: recipientProfile.isKnownRecipient,
        riskLevel: aiResult.riskLevel,
        riskScore: aiResult.score,
        transferAdvisory,
        aiMonitoring: aiResult,
        balanceBefore: Number(context.senderWallet.balance),
        balanceAfter: Math.max(
          0,
          Number(context.senderWallet.balance) - context.amount,
        ),
        sourceLabel: "AI_WARNING_REVIEW",
      });

      return res.status(409).json({
        error:
          transferAdvisory.severity === "warning"
            ? "Please review this high-risk transfer before continuing."
            : "Please review this transfer before continuing.",
        transferAdvisory,
        anomaly: aiResult,
      });
    }

    if (
      transferAdvisory &&
      body.advisoryAcknowledged === true &&
      body.advisoryRequestKey === transferAdvisory.requestKey
    ) {
      await logAuditEvent({
        actor: req.user?.email,
        userId: senderUserId,
        action: "TRANSFER_ADVISORY_ACKNOWLEDGED",
        details: {
          amount: context.amount,
          toAccount: context.receiverAccountNumber,
          severity: transferAdvisory.severity,
          transferRatio: transferAdvisory.transferRatio,
          remainingBalance: transferAdvisory.remainingBalance,
        },
        metadata: {
          ...auditClientMetadata,
          requestKey: transferAdvisory.requestKey,
          spendProfile,
          recipientProfile,
          transferAdvisory,
          aiMonitoring: buildStoredAiMonitoring(aiResult),
        },
        ipAddress: getRequestIp(req),
      });
    }

    const shouldRequireOtpForMediumRisk =
      aiResult.riskLevel === "medium" &&
      (context.amount >= TRANSFER_MEDIUM_RISK_OTP_MIN_AMOUNT ||
        transferAdvisory?.severity === "warning" ||
        transferAdvisory?.requiresAcknowledgement === true);
    const requiresOtp =
      shouldRequireOtpForMediumRisk ||
      aiResult.finalAction === "REQUIRE_OTP" ||
      aiResult.finalAction === "REQUIRE_OTP_FACE_ID" ||
      aiResult.finalAction === "HOLD_REVIEW" ||
      aiResult.riskLevel === "high" ||
      effectiveFaceIdRequired;
    if (!requiresOtp) {
      const completedTransfer = await completeAuthorizedTransfer({
        req,
        senderUser: user,
        senderUserId,
        amount: context.amount,
        toAccount: context.receiverAccountNumber,
        toUserId: context.resolvedReceiverUserId,
        note: context.note,
        transferAiResult: aiResult,
        transferAdvisory,
        transferSpendProfile: spendProfile,
        transferRequestKey,
        verificationMethod: "pin",
        faceIdRequired: false,
        faceIdReason: null,
      });

      return res.json({
        status: "completed",
        transferPinVerified: true,
        otpRequired: false,
        transferAdvisory,
        ...completedTransfer,
      });
    }

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
        currency: context.senderWallet.currency,
        txAiResult: aiResult,
        txSpendProfile: spendProfile,
        txRecipientProfile: recipientProfile,
        transferAdvisory,
        requestKey: transferRequestKey,
        faceIdRequired: effectiveFaceIdRequired,
        faceIdReason: effectiveFaceIdReason,
        rollingOutflowAmount: transferStepUpPolicy.rollingOutflowAmount,
      },
    });

    runAsyncSideEffect("sendTransferOtpEmail", () =>
      sendTransferOtpEmail({
        to: user.email,
        recipientName: user.fullName || user.email.split("@")[0] || "User",
        otpCode: otpChallenge.otpCode,
        expiresInMinutes: TRANSFER_OTP_TTL_MINUTES,
        amount: context.amount,
        toAccount: context.receiverAccountNumber,
      }),
    );

    if (
      effectiveFaceIdRequired &&
      context.amount <= TRANSFER_FACE_ID_THRESHOLD
    ) {
      runAsyncSideEffect("sendTransferRiskAlertEmail", () =>
        sendTransferRiskAlertEmail({
          to: user.email,
          recipientName: user.fullName || user.email.split("@")[0] || "User",
          amount: context.amount,
          currency: context.senderWallet.currency,
          toAccount: context.receiverAccountNumber,
          reason:
            effectiveFaceIdReason ||
            `Your total outgoing transfers in the last ${CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES} minutes require FaceID verification.`,
          totalOutflowWindow: transferStepUpPolicy.rollingOutflowAmount,
          windowLabel: `${CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES} minutes`,
          actionRequired: "faceid",
        }),
      );
    }

    await logAuditEvent({
      actor: req.user?.email,
      userId: senderUserId,
      action: "TRANSFER_OTP_SENT",
      details: {
        challengeId: otpChallenge.challengeId,
        amount: context.amount,
        toAccount: context.receiverAccountNumber,
        txRiskLevel: aiResult.riskLevel,
        txScore: aiResult.score,
        transferAdvisorySeverity: transferAdvisory?.severity || null,
      },
      metadata: {
        ...auditClientMetadata,
        requestKey: transferRequestKey,
        spendProfile,
        recipientProfile,
        transferAdvisory: transferAdvisory || undefined,
        aiMonitoring: buildStoredAiMonitoring(aiResult),
      },
      ipAddress: getRequestIp(req),
    });

    await logFundsFlowEvent({
      actor: req.user?.email,
      userId: senderUserId,
      ipAddress: getRequestIp(req),
      channel: "WALLET_TRANSFER",
      lifecycle: "PENDING_OTP",
      direction: "OUTFLOW",
      amount: context.amount,
      currency: context.senderWallet.currency,
      fromAccount: context.senderAccountNumber,
      toAccount: context.receiverAccountNumber,
      fromUserId: senderUserId,
      toUserId: context.resolvedReceiverUserId,
      requestKey: transferRequestKey,
      note: context.note,
      recipientKnown: recipientProfile.isKnownRecipient,
      riskLevel: aiResult.riskLevel,
      riskScore: aiResult.score,
      transferAdvisory: transferAdvisory || null,
      aiMonitoring: aiResult,
      balanceBefore: Number(context.senderWallet.balance),
      balanceAfter: Math.max(
        0,
        Number(context.senderWallet.balance) - context.amount,
      ),
      sourceLabel: "OTP_SENT",
    });

    return res.json({
      status: "otp_required",
      otpRequired: true,
      transferPinVerified: true,
      challengeId: otpChallenge.challengeId,
      expiresAt: otpChallenge.expiresAt.toISOString(),
      destination: maskEmail(user.email),
      retryAfterSeconds: otpChallenge.retryAfterSeconds,
      anomaly: aiResult,
      transferAdvisory,
      faceIdRequired: effectiveFaceIdRequired,
      faceIdReason: effectiveFaceIdReason,
      rollingOutflowAmount: transferStepUpPolicy.rollingOutflowAmount,
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
      if (err.message === "TRANSFER_MANUAL_REVIEW_REQUIRED") {
        return res.status(423).json({
          error:
            "This transfer exceeds the safe operating band for the current account tier and must be reviewed manually.",
        });
      }
      if (err.message === "TRANSFER_OTP_VERIFICATION_REQUIRED") {
        return res.status(409).json({
          error:
            "This transfer now requires OTP verification because it falls outside the normal account-tier baseline.",
        });
      }
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

app.post("/transfer/advisory/dismiss", requireAuth, async (req, res) => {
  const senderUserId = req.user?.sub;
  if (!senderUserId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    requestKey?: unknown;
    advisory?: unknown;
    toAccount?: unknown;
    amount?: unknown;
  };
  const requestKey =
    typeof body.requestKey === "string" ? body.requestKey.trim() : "";
  const transferAdvisory = normalizeTransferSafetyAdvisory(body.advisory);
  const auditClientMetadata = buildAuditClientMetadata(req, req.body);
  const amount = toPositiveAmount(body.amount);
  const toAccount =
    typeof body.toAccount === "string"
      ? body.toAccount.replace(/\D/g, "").slice(0, 19)
      : "";

  if (!requestKey && !transferAdvisory) {
    return res.status(400).json({ error: "Missing advisory reference" });
  }

  await logAuditEvent({
    actor: req.user?.email,
    userId: senderUserId,
    action: "TRANSFER_ADVISORY_DISMISSED",
    details: {
      amount: amount || transferAdvisory?.amount || null,
      toAccount: toAccount || null,
      severity: transferAdvisory?.severity || null,
      transferRatio: transferAdvisory?.transferRatio || null,
      remainingBalance: transferAdvisory?.remainingBalance || null,
    },
    metadata: {
      ...auditClientMetadata,
      requestKey: requestKey || transferAdvisory?.requestKey || null,
      transferAdvisory: transferAdvisory || undefined,
    },
    ipAddress: getRequestIp(req),
  });

  return res.json({ status: "ok" });
});

app.post("/transfer/flow-event", requireAuth, async (req, res) => {
  const senderUserId = req.user?.sub;
  if (!senderUserId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    eventType?: unknown;
    toAccount?: unknown;
    toUserId?: unknown;
    amount?: unknown;
    note?: unknown;
    requestKey?: unknown;
    step?: unknown;
    reason?: unknown;
    advisory?: unknown;
  };

  const eventType =
    typeof body.eventType === "string" ? body.eventType.trim() : "";
  if (
    eventType !== "STARTED" &&
    eventType !== "CANCELLED" &&
    eventType !== "BLOCKED_POPUP_SHOWN"
  ) {
    return res.status(400).json({ error: "Unsupported transfer flow event" });
  }

  const toAccount =
    typeof body.toAccount === "string"
      ? body.toAccount.replace(/\D/g, "").slice(0, 19)
      : "";
  const toUserId =
    typeof body.toUserId === "string" && body.toUserId.trim()
      ? body.toUserId.trim()
      : null;
  const note =
    typeof body.note === "string" && body.note.trim() ? body.note.trim() : null;
  const requestKey =
    typeof body.requestKey === "string" && body.requestKey.trim()
      ? body.requestKey.trim()
      : null;
  const step =
    typeof body.step === "number" && Number.isFinite(body.step)
      ? Math.trunc(body.step)
      : typeof body.step === "string" && body.step.trim()
        ? body.step.trim()
        : null;
  const reason =
    typeof body.reason === "string" && body.reason.trim()
      ? body.reason.trim()
      : null;
  const amount = toPositiveAmount(body.amount);
  const transferAdvisory = normalizeTransferSafetyAdvisory(body.advisory);
  const auditClientMetadata = buildAuditClientMetadata(req, req.body);

  await logAuditEvent({
    actor: req.user?.email,
    userId: senderUserId,
    action:
      eventType === "STARTED"
        ? "TRANSFER_FLOW_STARTED"
        : eventType === "CANCELLED"
          ? "TRANSFER_FLOW_CANCELLED"
          : "TRANSFER_SAFETY_BLOCKED",
    details: {
      ...(eventType === "BLOCKED_POPUP_SHOWN"
        ? {
            message:
              transferAdvisory?.message ||
              reason ||
              "Transfer was paused before OTP.",
            amount: amount ?? transferAdvisory?.amount ?? null,
            toAccount: toAccount || null,
            blockedUntil: transferAdvisory?.blockedUntil ?? null,
            riskLevel: transferAdvisory?.severity === "blocked" ? "high" : null,
            reasons:
              transferAdvisory?.reasons ||
              (reason ? [reason] : ["Transfer was paused before OTP."]),
          }
        : {
            amount: amount ?? null,
            toAccount: toAccount || null,
            step,
            reason,
          }),
    },
    metadata: {
      ...auditClientMetadata,
      requestKey: requestKey || transferAdvisory?.requestKey || null,
      toUserId,
      note,
      eventType,
      observedAt: new Date().toISOString(),
      transferAdvisory: transferAdvisory || undefined,
    },
    ipAddress: getRequestIp(req),
  });

  if (amount && eventType !== "BLOCKED_POPUP_SHOWN") {
    await logFundsFlowEvent({
      actor: req.user?.email,
      userId: senderUserId,
      ipAddress: getRequestIp(req),
      channel: "WALLET_TRANSFER",
      lifecycle: eventType,
      direction: "OUTFLOW",
      amount,
      currency: "USD",
      toAccount: toAccount || null,
      fromUserId: senderUserId,
      toUserId,
      requestKey,
      note,
      sourceLabel:
        eventType === "STARTED"
          ? "TRANSFER_FLOW_STARTED"
          : "TRANSFER_FLOW_CANCELLED",
    });
  }

  return res.json({ status: "ok" });
});

app.post("/transfer/otp/verify", requireAuth, async (req, res) => {
  const senderUserId = req.user?.sub;
  if (!senderUserId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    challengeId?: unknown;
    otp?: unknown;
  };
  const challengeId =
    typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.replace(/\D/g, "") : "";
  const auditClientMetadata = buildAuditClientMetadata(req, req.body);
  if (!challengeId || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: "Invalid transfer OTP payload" });
  }

  try {
    const { challenge, metadata } = await verifyEmailOtpChallenge({
      userId: senderUserId,
      purpose: "TRANSFER",
      challengeId,
      otp,
    });

    const amount = toPositiveAmount(metadata.amount);
    const currency =
      typeof metadata.currency === "string" && metadata.currency.trim()
        ? metadata.currency.trim()
        : "USD";
    const toAccount =
      typeof metadata.toAccount === "string" ? metadata.toAccount : "";
    const toUserId =
      typeof metadata.toUserId === "string" ? metadata.toUserId : "";
    const transferAiResult = normalizeAiResponse(
      metadata.txAiResult as Record<string, unknown> | undefined,
    );
    const transferAdvisory = normalizeTransferSafetyAdvisory(
      metadata.transferAdvisory,
    );
    const effectiveFinalAction = resolveEffectiveTransferFinalAction(
      transferAiResult,
      {
        note:
          typeof metadata.note === "string" && metadata.note.trim()
            ? metadata.note.trim()
            : null,
        accountProfile: null,
      },
    );

    if (!amount || (!toAccount && !toUserId)) {
      return res
        .status(400)
        .json({ error: "Stored OTP transfer payload is invalid" });
    }
    const faceIdRequired =
      metadata.faceIdRequired === true ||
      effectiveFinalAction === "REQUIRE_OTP_FACE_ID" ||
      amount > TRANSFER_FACE_ID_THRESHOLD;
    const faceIdReason =
      typeof metadata.faceIdReason === "string" ? metadata.faceIdReason : null;
    const rollingOutflowAmount =
      typeof metadata.rollingOutflowAmount === "number"
        ? metadata.rollingOutflowAmount
        : null;
    const transferRequestKey =
      typeof metadata.requestKey === "string" && metadata.requestKey.trim()
        ? metadata.requestKey.trim()
        : transferAiResult.requestKey || transferAdvisory?.requestKey || null;

    await logAuditEvent({
      actor: req.user?.email,
      userId: senderUserId,
      action: "TRANSFER_OTP_PREVERIFIED",
      details: {
        challengeId: challenge.id,
        amount,
        toAccount: toAccount || null,
        txRiskLevel: transferAiResult.riskLevel,
        txScore: transferAiResult.score,
        transferAdvisorySeverity: transferAdvisory?.severity || null,
      },
      metadata: {
        ...auditClientMetadata,
        requestKey: transferRequestKey,
        transferAdvisory: transferAdvisory || undefined,
        aiMonitoring: buildStoredAiMonitoring(transferAiResult),
      },
      ipAddress: getRequestIp(req),
    });

    await logFundsFlowEvent({
      actor: req.user?.email,
      userId: senderUserId,
      ipAddress: getRequestIp(req),
      channel: "WALLET_TRANSFER",
      lifecycle: "OTP_VERIFIED",
      direction: "OUTFLOW",
      amount,
      currency,
      toAccount: toAccount || null,
      fromUserId: senderUserId,
      toUserId: toUserId || null,
      challengeId: challenge.id,
      requestKey: transferRequestKey,
      note: typeof metadata.note === "string" ? metadata.note : null,
      riskLevel: transferAiResult.riskLevel,
      riskScore: transferAiResult.score,
      transferAdvisory: transferAdvisory || null,
      aiMonitoring: transferAiResult,
      sourceLabel: "OTP_PREVERIFIED",
    });

    return res.json({
      status: "ok",
      faceIdRequired,
      faceIdReason,
      rollingOutflowAmount,
      challengeId: challenge.id,
      expiresAt: challenge.expiresAt.toISOString(),
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
      return res.status(429).json({
        error: "Too many invalid OTP attempts",
        remainingAttempts:
          "remainingAttempts" in err
            ? ((err as { remainingAttempts?: number }).remainingAttempts ?? 0)
            : 0,
      });
    }
    if (err instanceof Error && err.message === "OTP_INCORRECT") {
      const remainingAttempts =
        "remainingAttempts" in err
          ? ((err as { remainingAttempts?: number }).remainingAttempts ?? null)
          : null;
      return res.status(400).json({
        error:
          remainingAttempts === null
            ? "Incorrect OTP"
            : `Incorrect OTP. ${remainingAttempts} attempt${
                remainingAttempts === 1 ? "" : "s"
              } remaining.`,
        remainingAttempts,
      });
    }
    console.error("Failed to verify transfer OTP", err);
    return res.status(500).json({ error: "Failed to verify transfer OTP" });
  }
});

app.post("/transfer/confirm", requireAuth, async (req, res) => {
  const senderUserId = req.user?.sub;
  if (!senderUserId) return res.status(401).json({ error: "Unauthorized" });

  const body = req.body as {
    challengeId?: unknown;
    otp?: unknown;
    faceIdEnrollment?: unknown;
  };
  const transferFaceEnrollment = readFaceIdEnrollment(req.body);
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

    const preverifiedChallenge = await verifyEmailOtpChallenge({
      userId: senderUserId,
      purpose: "TRANSFER",
      challengeId,
      otp,
    });
    const { challenge, metadata } = preverifiedChallenge;

    const amount = toPositiveAmount(metadata.amount);
    const toAccount =
      typeof metadata.toAccount === "string" ? metadata.toAccount : "";
    const toUserId =
      typeof metadata.toUserId === "string" ? metadata.toUserId : "";
    const note = typeof metadata.note === "string" ? metadata.note : "";
    const transferAiResult = normalizeAiResponse(
      metadata.txAiResult as Record<string, unknown> | undefined,
    );
    const transferAdvisory = normalizeTransferSafetyAdvisory(
      metadata.transferAdvisory,
    );
    const effectiveFinalAction = resolveEffectiveTransferFinalAction(
      transferAiResult,
      {
        note,
        accountProfile: buildResolvedAccountProfile(senderUser.metadata),
      },
    );
    const transferSpendProfile =
      metadata.txSpendProfile && typeof metadata.txSpendProfile === "object"
        ? (metadata.txSpendProfile as Record<string, unknown>)
        : undefined;
    if (!amount || (!toAccount && !toUserId)) {
      return res
        .status(400)
        .json({ error: "Stored OTP transfer payload is invalid" });
    }
    const faceIdRequired =
      metadata.faceIdRequired === true ||
      effectiveFinalAction === "REQUIRE_OTP_FACE_ID" ||
      amount > TRANSFER_FACE_ID_THRESHOLD;
    const faceIdReason =
      typeof metadata.faceIdReason === "string" ? metadata.faceIdReason : null;
    const transferRequestKey =
      typeof metadata.requestKey === "string" && metadata.requestKey.trim()
        ? metadata.requestKey.trim()
        : transferAdvisory?.requestKey || transferAiResult.requestKey || null;
    if (faceIdRequired) {
      await verifyRequiredTransferFaceId({
        senderUser,
        transferFaceEnrollment,
      });
    }
    await consumeOtpChallenge(challenge.id);
    const completedTransfer = await completeAuthorizedTransfer({
      req,
      senderUser,
      senderUserId,
      amount,
      toAccount,
      toUserId,
      note,
      transferAiResult,
      transferAdvisory,
      transferSpendProfile,
      transferRequestKey,
      verificationMethod: "otp",
      verifiedChallengeId: challenge.id,
      faceIdRequired,
      faceIdReason,
      transferFaceEnrollment,
      faceIdPreverified: faceIdRequired,
    });

    return res.json({
      status: "ok",
      otpRequired: false,
      transferPinVerified: true,
      ...completedTransfer,
    });
  } catch (err) {
    if (err instanceof Error && err.message === "OTP_CHALLENGE_NOT_FOUND") {
      return res.status(404).json({ error: "OTP challenge not found" });
    }
    if (err instanceof Error && err.message === "OTP_CHALLENGE_ALREADY_USED") {
      const replayResponse =
        await findCompletedTransferReplayResponseByChallenge({
          userId: senderUserId,
          challengeId,
        });
      if (replayResponse) {
        return res.json(replayResponse);
      }
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
    if (err instanceof Error && err.message === "INVALID_TRANSFER_PAYLOAD") {
      return res
        .status(400)
        .json({ error: "Stored OTP transfer payload is invalid" });
    }
    if (
      err instanceof Error &&
      err.message === "TRANSFER_MANUAL_REVIEW_REQUIRED"
    ) {
      return res.status(423).json({
        error:
          "This transfer exceeds the safe operating band for the current account tier and must be reviewed manually.",
      });
    }
    if (
      err instanceof Error &&
      err.message === "TRANSFER_OTP_VERIFICATION_REQUIRED"
    ) {
      return res.status(409).json({
        error:
          "This transfer now requires OTP verification because it falls outside the normal account-tier baseline.",
      });
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
    if (
      err instanceof Error &&
      err.message === "TRANSFER_FACE_ID_ENROLLMENT_REQUIRED"
    ) {
      return res.status(403).json({
        error:
          "Transfers above the FaceID threshold require FaceID enrollment on this account.",
      });
    }
    if (
      err instanceof Error &&
      err.message === "TRANSFER_FACE_ID_VERIFICATION_REQUIRED"
    ) {
      return res.status(400).json({
        error: "Complete FaceID verification before confirming this transfer.",
      });
    }
    if (
      err instanceof Error &&
      err.message === "TRANSFER_FACE_ID_LEGACY_REENROLL_REQUIRED"
    ) {
      return res.status(403).json({
        error:
          "Your FaceID profile was enrolled with an older sample format. Re-enroll FaceID in account settings once, then try this transfer again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_EXPIRED") {
      return res
        .status(400)
        .json({ error: "FaceID challenge expired. Scan again." });
    }
    if (err instanceof Error && err.message === "INVALID_FACE_ID") {
      return res
        .status(400)
        .json({ error: "Invalid FaceID challenge payload" });
    }
    if (err instanceof Error && err.message === "INVALID_FACE_ID_DESCRIPTOR") {
      return res.status(400).json({ error: "Invalid FaceID biometric sample" });
    }
    if (err instanceof Error && err.message === "FACE_ID_STEP_MISMATCH") {
      return res.status(400).json({
        error: "FaceID verification was not completed correctly.",
      });
    }
    if (
      err instanceof Error &&
      err.message === "FACE_ID_STEP_EVIDENCE_MISSING"
    ) {
      return res.status(400).json({
        error:
          "FaceID live challenge evidence was incomplete. Please scan again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_REQUIRED") {
      return res.status(400).json({
        error: "A 5-second FaceID verification video is required.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_TOO_SHORT") {
      return res.status(400).json({
        error:
          "FaceID video was too short. Record the full 5 seconds and try again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_VIDEO_INVALID") {
      return res.status(400).json({
        error:
          "FaceID video evidence is invalid. Please record a new 5-second clip.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_LIVENESS_TOO_LOW") {
      return res.status(400).json({
        error:
          "FaceID liveness check was too weak. Please scan again with your real face centered in frame.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_MOTION_TOO_LOW") {
      return res.status(400).json({
        error:
          "Face motion was too limited. Move naturally while recording and try again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_EYE_MOTION_TOO_LOW") {
      return res.status(400).json({
        error:
          "Eye landmark motion was too limited. Blink or keep your eyes moving naturally and scan again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_PREVIEW_REQUIRED") {
      return res.status(400).json({
        error: "Face image is required for FaceID verification.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_FACE_TOO_SMALL") {
      return res.status(400).json({
        error: "Move closer to the camera for FaceID verification.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_TOO_FEW_SAMPLES") {
      return res.status(400).json({
        error: "FaceID capture was too short. Please scan again.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_MISMATCH") {
      return res.status(403).json({
        error: "FaceID does not match this account.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_ANTI_SPOOF_FAILED") {
      return res.status(403).json({
        error:
          "Server anti-spoof checks rejected this FaceID scan. Please use a real live face.",
      });
    }
    if (
      err instanceof Error &&
      err.message === "FACE_ID_ANTI_SPOOF_UNAVAILABLE"
    ) {
      return res.status(503).json({
        error:
          "FaceID anti-spoof service is temporarily unavailable. Please try again.",
      });
    }
    console.error("Failed to confirm transfer with OTP", err);
    return res.status(500).json({ error: "Failed to confirm transfer" });
  }
});

app.post("/transfer", requireAuth, async (req, res) => {
  return res.status(410).json({
    error:
      "Direct transfers are disabled. Use /transfer/otp/send and /transfer/confirm so AI scam checks and OTP protection cannot be bypassed.",
  });
});

app.get("/transactions", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const payload = await getCachedUserResponse(
      userId,
      "transactions",
      async () => {
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
          take: 120,
        });

        return txns
          .map((txn) => safelyDecryptTransaction(txn, "/transactions"))
          .filter((txn): txn is NonNullable<typeof txn> => Boolean(txn))
          .map((decrypted) => ({
            id: decrypted.id,
            amount: decrypted.amount,
            type: decrypted.type,
            status: decrypted.status,
            description: decrypted.description ?? undefined,
            createdAt: decrypted.createdAt.toISOString(),
            metadata: decrypted.metadata,
          }));
      },
    );

    return res.json(payload);
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
    const payload = await getCachedUserResponse(
      userId,
      "security",
      async () => {
        const [policy, userDoc] = await Promise.all([
          getSecurityPolicy(),
          createUserRepository().findValidatedById(userId),
        ]);

        if (!userDoc) {
          throw new Error("SECURITY_USER_NOT_FOUND");
        }

        const authSecurityState = getAuthSecurityState(userDoc.metadata);
        const activeSession = authSecurityState.activeSession;
        const currentRequestLocation = getRequestLocation(req);
        const activeSessionReferenceTime = Date.parse(
          authSecurityState.lastLoginAt || activeSession?.issuedAt || "",
        );
        const repo = createLoginEventRepository();
        const since = new Date(
          Date.now() - SECURITY_OVERVIEW_WINDOW_DAYS * 24 * 60 * 60 * 1000,
        );
        const events = await repo.findByUserSince(userId, since, 50);
        const trustedByIp = new Map(
          authSecurityState.trustedIps.map((entry) => [entry.ipAddress, entry]),
        );

        const userFacingEvents = events.filter(
          (event) => !isSyntheticAiLoginEvent(event),
        );
        const visibleEvents = userFacingEvents.length
          ? userFacingEvents
          : events;

        const alerts = visibleEvents.slice(0, 12).map((event) => {
          const normalizedIp = normalizeIpAddress(event.ipAddress);
          return buildUserSecurityAlert(
            event,
            policy.anomalyAlertThreshold,
            normalizedIp ? trustedByIp.get(normalizedIp) : undefined,
          );
        });

        const recentLogins = visibleEvents.slice(0, 20).map((event) => {
          const storedDeviceContext =
            event.metadata && typeof event.metadata === "object"
              ? normalizeClientDeviceContext(
                  (event.metadata as Record<string, unknown>).deviceContext,
                )
              : undefined;
          const eventIsCurrentSessionLogin =
            Boolean(event.success) &&
            Boolean(activeSession) &&
            Number.isFinite(activeSessionReferenceTime) &&
            Math.abs(event.createdAt.getTime() - activeSessionReferenceTime) <=
              30 * 60 * 1000 &&
            (!activeSession?.userAgent ||
              !event.userAgent ||
              event.userAgent === activeSession.userAgent);
          const effectiveIp = normalizeIpAddress(
            event.ipAddress ||
              (eventIsCurrentSessionLogin
                ? activeSession?.ipAddress || authSecurityState.lastLoginIp
                : undefined),
          );
          const effectiveUserAgent =
            event.userAgent ||
            (eventIsCurrentSessionLogin ? activeSession?.userAgent : undefined);
          const currentSessionLocation =
            eventIsCurrentSessionLogin &&
            currentRequestLocation !== "Local device" &&
            currentRequestLocation !== "Private network"
              ? currentRequestLocation
              : undefined;
          const effectiveLocation = buildSecurityLocationLabel({
            location: event.location || currentSessionLocation,
            ipAddress: effectiveIp,
          });
          const deviceSummary = buildUserAgentDeviceSummary(
            effectiveUserAgent,
            storedDeviceContext,
          );
          const trustedIp = effectiveIp
            ? trustedByIp.get(effectiveIp)
            : undefined;
          return {
            id: event.id,
            location: effectiveLocation,
            ipAddress: effectiveIp ?? undefined,
            userAgent: effectiveUserAgent ?? "Unknown device",
            deviceTitle: deviceSummary.title,
            deviceDetail: deviceSummary.detail,
            success: Boolean(event.success),
            anomaly: event.anomaly ?? 0,
            riskUnavailable: isFallbackMonitoringLoginEvent(event),
            createdAt: event.createdAt.toISOString(),
            trustedIp: Boolean(trustedIp),
          };
        });

        const trustedDevices = authSecurityState.trustedIps.map(
          (entry, index) => {
            const matchingEvent = visibleEvents.find(
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
          },
        );

        return {
          alerts,
          recentLogins,
          trustedDevices,
        };
      },
    );

    return res.json(payload);
  } catch (err) {
    if (err instanceof Error && err.message === "SECURITY_USER_NOT_FOUND") {
      return res.status(404).json({ error: "User not found" });
    }
    console.error("Failed to load security overview", err);
    return res.status(500).json({ error: "Internal error" });
  }
});

app.get("/activity/assistant", requireAuth, async (req, res) => {
  const userId = req.user?.sub;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const assistantActions = [
    "BUDGET_PLAN_SAVED",
    "BUDGET_PLAN_CATEGORY_ALLOCATION_UPDATED",
    "BUDGET_PLAN_WARNING_TRIGGERED",
    "BUDGET_PLAN_LIMIT_EXCEEDED",
    "BUDGET_CATEGORY_WARNING_TRIGGERED",
    "BUDGET_CATEGORY_LIMIT_EXCEEDED",
    "BUDGET_ASSISTANT_PREFERENCES_UPDATED",
    "BUDGET_ASSISTANT_DIGEST_SENT",
    "BUDGET_ASSISTANT_PACING_REMINDER_SENT",
  ] as const;

  try {
    const rows = await prisma.auditLog.findMany({
      where: {
        userId,
        action: { in: [...assistantActions] },
      },
      orderBy: { createdAt: "desc" },
      take: 20,
    });

    const notifications = rows.map((row) => {
      const details = normalizeRecord(row.details);
      const currency =
        typeof details.currency === "string" && details.currency.trim()
          ? details.currency.trim().toUpperCase()
          : "USD";

      if (row.action === "BUDGET_ASSISTANT_DIGEST_SENT") {
        const periodLabel =
          typeof details.periodLabel === "string"
            ? details.periodLabel
            : "VaultAI brief";
        const spentAmount =
          typeof details.spentAmount === "number" ? details.spentAmount : 0;
        return {
          id: row.id,
          title: `VaultAI ${periodLabel} brief`,
          message:
            typeof details.headline === "string" && details.headline.trim()
              ? details.headline.trim()
              : "VaultAI generated a fresh financial brief for you.",
          meta:
            typeof details.topCategoryLabel === "string" &&
            details.topCategoryLabel.trim()
              ? `Top category: ${details.topCategoryLabel.trim()}`
              : "Assistant brief ready",
          createdAt: row.createdAt.toISOString(),
          amountText: `${currency} ${spentAmount.toLocaleString("en-US", {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2,
          })}`,
          amountTone: "negative" as const,
        };
      }

      if (row.action === "BUDGET_ASSISTANT_PACING_REMINDER_SENT") {
        const projectedSpendAmount =
          typeof details.projectedSpendAmount === "number"
            ? details.projectedSpendAmount
            : 0;
        return {
          id: row.id,
          title: "VaultAI pace reminder",
          message:
            "Your current spending pace may overshoot the active budget before month end.",
          meta:
            typeof details.periodLabel === "string"
              ? `Tracking period: ${details.periodLabel}`
              : "Projected overspend risk",
          createdAt: row.createdAt.toISOString(),
          amountText: `${currency} ${projectedSpendAmount.toLocaleString(
            "en-US",
            {
              minimumFractionDigits: 2,
              maximumFractionDigits: 2,
            },
          )}`,
          amountTone: "negative" as const,
        };
      }

      if (row.action === "BUDGET_ASSISTANT_PREFERENCES_UPDATED") {
        return {
          id: row.id,
          title: "VaultAI assistant updated",
          message: "Your reminder and automatic brief settings were updated.",
          meta: "Assistant preferences saved",
          createdAt: row.createdAt.toISOString(),
        };
      }

      if (row.action === "BUDGET_PLAN_SAVED") {
        const targetAmount =
          typeof details.targetAmount === "number" ? details.targetAmount : 0;
        return {
          id: row.id,
          title: "Budget plan saved",
          message: "VaultAI saved a new active spending plan for you.",
          meta: "Budget plan updated",
          createdAt: row.createdAt.toISOString(),
          amountText: `${currency} ${targetAmount.toLocaleString("en-US", {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2,
          })}`,
          amountTone: "positive" as const,
        };
      }

      if (row.action === "BUDGET_PLAN_CATEGORY_ALLOCATION_UPDATED") {
        return {
          id: row.id,
          title: "Category mix updated",
          message:
            "VaultAI rebalanced your category allocations from the latest chat instructions.",
          meta: "Spending mix changed",
          createdAt: row.createdAt.toISOString(),
        };
      }

      if (row.action === "BUDGET_PLAN_WARNING_TRIGGERED") {
        return {
          id: row.id,
          title: "Budget warning zone",
          message: "Your overall spending has crossed the warning threshold.",
          meta: "Overall budget alert",
          createdAt: row.createdAt.toISOString(),
        };
      }

      if (row.action === "BUDGET_PLAN_LIMIT_EXCEEDED") {
        return {
          id: row.id,
          title: "Budget exceeded",
          message: "Your overall spending has moved beyond the active budget.",
          meta: "Overall budget alert",
          createdAt: row.createdAt.toISOString(),
        };
      }

      const categoryLabel =
        typeof details.categoryLabel === "string" &&
        details.categoryLabel.trim()
          ? details.categoryLabel.trim()
          : "A spending category";
      const categorySpentAmount =
        typeof details.categorySpentAmount === "number"
          ? details.categorySpentAmount
          : 0;
      return {
        id: row.id,
        title:
          row.action === "BUDGET_CATEGORY_LIMIT_EXCEEDED"
            ? `${categoryLabel} exceeded`
            : `${categoryLabel} warning`,
        message:
          row.action === "BUDGET_CATEGORY_LIMIT_EXCEEDED"
            ? `${categoryLabel} has moved beyond its saved limit.`
            : `${categoryLabel} is close to its saved limit.`,
        meta: "Category budget alert",
        createdAt: row.createdAt.toISOString(),
        amountText: `${currency} ${categorySpentAmount.toLocaleString("en-US", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        })}`,
        amountTone: "negative" as const,
      };
    });

    return res.json(notifications);
  } catch (err) {
    console.error("Failed to load assistant activity", err);
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
  "/admin/users/:id/account-profile",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    try {
      const userRepository = createUserRepository();
      const existingUser = await userRepository.findValidatedById(
        req.params.id,
      );
      if (!existingUser) {
        return res.status(404).json({ error: "User not found" });
      }

      const body = req.body as {
        category?: unknown;
        tier?: unknown;
        approvePending?: unknown;
        confidence?: unknown;
        status?: unknown;
      };
      const currentProfile = buildResolvedAccountProfile(existingUser.metadata);
      const usePendingRequest =
        body.approvePending === true &&
        currentProfile.requestedCategory &&
        currentProfile.requestedTier;
      const nextMetadata = setEffectiveAccountProfileMetadata(
        existingUser.metadata,
        {
          category:
            body.category ??
            (usePendingRequest ? currentProfile.requestedCategory : undefined),
          tier:
            body.tier ??
            (usePendingRequest ? currentProfile.requestedTier : undefined),
          confidence: body.confidence,
          status: normalizeAccountProfileStatus(body.status ?? "VERIFIED"),
          clearPendingRequest: true,
        },
        req.user?.email || "admin",
      );
      const updated = await userRepository.updateMetadata(
        req.params.id,
        nextMetadata,
      );
      const sanitized = sanitizeUser(updated);

      await logAuditEvent({
        actor: req.user?.email || "admin",
        userId: req.params.id,
        action: "ADMIN_ACCOUNT_PROFILE_UPDATED",
        details: {
          previousProfile: currentProfile,
          accountProfile: buildResolvedAccountProfile(updated.metadata),
        },
        ipAddress: getRequestIp(req),
      });

      invalidateUserResponseCache(req.params.id, [
        "auth",
        "security",
        "transactions",
      ]);

      return res.json({
        user: sanitized,
        accountProfile: buildResolvedAccountProfile(updated.metadata),
      });
    } catch (err) {
      console.error("Failed to update admin account profile", err);
      return res.status(400).json({ error: "Invalid user id" });
    }
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
      const policy = await getSecurityPolicy();
      const existingUser = await userRepository.findValidatedById(
        req.params.id,
      );
      const lockoutWindowStart = new Date(
        Date.now() - policy.lockoutMinutes * 60 * 1000,
      );
      await userRepository.setStatus(
        req.params.id,
        statusNormalized as UserStatus,
      );
      let updated = await userRepository.findValidatedById(req.params.id);
      if (updated && existingUser && statusNormalized === "ACTIVE") {
        await prisma.loginEvent.deleteMany({
          where: {
            email: existingUser.email,
            success: false,
            createdAt: { gte: lockoutWindowStart },
          },
        });
        await prisma.otpChallenge.updateMany({
          where: {
            userId: req.params.id,
            purpose: { in: ["LOGIN", "LOGIN_HIGH_RISK"] },
            consumedAt: null,
          },
          data: {
            consumedAt: new Date(),
          },
        });
        updated = await userRepository.updateMetadata(req.params.id, {
          ...(updated.metadata ?? {}),
          lockoutResetAt: new Date().toISOString(),
        });
      }
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

      await logFundsFlowEvent({
        actor: req.user?.email ?? "admin",
        userId: targetUserId,
        ipAddress: getRequestIp(req),
        channel: "ADMIN_TOPUP",
        lifecycle: "COMPLETED",
        direction: "INFLOW",
        amount,
        currency: updated.nextWallet.currency,
        fromUserId: adminUserId,
        toUserId: targetUser.id,
        transactionId: updated.transaction.id,
        sourceLabel: "ADMIN_TOPUP",
        balanceBefore: Number(updated.nextWallet.balance) - amount,
        balanceAfter: Number(updated.nextWallet.balance),
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
    const normalized = txns
      .map((txn) => safelyDecryptTransaction(txn, "/admin/transactions"))
      .filter((txn): txn is NonNullable<typeof txn> => Boolean(txn))
      .map((decrypted) => ({
        id: decrypted.id,
        amount: decrypted.amount,
        type: decrypted.type,
        status: decrypted.status,
        description: decrypted.description ?? "",
        createdAt: decrypted.createdAt,
        fromUserId: decrypted.fromUserId ?? undefined,
        toUserId: decrypted.toUserId ?? undefined,
      }));
    res.json(normalized);
  },
);

app.get(
  "/admin/alerts",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const limit = Math.min(
      parseInt(String(req.query.limit ?? "100"), 10) || 100,
      200,
    );
    const statusFilter = normalizeAdminAlertStatus(req.query.status);

    const alertLogs = await prisma.auditLog.findMany({
      where: {
        action: { in: [...AI_ALERT_ACTIONS] },
      },
      orderBy: { createdAt: "desc" },
      take: limit,
    });

    const seenAlertKeys = new Set<string>();
    const alerts = alertLogs
      .filter((log: (typeof alertLogs)[number]) => {
        const dedupKey = buildAdminAlertDedupKey({
          userId: log.userId,
          action: log.action,
          createdAt: log.createdAt,
          details: log.details,
          metadata: log.metadata,
        });
        if (seenAlertKeys.has(dedupKey)) {
          return false;
        }
        seenAlertKeys.add(dedupKey);
        return true;
      })
      .map((log: (typeof alertLogs)[number]) =>
        buildAdminAlertResponse({
          id: log.id,
          userId: log.userId,
          actor: log.actor,
          action: log.action,
          details: log.details,
          ipAddress: log.ipAddress,
          createdAt: log.createdAt,
          metadata: log.metadata,
        }),
      )
      .filter((alert: AdminAlertResponse) => {
        const requestedStatus =
          typeof req.query.status === "string" ? req.query.status.trim() : "";
        return requestedStatus ? alert.adminStatus === statusFilter : true;
      });

    res.json(alerts);
  },
);

app.patch(
  "/admin/alerts/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const alertId = String(req.params.id || "").trim();
    if (!alertId) {
      return res.status(400).json({ error: "Alert id is required" });
    }

    const status = normalizeAdminAlertStatus(req.body?.status);
    const note = typeof req.body?.note === "string" ? req.body.note.trim() : "";

    const existing = await prisma.auditLog.findUnique({
      where: { id: alertId },
    });
    if (
      !existing ||
      !AI_ALERT_ACTIONS.includes(
        existing.action as (typeof AI_ALERT_ACTIONS)[number],
      )
    ) {
      return res.status(404).json({ error: "Alert not found" });
    }

    const existingDetails = normalizeRecord(existing.details);
    const existingMetadata = normalizeRecord(existing.metadata);
    const reviewedAt = new Date().toISOString();
    const reviewedBy = req.user?.email || "admin";

    const nextDetails = {
      ...existingDetails,
      adminStatus: status,
      adminNote: note || null,
      reviewedAt,
      reviewedBy,
    };
    const nextMetadata = {
      ...existingMetadata,
      adminStatus: status,
      adminNote: note || null,
      reviewedAt,
      reviewedBy,
    };

    const updated = await prisma.auditLog.update({
      where: { id: alertId },
      data: {
        details: nextDetails as never,
        metadata: nextMetadata as never,
      },
    });

    await logAuditEvent({
      actor: reviewedBy,
      userId: updated.userId ?? undefined,
      action: "AI_ALERT_REVIEW_UPDATED",
      details: {
        alertId,
        sourceAction: updated.action,
        status,
        note: note || null,
      },
      ipAddress: getRequestIp(req),
      metadata: {
        alertId,
        status,
      },
    });

    return res.json(
      buildAdminAlertResponse({
        id: updated.id,
        userId: updated.userId,
        actor: updated.actor,
        action: updated.action,
        details: updated.details,
        ipAddress: updated.ipAddress,
        createdAt: updated.createdAt,
        metadata: updated.metadata,
      }),
    );
  },
);

app.get(
  "/admin/audit-logs",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const page = Math.max(parseInt(String(req.query.page ?? "1"), 10) || 1, 1);
    const pageSize = Math.min(
      Math.max(parseInt(String(req.query.pageSize ?? "10"), 10) || 10, 1),
      100,
    );
    const rangeDays = Math.max(
      parseInt(String(req.query.rangeDays ?? "30"), 10) || 30,
      0,
    );
    const activity =
      typeof req.query.activity === "string"
        ? req.query.activity.trim()
        : "all";
    const status =
      typeof req.query.status === "string" ? req.query.status.trim() : "all";
    const accountQuery =
      typeof req.query.accountQuery === "string"
        ? req.query.accountQuery.trim()
        : "";
    const source =
      typeof req.query.source === "string" ? req.query.source.trim() : "human";

    const createdAtFilter =
      rangeDays > 0
        ? { gte: new Date(Date.now() - rangeDays * 24 * 60 * 60 * 1000) }
        : undefined;

    const logs = await prisma.auditLog.findMany({
      where: {
        createdAt: createdAtFilter,
        ...(accountQuery
          ? {
              actor: {
                contains: accountQuery,
                mode: "insensitive",
              },
            }
          : {}),
      },
      orderBy: { createdAt: "desc" },
    });

    const filtered = logs.filter((log) => {
      const category = inferAdminAuditCategory(log.action);
      const inferredStatus = inferAdminAuditStatus(log.action, log.details);
      const inferredSource = inferAdminAuditSource({
        actor: log.actor,
        action: log.action,
        metadata: log.metadata,
      });

      if (activity !== "all" && category !== activity) return false;
      if (status !== "all" && inferredStatus !== status) return false;
      if (source !== "all" && inferredSource !== source) return false;
      return true;
    });

    const totalCount = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
    const currentPage = Math.min(page, totalPages);
    const start = (currentPage - 1) * pageSize;
    const pageItems = filtered.slice(start, start + pageSize);

    const normalized = pageItems.map((log) => ({
      id: log.id,
      actor: log.actor,
      action: log.action,
      details: log.details ?? "",
      ipAddress: log.ipAddress ?? "unknown",
      createdAt: log.createdAt,
      metadata: log.metadata ?? {},
    }));
    res.json({
      logs: normalized,
      totalCount,
      page: currentPage,
      pageSize,
      totalPages,
    });
  },
);

app.get(
  "/admin/funds-flow-dataset",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const limit = Math.min(
      parseInt(String(req.query.limit ?? "1000"), 10) || 1000,
      FUNDS_FLOW_DATASET_LIMIT_MAX,
    );
    const format =
      String(req.query.format ?? "json").toLowerCase() === "csv"
        ? "csv"
        : "json";
    const lifecycleFilter = new Set(
      parseFundsFlowListFilter(req.query.lifecycle),
    );
    const directionFilter = new Set(
      parseFundsFlowListFilter(req.query.direction),
    );
    const channelFilter = new Set(parseFundsFlowListFilter(req.query.channel));
    const userId =
      typeof req.query.userId === "string" && req.query.userId.trim().length > 0
        ? req.query.userId.trim()
        : null;
    const from =
      typeof req.query.from === "string" &&
      !Number.isNaN(Date.parse(req.query.from))
        ? new Date(req.query.from)
        : null;
    const to =
      typeof req.query.to === "string" &&
      !Number.isNaN(Date.parse(req.query.to))
        ? new Date(req.query.to)
        : null;

    const logs = await prisma.auditLog.findMany({
      where: {
        action: "FUNDS_FLOW_EVENT",
        ...(userId ? { userId } : {}),
        ...(from || to
          ? {
              createdAt: {
                ...(from ? { gte: from } : {}),
                ...(to ? { lte: to } : {}),
              },
            }
          : {}),
      },
      orderBy: { createdAt: "desc" },
      take: FUNDS_FLOW_DATASET_LIMIT_MAX,
      select: {
        id: true,
        actor: true,
        userId: true,
        ipAddress: true,
        createdAt: true,
        metadata: true,
      },
    });

    const rows = logs
      .map(toFundsFlowDatasetRow)
      .filter((row): row is FundsFlowDatasetRow => Boolean(row))
      .filter(
        (row) =>
          (lifecycleFilter.size === 0 || lifecycleFilter.has(row.lifecycle)) &&
          (directionFilter.size === 0 || directionFilter.has(row.direction)) &&
          (channelFilter.size === 0 || channelFilter.has(row.channel)),
      )
      .slice(0, limit);

    const summary = rows.reduce(
      (acc, row) => {
        acc.byLifecycle[row.lifecycle] =
          (acc.byLifecycle[row.lifecycle] || 0) + 1;
        acc.byDirection[row.direction] =
          (acc.byDirection[row.direction] || 0) + 1;
        acc.byChannel[row.channel] = (acc.byChannel[row.channel] || 0) + 1;
        if (row.direction === "INFLOW") {
          acc.totalInflow += row.amount;
        } else {
          acc.totalOutflow += row.amount;
        }
        return acc;
      },
      {
        byLifecycle: {} as Record<string, number>,
        byDirection: {} as Record<string, number>,
        byChannel: {} as Record<string, number>,
        totalInflow: 0,
        totalOutflow: 0,
      },
    );

    await logAuditEvent({
      actor: req.user?.email ?? "admin",
      userId: req.user?.sub,
      action: "ADMIN_EXPORT_FUNDS_FLOW_DATASET",
      ipAddress: getRequestIp(req),
      details: {
        format,
        limit,
        count: rows.length,
      },
      metadata: {
        format,
        limit,
        count: rows.length,
        filters: {
          lifecycle: Array.from(lifecycleFilter),
          direction: Array.from(directionFilter),
          channel: Array.from(channelFilter),
          userId,
          from: from?.toISOString() ?? null,
          to: to?.toISOString() ?? null,
        },
      },
    });

    if (format === "csv") {
      const columns: Array<keyof FundsFlowDatasetRow> = [
        "id",
        "createdAt",
        "actor",
        "userId",
        "ipAddress",
        "channel",
        "lifecycle",
        "direction",
        "amount",
        "currency",
        "fromAccount",
        "toAccount",
        "fromUserId",
        "toUserId",
        "transactionId",
        "reconciliationId",
        "requestKey",
        "note",
        "sourceLabel",
        "recipientKnown",
        "riskLevel",
        "riskScore",
        "balanceBefore",
        "balanceAfter",
      ];
      const csv = [
        columns.join(","),
        ...rows.map((row) =>
          columns.map((column) => formatCsvValue(row[column])).join(","),
        ),
      ].join("\n");

      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=\"funds-flow-dataset-${new Date()
          .toISOString()
          .slice(0, 19)
          .replace(/[:T]/g, "-")}.csv\"`,
      );
      return res.send(csv);
    }

    return res.json({
      generatedAt: new Date().toISOString(),
      count: rows.length,
      filters: {
        limit,
        lifecycle: Array.from(lifecycleFilter),
        direction: Array.from(directionFilter),
        channel: Array.from(channelFilter),
        userId,
        from: from?.toISOString() ?? null,
        to: to?.toISOString() ?? null,
      },
      summary: {
        ...summary,
        totalInflow: roundMoney(summary.totalInflow),
        totalOutflow: roundMoney(summary.totalOutflow),
      },
      rows,
    });
  },
);

app.post(
  "/admin/ai/tx/retrain",
  requireAuth,
  requireRole(["ADMIN"]),
  async (req, res) => {
    const limit = Math.min(
      Math.max(parseInt(String(req.body?.limit ?? "800"), 10) || 800, 50),
      2500,
    );
    try {
      const dataset = await buildTxRetrainDataset(limit);
      if (dataset.events.length < 10) {
        return res.status(400).json({
          error:
            "Not enough clean completed transfer events are available for retraining.",
          count: dataset.events.length,
        });
      }

      const modelVersion = `admin_tx_iforest_${new Date()
        .toISOString()
        .slice(0, 19)
        .replace(/[:T]/g, "_")}`;
      const response = await fetch(
        `${AI_URL}/ai/tx/train?persist=true&promote=true&model_version=${encodeURIComponent(
          modelVersion,
        )}`,
        {
          method: "POST",
          headers: buildAiServiceHeaders(),
          body: JSON.stringify({ events: dataset.events }),
        },
      );
      const payload = (await response.json().catch(() => null)) as Record<
        string,
        unknown
      > | null;
      if (!response.ok) {
        return res.status(502).json({
          error:
            (typeof payload?.detail === "string" && payload.detail) ||
            "AI service rejected transaction retraining.",
        });
      }

      await logAuditEvent({
        actor: req.user?.email || "admin",
        userId: req.user?.sub,
        action: "ADMIN_TX_MODEL_RETRAINED",
        ipAddress: getRequestIp(req),
        details: {
          modelVersion:
            typeof payload?.model_version === "string"
              ? payload.model_version
              : modelVersion,
          trainSize: dataset.events.length,
          rawCount: dataset.rawCount,
          excludedFlaggedCount: dataset.excludedFlaggedCount,
        },
        metadata: {
          modelVersion:
            typeof payload?.model_version === "string"
              ? payload.model_version
              : modelVersion,
          trainSize: dataset.events.length,
          rawCount: dataset.rawCount,
          excludedFlaggedCount: dataset.excludedFlaggedCount,
        },
      });

      return res.json({
        status: "trained",
        modelVersion:
          typeof payload?.model_version === "string"
            ? payload.model_version
            : modelVersion,
        trainedAt:
          typeof payload?.trained_at === "string"
            ? payload.trained_at
            : new Date().toISOString(),
        trainSize: dataset.events.length,
        rawCount: dataset.rawCount,
        excludedFlaggedCount: dataset.excludedFlaggedCount,
      });
    } catch (err) {
      console.error("Failed to retrain transaction AI model", err);
      return res.status(500).json({
        error: "Failed to retrain transaction AI model",
      });
    }
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

    invalidateSecurityPolicyCache();

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
  if (
    err &&
    typeof err === "object" &&
    "type" in err &&
    (err as { type?: string }).type === "entity.too.large"
  ) {
    res.status(413).json({
      error:
        "Request payload is too large. Please retry with a shorter or smaller capture.",
    });
    return;
  }
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
      if (BOOTSTRAP_DEFAULT_ADMIN) {
        const adminPasswordHash = await hashPassword(DEFAULT_ADMIN_PASSWORD);
        await prisma.user.upsert({
          where: { email: DEFAULT_ADMIN_EMAIL },
          update: {
            passwordHash: adminPasswordHash,
            role: "ADMIN",
            status: "ACTIVE",
          },
          create: {
            id: crypto.randomUUID(),
            email: DEFAULT_ADMIN_EMAIL,
            passwordHash: adminPasswordHash,
            role: "ADMIN",
            status: "ACTIVE",
          },
        });
        console.log(`Bootstrapped admin account. email=${DEFAULT_ADMIN_EMAIL}`);
      } else {
        console.log(
          "Skipping admin bootstrap. Set BOOTSTRAP_DEFAULT_ADMIN=1 to create an initial admin account.",
        );
      }
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
    validateStartupConfiguration();
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
    void ensureLocalAiService();
    void initializeDatabase();
  } catch (err) {
    console.error("Failed to start API server", err);
    process.exit(1);
  }
};

start();
