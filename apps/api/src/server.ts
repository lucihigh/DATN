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
import type { Wallet } from "@prisma/client";

import {
  PROFESSIONAL_PASSWORD_MIN_LENGTH,
  loginSchema,
  meetsProfessionalPasswordPolicy,
  registerSchema,
} from "@secure-wallet/shared";
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
  invalidateSecurityPolicyCache,
} from "./services/securityPolicy";
import { logAuditEvent } from "./services/audit";
import {
  sendBalanceChangeEmail,
  sendCardDetailsOtpEmail,
  sendLoginOtpEmail,
  sendLoginRiskAlertEmail,
  sendPasswordResetOtpEmail,
  sendRegisterOtpEmail,
  sendTransferRiskAlertEmail,
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
app.use(cors());
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
app.use(applySecurityHeaders);
app.use(lockoutGuard);

const PORT = process.env.PORT_API || 4000;
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
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";
const OPENAI_REASONING_EFFORT = process.env.OPENAI_REASONING_EFFORT || "low";
const APP_TIMEZONE = process.env.APP_TIMEZONE || "Asia/Ho_Chi_Minh";
const ADMIN_EMAIL = "ledanhdat56@gmail.com";
const ADMIN_PASSWORD = "Ledanhdat2005@";
const TRANSFER_OTP_TTL_MINUTES = Number(
  process.env.TRANSFER_OTP_TTL_MINUTES || "5",
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
  process.env.FACE_ID_MIN_LIVENESS_SCORE || "0.66",
);
const FACE_ID_MIN_MOTION_SCORE = Number(
  process.env.FACE_ID_MIN_MOTION_SCORE || "0.22",
);
const FACE_ID_MIN_FACE_COVERAGE = Number(
  process.env.FACE_ID_MIN_FACE_COVERAGE || "0.085",
);
const FACE_ID_MIN_SAMPLE_COUNT = Number(
  process.env.FACE_ID_MIN_SAMPLE_COUNT || "12",
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
const FACE_ID_DESCRIPTOR_V2_PREFIX = "faceid_v2:";
const TRANSFER_FACE_ID_THRESHOLD = Number(
  process.env.TRANSFER_FACE_ID_THRESHOLD || "10000",
);
const CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES = Number(
  process.env.CUMULATIVE_TRANSFER_FACE_ID_WINDOW_MINUTES || "10",
);
const CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES = Number(
  process.env.CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES || "5",
);
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
  String(process.env.AUTO_START_LOCAL_AI_SERVICE || "1")
    .trim()
    .toLowerCase(),
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
};

type TransferSafetyAdvisory = {
  requestKey: string | null;
  severity: "caution" | "warning" | "blocked";
  title: string;
  message: string;
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
};

type TransferStepUpPolicy = {
  faceIdRequired: boolean;
  faceIdReason: string | null;
  rollingOutflowAmount: number;
  recentLargeCompletedCount: number;
  shouldBlockContinuousLargeTransfer: boolean;
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
  minFaceCoverage: number;
  minSampleCount: number;
};

type FaceIdEnrollmentSubmission = {
  challengeToken: string;
  descriptor: string;
  livenessScore: number;
  motionScore: number;
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

  return {
    score,
    riskLevel: score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low",
    reasons,
    monitoringOnly: false,
    action: "NOTIFY_ADMIN_ONLY",
    requireOtp: !input.wasTrustedIp,
    otpChannel: !input.wasTrustedIp ? "email" : null,
    otpReason: !input.wasTrustedIp ? "New IP sign-in verification" : null,
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

const normalizeAiResponse = (value: unknown): AnomalyResponse => {
  if (!value || typeof value !== "object") return DEFAULT_AI_RESPONSE;
  const data = value as Record<string, unknown>;
  return {
    score: toAnomalyScore(data.anomaly_score ?? data.score),
    riskLevel: normalizeRiskLevel(data.risk_level ?? data.riskLevel),
    reasons: toStringList(data.reasons),
    monitoringOnly: Boolean(
      data.monitoring_only ?? data.monitoringOnly ?? true,
    ),
    action: typeof data.action === "string" ? data.action : undefined,
    requireOtp: Boolean(data.require_otp_sms ?? data.requireOtp),
    otpChannel:
      typeof data.otp_channel === "string"
        ? data.otp_channel
        : typeof data.otpChannel === "string"
          ? data.otpChannel
          : null,
    otpReason:
      typeof data.otp_reason === "string"
        ? data.otp_reason
        : typeof data.otpReason === "string"
          ? data.otpReason
          : null,
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
    ruleHitCount:
      typeof data.rule_hit_count === "number"
        ? data.rule_hit_count
        : typeof data.ruleHitCount === "number"
          ? data.ruleHitCount
          : undefined,
    ruleHits: normalizeRuleHits(data.rule_hits ?? data.ruleHits),
    warning: normalizeWarningPayload(data.warning_vi ?? data.warning),
  };
};

const AI_ALERT_ACTIONS = [
  "AI_LOGIN_ALERT",
  "AI_TRANSACTION_ALERT",
  "AI_ALERT",
] as const;

const normalizeRecord = (value: unknown): Record<string, unknown> => {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
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
  const type = log.action === "AI_TRANSACTION_ALERT" ? "transaction" : "login";
  const reasons = toStringList(detail.reasons);
  const riskLevel = normalizeRiskLevel(
    detail.riskLevel ?? metadata.riskLevel ?? "low",
  );
  const monitoringOnly = Boolean(
    detail.monitoringOnly ?? metadata.monitoringOnly ?? true,
  );
  const explanation = buildAdminAlertExplanation({
    type,
    riskLevel,
    reasons,
    monitoringOnly,
    aiDecision: asStringOrNull(detail.aiDecision),
  });
  const country = asStringOrNull(detail.country);
  const region = asStringOrNull(detail.region);
  const city = asStringOrNull(detail.city);
  const location =
    [city, region, country].filter(Boolean).join(", ") || country;

  return {
    id: log.id,
    type,
    sourceAction: log.action,
    actor: log.actor,
    userId: log.userId,
    createdAt: log.createdAt.toISOString(),
    ipAddress: log.ipAddress ?? asStringOrNull(detail.ipAddress),
    riskLevel,
    anomalyScore: toAnomalyScore(detail.anomalyScore ?? detail.score),
    reasons,
    summary: explanation.summary,
    explanation: explanation.explanation,
    keySignals: buildAdminAlertSignals(type, detail, riskLevel),
    adminStatus: normalizeAdminAlertStatus(
      detail.adminStatus ?? metadata.adminStatus,
    ),
    adminNote: asStringOrNull(detail.adminNote ?? metadata.adminNote),
    reviewedAt: asStringOrNull(detail.reviewedAt ?? metadata.reviewedAt),
    reviewedBy: asStringOrNull(detail.reviewedBy ?? metadata.reviewedBy),
    monitoringOnly,
    aiDecision: asStringOrNull(detail.aiDecision),
    modelVersion:
      asStringOrNull(detail.modelVersion) ??
      asStringOrNull(metadata.modelVersion),
    modelSource:
      asStringOrNull(detail.modelSource) ??
      asStringOrNull(metadata.modelSource),
    eventId:
      asStringOrNull(detail.loginEventId) ??
      asStringOrNull(detail.transactionEventId) ??
      asStringOrNull(metadata.loginEventId) ??
      asStringOrNull(metadata.transactionEventId),
    transactionId:
      asStringOrNull(detail.transactionId) ??
      asStringOrNull(metadata.transactionId),
    amount: asNumberOrNull(detail.amount),
    currency: asStringOrNull(detail.currency),
    location,
    paymentMethod: asStringOrNull(detail.paymentMethod),
    merchantCategory: asStringOrNull(detail.merchantCategory),
  };
};

const buildSessionSecurityState = (
  riskLevel: AnomalyResponse["riskLevel"],
  options?: {
    reviewReason?: string;
    verificationMethod?: "password" | "email_otp" | "sms_otp";
  },
): SessionSecurityState => ({
  riskLevel,
  reviewReason: options?.reviewReason,
  verificationMethod: options?.verificationMethod ?? "password",
  restrictLargeTransfers: riskLevel === "medium",
  maxTransferAmount:
    riskLevel === "medium" ? MEDIUM_RISK_TRANSFER_LIMIT : undefined,
});

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
};

type MarketIntent = {
  assetClass: "fx" | "crypto" | "commodity" | "stock" | "index";
  symbol: string;
  label: string;
  quoteHint?: string | null;
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
  source: "Yahoo Finance";
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
      /\b(dau tu|loi nhuan|bao lai|tin hieu|san forex|phi vay|hoa hong)\b/i,
    reason:
      "Transfer note references investment or fee-collection language often used in fraud.",
  },
];

const getSuspiciousTransferNoteReasons = (note: string) => {
  const normalizedNote = note.trim();
  if (!normalizedNote) return [];
  return suspiciousTransferNotePatterns
    .filter((entry) => entry.pattern.test(normalizedNote))
    .map((entry) => entry.reason);
};

const isGenericTransferNote = (note: string) => {
  const normalizedNote = note.trim().toLowerCase();
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
  const noteRiskReasons = getSuspiciousTransferNoteReasons(input.note);
  const noteIsGeneric = isGenericTransferNote(input.note);
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
  const hasStrongWarningSignal =
    amount >= HIGH_TRANSFER_ADVISORY_AMOUNT ||
    (hasWarningDrainAmount && transferRatio >= BALANCE_DRAIN_WARNING_RATIO) ||
    (input.spendProfile.dailySpendAvg30d > 0 &&
      input.spendProfile.spendSurgeRatio !== null &&
      input.spendProfile.spendSurgeRatio >= 8) ||
    (noteRiskReasons.length > 0 &&
      amount >= Math.max(500, LARGE_TRANSFER_ADVISORY_AMOUNT * 0.5));

  if (hasMaterialDrainAmount && transferRatio >= BALANCE_DRAIN_ADVISORY_RATIO) {
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
      `This is a high-value transfer for a consumer wallet (${formatMoneyAmount(input.currency, amount)}).`,
    );
  }
  if (qualifiesForRedWarning) {
    severity = "warning";
  }

  if (!input.recipientProfile.isKnownRecipient) {
    addReason(
      `${recipientLabel} has not appeared in your completed transfer history yet.`,
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

  if (input.behaviorProfile.similarFlaggedAmountCount90d > 0) {
    addReason(
      `You had ${input.behaviorProfile.similarFlaggedAmountCount90d} recent transfer attempt${
        input.behaviorProfile.similarFlaggedAmountCount90d === 1 ? "" : "s"
      } near this amount that were reviewed or blocked before completion.`,
    );
    if (qualifiesForRedWarning) {
      severity = "warning";
    }
  }

  if (input.behaviorProfile.sameRecipientFlaggedCount90d > 0) {
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
    input.behaviorProfile.recentReviewCount30d +
      input.behaviorProfile.recentBlockedCount30d >=
    3
  ) {
    addReason(
      `Recent outbound transfer behavior has triggered ${input.behaviorProfile.recentReviewCount30d + input.behaviorProfile.recentBlockedCount30d} AI reviews or blocks in the last 30 days.`,
    );
  }

  if (input.behaviorProfile.recentPendingOtpCount7d >= 4) {
    addReason(
      `You started ${input.behaviorProfile.recentPendingOtpCount7d} outbound transfer verification flows in the last 7 days, which is faster than your usual pace.`,
    );
  }

  for (const noteReason of noteRiskReasons) {
    addReason(noteReason);
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
    addReason(
      "AI sees this transfer as less typical than your recent completed behavior.",
    );
  }
  if (input.aiResult.riskLevel === "high") {
    if (qualifiesForRedWarning && hasStrongWarningSignal) {
      severity = "warning";
    }
    addReason(
      "AI found multiple scam-like signals around this recipient, amount, and transfer pattern.",
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
    input.behaviorProfile.sameRecipientFlaggedCount90d > 0 ||
    input.behaviorProfile.similarFlaggedAmountCount90d > 0;
  const hasHighRiskAiSignal = input.aiResult.riskLevel === "high";
  const shouldBlock =
    hasBlockSizedAmount &&
    ((hasSuspiciousNoteSignal &&
      (!input.recipientProfile.isKnownRecipient ||
        hasNearZeroRemainingBalance)) ||
      (hasNearZeroRemainingBalance &&
        hasRecipientFraudHistory &&
        hasHighRiskAiSignal));

  if (shouldBlock) {
    const blockedUntil = new Date(
      Date.now() + TRANSFER_SCAM_HOLD_MS,
    ).toISOString();
    return buildBlockedTransferAdvisory({
      requestKey: input.requestKey,
      amount,
      currency: input.currency,
      senderBalance,
      blockedUntil,
      reasons: advisoryReasons,
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

  return {
    requestKey: input.requestKey || null,
    severity,
    title,
    message: `${messageLead} ${messageTail}`,
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

const sanitizeCopilotText = (value: string) =>
  value
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

const parseOpenAiCopilotPayload = (
  value: string,
): CopilotResponsePayload | null => {
  try {
    const parsed = JSON.parse(sanitizeCopilotText(value)) as Record<
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

    return {
      reply: parsed.reply.trim(),
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
      followUpQuestion:
        typeof parsed.followUpQuestion === "string" &&
        parsed.followUpQuestion.trim()
          ? parsed.followUpQuestion.trim()
          : null,
    };
  } catch {
    return null;
  }
};

const summarizeCopilotConversation = (messages: CopilotMessagePayload[]) =>
  messages
    .slice(-8)
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

const buildOpenAiCopilotInput = (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
}) => {
  const now = formatMarketTimestamp(new Date());
  const transactionSummary = summarizeCopilotTransactions(
    input.recentTransactions,
    input.currency,
  );
  const conversationSummary = summarizeCopilotConversation(input.messages);

  return [
    `Current time: ${now}`,
    `Preferred response language: ${input.language === "vi" ? "Vietnamese" : "English"}`,
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
    "Conversation transcript:",
    conversationSummary,
  ].join("\n\n");
};

const buildCopilotSystemInstructions = (language: CopilotLanguage) =>
  [
    "You are FPIPay Financial Copilot.",
    "Answer as a practical financial assistant for a wallet app.",
    "Use the wallet context and transaction context provided.",
    `Reply in ${language === "vi" ? "Vietnamese" : "English"} and keep the same language as the user's latest message.`,
    "Prioritize user safety over convenience when the message contains signs of fraud, impersonation, urgency, OTP harvesting, remote-access setup, fake refunds, fake investment schemes, or account-takeover attempts.",
    "If a message looks like a scam, clearly say so, tell the user not to send money or codes, and recommend official verification steps.",
    "You can answer stock-market, equity, index, ETF, and portfolio-allocation questions at an educational and practical level.",
    "For stock-market questions, help with concepts such as ticker basics, index vs stock, sector concentration, diversification, valuation checkpoints, drawdown risk, and how to read metrics like P/E, EPS, market cap, revenue growth, margin, debt, and free cash flow.",
    "When the user asks for market analysis without requiring exact real-time numbers, provide a concise structured framework and clearly label assumptions.",
    "Do not claim real-time market prices unless they were already provided by another tool in the app context.",
    "If the user asks for exact live market prices and no live quote is present, say that live quote support should be used.",
    "Return valid JSON only with these keys:",
    "reply, topic, suggestedActions, suggestedDepositAmount, riskLevel, confidence, followUpQuestion",
    "The reply field may contain Markdown tables.",
    "When presenting amounts, prices, rates, percentages, counts, dates, or other numeric comparisons, format the numeric section as a compact Markdown table.",
    "riskLevel must be one of: low, medium, high.",
    "confidence must be a number between 0 and 1.",
    "suggestedActions must be an array of short strings.",
    "suggestedDepositAmount must be a number or null.",
    "followUpQuestion must be a string or null.",
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
          temperature: 0.2,
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

const callOpenAiCopilot = async (input: {
  currency: string;
  currentBalance: number;
  monthlyIncome: number;
  monthlyExpenses: number;
  recentTransactions: CopilotTransactionPayload[];
  messages: CopilotMessagePayload[];
  language: CopilotLanguage;
}): Promise<OpenAiCopilotResult> => {
  if (!openaiClient) return { status: "disabled" };

  try {
    const response = await openaiClient.responses.create({
      model: OPENAI_MODEL,
      reasoning: {
        effort: OPENAI_REASONING_EFFORT as "low" | "medium" | "high",
      },
      instructions: buildCopilotSystemInstructions(input.language),
      input: buildOpenAiCopilotInput(input),
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

const COPILOT_MARKET_TIMEOUT_MS = Number(
  process.env.COPILOT_MARKET_TIMEOUT_MS || "7000",
);
const COPILOT_COMPANY_ALIASES: Record<string, MarketIntent> = {
  apple: { assetClass: "stock", symbol: "AAPL", label: "Apple" },
  tesla: { assetClass: "stock", symbol: "TSLA", label: "Tesla" },
  nvidia: { assetClass: "stock", symbol: "NVDA", label: "NVIDIA" },
  microsoft: { assetClass: "stock", symbol: "MSFT", label: "Microsoft" },
  google: { assetClass: "stock", symbol: "GOOGL", label: "Alphabet" },
  alphabet: { assetClass: "stock", symbol: "GOOGL", label: "Alphabet" },
  amazon: { assetClass: "stock", symbol: "AMZN", label: "Amazon" },
  meta: { assetClass: "stock", symbol: "META", label: "Meta" },
  netflix: { assetClass: "stock", symbol: "NFLX", label: "Netflix" },
  fpt: { assetClass: "stock", symbol: "FPT.VN", label: "FPT" },
  vnm: { assetClass: "stock", symbol: "VNM.VN", label: "Vinamilk" },
  hpg: { assetClass: "stock", symbol: "HPG.VN", label: "Hoa Phat" },
  vcb: { assetClass: "stock", symbol: "VCB.VN", label: "Vietcombank" },
  vic: { assetClass: "stock", symbol: "VIC.VN", label: "Vingroup" },
  vhm: { assetClass: "stock", symbol: "VHM.VN", label: "Vinhomes" },
  mwg: { assetClass: "stock", symbol: "MWG.VN", label: "Mobile World" },
};
const COPILOT_INDEX_ALIASES: Record<string, MarketIntent> = {
  sp500: { assetClass: "index", symbol: "^GSPC", label: "S&P 500" },
  "s&p500": { assetClass: "index", symbol: "^GSPC", label: "S&P 500" },
  "s&p 500": { assetClass: "index", symbol: "^GSPC", label: "S&P 500" },
  nasdaq: { assetClass: "index", symbol: "^IXIC", label: "NASDAQ Composite" },
  dowjones: { assetClass: "index", symbol: "^DJI", label: "Dow Jones" },
  "dow jones": { assetClass: "index", symbol: "^DJI", label: "Dow Jones" },
  vnindex: { assetClass: "index", symbol: "^VNINDEX", label: "VN-Index" },
  "vn-index": { assetClass: "index", symbol: "^VNINDEX", label: "VN-Index" },
};
const COPILOT_COMMON_MARKET_SYMBOLS = new Set([
  "AAPL",
  "AMZN",
  "BTC",
  "DJI",
  "ETH",
  "EUR",
  "FPT",
  "GC",
  "GOOGL",
  "META",
  "MSFT",
  "NASDAQ",
  "NVDA",
  "S&P",
  "SPY",
  "TSLA",
  "USD",
  "VND",
  "VNINDEX",
  "VNM",
  "XAU",
]);

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

const buildLiveMarketCopilotResponse = async (
  latestMessage: string,
): Promise<CopilotResponsePayload | null> => {
  const language = detectCopilotLanguage(latestMessage);
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
          )} tại ${formatMarketTimestamp(quote.asOf)}. Biến động là ${changeText}.${exchangeText}${marketStateText} Nguồn: ${quote.source}.`
        : `Latest available quote for ${quote.label} is ${quote.currency} ${formatMarketPrice(
            quote.price,
          )} as of ${formatMarketTimestamp(quote.asOf)}. That is ${changeText}.${exchangeText}${marketStateText} Source: ${quote.source}.`,
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

  if (
    !asksCompare &&
    !asksAllocation &&
    !asksValuation &&
    !asksStockLearning &&
    !asksWatchlist
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
    /\b(otp|ma otp|verification code|ma xac minh|faceid|sinh trac|safe account|tai khoan an toan|security team|support team|nhan vien ngan hang|bank staff|refund|hoan tien|customs|hai quan|tax|thue|penalty|phat|unlock|mo khoa|broker|forex|crypto signal|guaranteed return|bao loi nhuan|remote access|anydesk|teamviewer|screen share|chia se man hinh|chuyen ngay|urgent|gap)\b/.test(
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

  if (
    /deposit|top up|fund|emergency|save|nap tien|gui tien|tiet kiem|quy du phong|du phong/.test(
      latest,
    )
  ) {
    const summaryTable = buildCopilotMarkdownTable(
      language === "vi" ? ["Chi so", "Gia tri"] : ["Metric", "Value"],
      [
        [
          language === "vi" ? "So du hien tai" : "Current balance",
          formatCopilotMoney(input.currency, balance),
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
          language === "vi" ? "Muc nap goi y" : "Suggested deposit",
          suggestedDepositAmount !== null
            ? formatCopilotMoney(input.currency, suggestedDepositAmount)
            : language === "vi"
              ? "Can them du lieu"
              : "Need more data",
        ],
      ],
    );
    return {
      reply:
        language === "vi"
          ? netCashFlow > 0
            ? `Vi cua ban co kha nang hap thu mot khoan nap them co ke hoach ma khong gay ap luc lon len dong tien hang thang. Dua tren cac so lieu ban nhap, nap theo tung dot se an toan hon chuyen mot khoan lon ngay lap tuc.\n\n${summaryTable}`
            : `Du lieu hien tai cho thay dong tien tu do dang han che, vi vay toi se uu tien giu thanh khoan va tranh nap them qua manh o luc nay.\n\n${summaryTable}`
          : netCashFlow > 0
            ? `Your wallet can likely absorb a planned top-up without stressing monthly cash flow. Based on the numbers you entered, a staged deposit is safer than moving a large amount at once.\n\n${summaryTable}`
            : `Your current inputs show limited free cash flow, so I would avoid an aggressive top-up and preserve liquidity first.\n\n${summaryTable}`,
      topic: "deposit-planning",
      suggestedActions:
        language === "vi"
          ? [
              "Giu lai it nhat mot chu ky chi phi hang thang o trang thai thanh khoan truoc khi nap them lon.",
              suggestedDepositAmount
                ? `Bat dau voi muc nap khoang ${input.currency} ${suggestedDepositAmount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}.`
                : "Cap nhat thu nhap va chi phi hang thang de toi de xuat muc nap chinh xac hon.",
              "Ra soat cac giao dich ghi no dinh ky de cat giam nhung khoan co the toi uu trong thang nay.",
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
        "Ban muon toi de xuat sat hon cho quy du phong, hoc phi hay phan bo tien dau tu khong?",
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
    /\b(transaction|transactions|giao dich|dong tien|thu chi|money flow|cash flow)\b/.test(
      normalized,
    );
  const asksForReport =
    /\b(report|summary|summarize|list|bao cao|tong hop|liet ke|thong ke)\b/.test(
      normalized,
    ) ||
    /giao dich hom nay|transactions today|today transaction/.test(normalized);

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
    /\b(transaction|transactions|giao dich|dong tien|thu chi|money flow|cash flow)\b/.test(
      normalized,
    );
  const asksForReport =
    /\b(report|summary|summarize|list|bao cao|tong hop|liet ke|thong ke)\b/.test(
      normalized,
    ) || /giao dich tuan|weekly transaction|week transaction/.test(normalized);

  return asksForWeek && asksForTransactions && asksForReport;
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
    ? `- ${timeLabel} | ${input.direction === "credit" ? "Vao" : "Ra"} | ${signedAmount} | ${input.description} (${input.type})`
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
    input.language === "vi" ? ["Chi so", "Gia tri"] : ["Metric", "Value"],
    [
      [
        input.language === "vi" ? "Tong tien vao" : "Total inflow",
        formatCopilotMoney(input.currency, totalInflow),
      ],
      [
        input.language === "vi" ? "Tong tien ra" : "Total outflow",
        formatCopilotMoney(input.currency, totalOutflow),
      ],
      [
        input.language === "vi" ? "Dong tien rong" : "Net flow",
        formatCopilotSignedMoney(input.currency, netFlow),
      ],
      [
        input.language === "vi" ? "So giao dich" : "Transaction count",
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
        ? "Vao"
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
            ? ["Thoi gian", "Huong", "So tien", "Noi dung", "Loai"]
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
        "Khong co giao dich trong khoang thoi gian nay.",
        "There were no transactions in this period.",
      ),
    ].join("\n");
  }

  return [
    input.periodLabel,
    "",
    summaryTable,
    "",
    input.language === "vi" ? "Chi tiet giao dich:" : "Transaction details:",
    "",
    detailsTable,
  ].join("\n");
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
  const walletIds = wallets.map((wallet) => wallet.id);
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
          ? `Bao cao giao dich hom nay (${APP_TIMEZONE}, 00:00 den hien tai):`
          : `Today's transaction report (${APP_TIMEZONE}, 00:00 until now):`,
      detailMode: "time",
    }),
    topic: "today-transaction-report",
    suggestedActions:
      input.language === "vi"
        ? [
            "Hoi them bao cao giao dich tuan nay neu ban muon xem xu huong rong hon.",
            "Hoi rieng tong tien vao hoac tong tien ra neu ban muon rut gon bao cao.",
            "Yeu cau toi danh dau giao dich nao lon nhat trong ngay.",
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
      "Ban co muon toi tach them theo giao dich nap tien, nhan tien va chuyen tien khong?",
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
  const walletIds = wallets.map((wallet) => wallet.id);
  const endExclusive = new Date();
  const startInclusive = new Date(endExclusive);
  startInclusive.setHours(0, 0, 0, 0);
  startInclusive.setDate(startInclusive.getDate() - 6);

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
          ? `Bao cao giao dich 7 ngay gan nhat (${formatCopilotCalendarDate(input.language, startInclusive)} - ${formatCopilotCalendarDate(input.language, endExclusive)}):`
          : `Transaction report for the last 7 days (${formatCopilotCalendarDate(input.language, startInclusive)} - ${formatCopilotCalendarDate(input.language, endExclusive)}):`,
      detailMode: "datetime",
    }),
    topic: "weekly-transaction-report",
    suggestedActions:
      input.language === "vi"
        ? [
            "Hoi them giao dich co gia tri lon nhat trong 7 ngay qua.",
            "Yeu cau tach rieng dong tien vao hoac dong tien ra neu ban muon gon hon.",
            "Hoi them so sanh hom nay voi 7 ngay gan nhat neu ban muon xem xu huong.",
          ]
        : [
            "Ask for the largest transaction in the last 7 days.",
            "Ask for inflows only or outflows only if you want a shorter report.",
            "Ask for a today-vs-week comparison if you want a trend view.",
          ],
    suggestedDepositAmount: null,
    riskLevel: "low",
    confidence: 0.99,
    followUpQuestion: localizeCopilotText(
      input.language,
      "Ban co muon toi tach them theo ngay hoac theo loai giao dich khong?",
      "Do you want this split further by day or by transaction type?",
    ),
  };
};

const sanitizeUser = (user: UserEntity | null) => {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  void passwordHash;
  return rest;
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
  const steps: FaceIdStep[] = ["center", "move_closer"];
  const issuedAt = Date.now();
  const payload: FaceIdChallengePayload = {
    kind: "faceid_v1",
    nonce: crypto.randomUUID(),
    issuedAt,
    expiresAt: issuedAt + FACE_ID_CHALLENGE_TTL_MS,
    steps,
    minLivenessScore: FACE_ID_MIN_LIVENESS_SCORE,
    minMotionScore: FACE_ID_MIN_MOTION_SCORE,
    minFaceCoverage: FACE_ID_MIN_FACE_COVERAGE,
    minSampleCount: FACE_ID_MIN_SAMPLE_COUNT,
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

  if (isV2Pair && typeof alignedScore === "number") {
    return {
      similarity: alignedScore,
      alignedScore,
      geometryScore,
      legacyScore,
      threshold: FACE_ID_V2_MATCH_THRESHOLD,
    };
  }

  const scores: Array<{ score: number; weight: number }> = [];
  if (typeof geometryScore === "number") {
    scores.push({
      score: geometryScore,
      weight: 0.35,
    });
  }
  if (typeof alignedScore === "number") {
    scores.push({
      score: alignedScore,
      weight: 0.65,
    });
  }
  if (typeof legacyScore === "number") {
    scores.push({
      score: legacyScore,
      weight: scores.length ? 0.35 : 1,
    });
  }

  if (!scores.length) {
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

  const totalWeight = scores.reduce((sum, entry) => sum + entry.weight, 0);
  const similarity =
    scores.reduce((sum, entry) => sum + entry.score * entry.weight, 0) /
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
    stepCaptures: Array.isArray(source.stepCaptures)
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
      : [],
    previewImage:
      typeof source.previewImage === "string" ? source.previewImage : undefined,
  };
};

const verifyFaceIdSubmission = (
  submission: FaceIdEnrollmentSubmission,
  storedDescriptor?: string,
) => {
  const challenge = decodeFaceIdChallengeToken(submission.challengeToken);
  if (
    challenge.steps.length < 2 ||
    !challenge.steps.includes("center") ||
    !challenge.steps.includes("move_closer")
  ) {
    throw new Error("FACE_ID_STEP_MISMATCH");
  }
  if (
    submission.completedSteps.length !== challenge.steps.length ||
    submission.completedSteps.some(
      (step, index) => step !== challenge.steps[index],
    )
  ) {
    throw new Error("FACE_ID_STEP_MISMATCH");
  }
  if (
    !submission.previewImage ||
    !submission.previewImage.startsWith("data:image/")
  ) {
    throw new Error("FACE_ID_LOW_LIVENESS");
  }
  if (submission.stepCaptures.length < challenge.steps.length) {
    throw new Error("FACE_ID_STEP_EVIDENCE_MISSING");
  }
  if (submission.livenessScore < challenge.minLivenessScore) {
    throw new Error("FACE_ID_LOW_LIVENESS");
  }
  if (submission.motionScore < challenge.minMotionScore) {
    throw new Error("FACE_ID_LOW_MOTION");
  }
  if (submission.faceCoverage < challenge.minFaceCoverage) {
    throw new Error("FACE_ID_FACE_TOO_SMALL");
  }
  if (submission.sampleCount < challenge.minSampleCount) {
    throw new Error("FACE_ID_TOO_FEW_SAMPLES");
  }

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

  if (
    storedDescriptor &&
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
  const antiSpoof = await assessFaceIdAntiSpoof(submission);
  if (!antiSpoof.passed) {
    throw new Error("FACE_ID_ANTI_SPOOF_FAILED");
  }
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

const buildPublicUserMetadata = (metadata: unknown) => {
  const source =
    metadata && typeof metadata === "object"
      ? { ...(metadata as Record<string, unknown>) }
      : {};
  delete source.faceId;
  delete source.transferSecurity;
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
  return source;
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
    "Security update: add your live FaceID scan after sign-in to keep this account protected.";
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

const countRecentFailedTransfers = async (userId: string, hours: number) =>
  prisma.transaction.count({
    where: {
      fromUserId: userId,
      status: "FAILED",
      createdAt: {
        gte: new Date(Date.now() - hours * 60 * 60 * 1000),
      },
    },
  });

const countRecentTransferVelocity = async (userId: string, hours: number) =>
  prisma.transaction.count({
    where: {
      fromUserId: userId,
      type: "TRANSFER",
      createdAt: {
        gte: new Date(Date.now() - hours * 60 * 60 * 1000),
      },
    },
  });

const getTransferSpendProfile = async (
  userId: string,
  pendingAmount: number,
): Promise<TransferSpendProfile> => {
  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const rows = await prisma.transaction.findMany({
    where: {
      fromUserId: userId,
      type: "TRANSFER",
      status: "COMPLETED",
      createdAt: {
        gte: since,
      },
    },
    orderBy: { createdAt: "desc" },
  });

  const dailyTotals = new Map<string, number>();
  for (const row of rows) {
    const tx = safelyDecryptTransaction(row, "getTransferSpendProfile");
    if (!tx) continue;
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
  const rows = await prisma.transaction.findMany({
    where: {
      fromUserId: input.userId,
      type: "TRANSFER",
      status: "COMPLETED",
      createdAt: {
        gte: since,
      },
    },
    orderBy: { createdAt: "desc" },
  });

  let completedTransfers = 0;
  let totalSent = 0;
  let lastTransferAt: string | null = null;

  for (const row of rows) {
    const tx = safelyDecryptTransaction(row, "getTransferRecipientProfile");
    if (!tx) continue;
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
  const similarAmountTolerance = Math.max(250, input.amount * 0.2);

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

  for (const row of rows) {
    const event = toFundsFlowDatasetRow(row);
    if (
      !event ||
      event.channel !== "WALLET_TRANSFER" ||
      event.direction !== "OUTFLOW"
    ) {
      continue;
    }

    const createdAtMs = new Date(event.createdAt).getTime();
    const amountDelta = Math.abs(event.amount - input.amount);
    const sameRecipient =
      Boolean(input.toAccount) &&
      Boolean(event.toAccount) &&
      event.toAccount === input.toAccount;

    if (event.lifecycle === "COMPLETED") {
      completedOutflowSum90d += event.amount;
      completedOutflowCount90d += 1;
      if (event.amount > maxCompletedOutflow90d) {
        maxCompletedOutflow90d = event.amount;
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
  };
};

const evaluateTransferStepUpPolicy = async (input: {
  userId: string;
  amount: number;
  currency: string;
}) => {
  const now = Date.now();
  const fundsFlowWindowMinutes = Math.max(
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
  const largeTransferSince = new Date(
    now - CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES * 60 * 1000,
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
  const blockedUntilDate =
    shouldBlockContinuousLargeTransfer && latestLargeCompletedAt
      ? new Date(
          latestLargeCompletedAt.getTime() +
            CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES * 60 * 1000,
        )
      : null;
  const retryAfterSeconds = blockedUntilDate
    ? Math.max(1, Math.ceil((blockedUntilDate.getTime() - Date.now()) / 1000))
    : null;
  const blockReason = shouldBlockContinuousLargeTransfer
    ? `Another transfer above ${formatMoneyAmount(
        input.currency,
        TRANSFER_FACE_ID_THRESHOLD,
      )} was completed less than ${CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES} minutes ago. Please wait ${formatRetryWait(
        retryAfterSeconds ??
          CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES * 60,
      )} before sending another high-value transfer.`
    : null;

  return {
    faceIdRequired,
    faceIdReason,
    rollingOutflowAmount: projectedOutflowWindow,
    recentLargeCompletedCount,
    shouldBlockContinuousLargeTransfer,
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
      senderBalance: Number(senderWallet.balance) - input.amount,
      receiverBalance: Number(receiverWallet.balance) + input.amount,
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
  verificationMethod: "pin" | "otp";
  verifiedChallengeId?: string | null;
  faceIdRequired: boolean;
  faceIdReason?: string | null;
  transferFaceEnrollment?: FaceIdEnrollmentSubmission | null;
}) => {
  if (!input.amount || (!input.toAccount && !input.toUserId)) {
    throw new Error("INVALID_TRANSFER_PAYLOAD");
  }

  if (input.faceIdRequired) {
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
      requestKey:
        input.transferAiResult.requestKey ||
        input.transferAdvisory?.requestKey ||
        null,
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
    requestKey:
      input.transferAiResult.requestKey ||
      input.transferAdvisory?.requestKey ||
      null,
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
    requestKey:
      input.transferAiResult.requestKey ||
      input.transferAdvisory?.requestKey ||
      null,
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

app.post("/ai/copilot-chat", requireAuth, async (req, res) => {
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

  const recentTransactions = Array.isArray(body.recentTransactions)
    ? body.recentTransactions.filter(
        (item): item is CopilotTransactionPayload =>
          Boolean(item) &&
          typeof item === "object" &&
          typeof (item as { amount?: unknown }).amount === "number" &&
          typeof (item as { type?: unknown }).type === "string" &&
          typeof (item as { createdAt?: unknown }).createdAt === "string" &&
          ((item as { direction?: unknown }).direction === "credit" ||
            (item as { direction?: unknown }).direction === "debit"),
      )
    : [];

  const currency =
    typeof body.currency === "string" && body.currency.trim()
      ? body.currency.trim().toUpperCase()
      : "USD";

  if (
    req.user?.sub &&
    isWeeklyTransactionReportIntent(latestUserMessage.content)
  ) {
    const weeklyReport = await buildWeeklyTransactionReportResponse({
      userId: req.user.sub,
      currency,
      language,
    });
    return res.json(weeklyReport);
  }

  if (
    req.user?.sub &&
    isTodayTransactionReportIntent(latestUserMessage.content)
  ) {
    const todayReport = await buildTodayTransactionReportResponse({
      userId: req.user.sub,
      currency,
      language,
    });
    return res.json(todayReport);
  }

  const marketResponse = await buildLiveMarketCopilotResponse(
    latestUserMessage.content,
  );
  if (marketResponse) {
    return res.json(marketResponse);
  }

  const copilotInput = {
    currency,
    currentBalance: Number(body.currentBalance || 0),
    monthlyIncome: Number(body.monthlyIncome || 0),
    monthlyExpenses: Number(body.monthlyExpenses || 0),
    recentTransactions,
    messages,
    language,
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
    currency,
    currentBalance: Number(body.currentBalance || 0),
    monthlyIncome: Number(body.monthlyIncome || 0),
    monthlyExpenses: Number(body.monthlyExpenses || 0),
    recentTransactions,
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
      metadata: {
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
          faceCoverage: faceEnrollment.faceCoverage,
          sampleCount: faceEnrollment.sampleCount,
          previewImage: faceEnrollment.previewImage,
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
    if (err instanceof Error && err.message === "FACE_ID_LOW_LIVENESS") {
      return res
        .status(403)
        .json({ error: "FaceID liveness check failed. Real face required." });
    }
    if (err instanceof Error && err.message === "FACE_ID_LOW_MOTION") {
      return res.status(403).json({
        error: "FaceID motion challenge failed. Please move naturally.",
      });
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
      return res
        .status(423)
        .json({ error: "Account temporarily locked due to repeated failures" });
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
    await verifyEmailOtpChallenge({
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

    await consumeOtpChallenge(challengeId);
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
        faceCoverage: faceEnrollment.faceCoverage,
        sampleCount: faceEnrollment.sampleCount,
        previewImage: faceEnrollment.previewImage,
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
      },
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
    if (err instanceof Error && err.message === "FACE_ID_LOW_LIVENESS") {
      return res.status(400).json({
        error:
          "Live face check failed. Photos or static captures are not accepted.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_LOW_MOTION") {
      return res.status(400).json({
        error:
          "Face movement was too limited. Follow the live challenge again.",
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
  };
  const currentPin =
    typeof body.currentPin === "string"
      ? body.currentPin.replace(/\D/g, "")
      : "";
  const newPin =
    typeof body.newPin === "string" ? body.newPin.replace(/\D/g, "") : "";
  if (!/^\d{6}$/.test(newPin)) {
    return res.status(400).json({
      error: "Transfer password must be exactly 6 digits",
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

      const metadata =
        userDoc.metadata && typeof userDoc.metadata === "object"
          ? (userDoc.metadata as Record<string, unknown>)
          : {};
      const authSecurityState = getAuthSecurityState(userDoc.metadata);

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
        metadata: buildPublicUserMetadata(metadata),
        security:
          authSecurityState.activeSession?.security ??
          buildSessionSecurityState("low"),
      };
    });

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
  delete (safeMetadata as Record<string, unknown>).faceId;

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
    await verifyEmailOtpChallenge({
      userId,
      purpose: "CARD_DETAILS",
      challengeId,
      otp,
    });
    await consumeOtpChallenge(challengeId);

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

    const storedFaceId = getInternalFaceIdMetadata(user.metadata);
    const hasTransferFaceId =
      storedFaceId?.enabled === true &&
      typeof storedFaceId.descriptor === "string" &&
      storedFaceId.descriptor.length > 0;
    const transferStepUpPolicy = await evaluateTransferStepUpPolicy({
      userId: senderUserId,
      amount: context.amount,
      currency: context.senderWallet.currency,
    });

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

    let aiResult = DEFAULT_AI_RESPONSE;
    try {
      const aiResp = await fetch(`${AI_URL}/ai/tx/score`, {
        method: "POST",
        headers: buildAiServiceHeaders(),
        body: JSON.stringify({
          userId: senderUserId,
          transactionId: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          amount: context.amount,
          currency: context.senderWallet.currency,
          location: getRequestLocation(req),
          paymentMethod: "wallet_balance",
          merchantCategory: "p2p_transfer",
          device:
            typeof req.headers["user-agent"] === "string"
              ? req.headers["user-agent"]
              : "unknown",
          channel: "web",
          failedTx24h,
          velocity1h,
          dailySpendAvg30d: spendProfile.dailySpendAvg30d,
          todaySpendBefore: spendProfile.todaySpendBefore,
          projectedDailySpend: spendProfile.projectedDailySpend,
          balanceBefore: Number(context.senderWallet.balance),
          remainingBalance: Math.max(
            0,
            Number(context.senderWallet.balance) - context.amount,
          ),
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

    const transferAdvisory = buildTransferSafetyAdvisory({
      amount: context.amount,
      senderBalance: Number(context.senderWallet.balance),
      currency: context.senderWallet.currency,
      aiResult,
      spendProfile,
      recipientProfile,
      behaviorProfile,
      recipientAccount: context.receiverAccountNumber,
      note: context.note,
      requestKey: aiResult.requestKey,
    });
    const shouldForceFaceIdForHighRisk =
      aiResult.riskLevel === "high" && hasTransferFaceId;
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
    });
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
          windowLabel: `${CONTINUOUS_LARGE_TRANSFER_BLOCK_WINDOW_MINUTES} minutes`,
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

    let aiResult = DEFAULT_AI_RESPONSE;
    try {
      const aiResp = await fetch(`${AI_URL}/ai/tx/score`, {
        method: "POST",
        headers: buildAiServiceHeaders(),
        body: JSON.stringify({
          userId: senderUserId,
          transactionId: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          amount: context.amount,
          currency: context.senderWallet.currency,
          location: getRequestLocation(req),
          paymentMethod: "wallet_balance",
          merchantCategory: "p2p_transfer",
          device:
            typeof req.headers["user-agent"] === "string"
              ? req.headers["user-agent"]
              : "unknown",
          channel: "web",
          failedTx24h,
          velocity1h,
          dailySpendAvg30d: spendProfile.dailySpendAvg30d,
          todaySpendBefore: spendProfile.todaySpendBefore,
          projectedDailySpend: spendProfile.projectedDailySpend,
          balanceBefore: Number(context.senderWallet.balance),
          remainingBalance: Math.max(
            0,
            Number(context.senderWallet.balance) - context.amount,
          ),
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
    const transferAdvisory = buildTransferSafetyAdvisory({
      amount: context.amount,
      senderBalance: Number(context.senderWallet.balance),
      currency: context.senderWallet.currency,
      aiResult,
      spendProfile,
      recipientProfile,
      behaviorProfile,
      recipientAccount: context.receiverAccountNumber,
      note: context.note,
      requestKey: aiResult.requestKey,
    });
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
          dailySpendAvg30d: spendProfile.dailySpendAvg30d,
          todaySpendBefore: spendProfile.todaySpendBefore,
          projectedDailySpend: spendProfile.projectedDailySpend,
          spendSurgeRatio: spendProfile.spendSurgeRatio,
          reasons: aiResult.reasons,
        },
        metadata: {
          requestKey: aiResult.requestKey || null,
          spendProfile,
          transferAdvisory: transferAdvisory || undefined,
          aiMonitoring: buildStoredAiMonitoring(aiResult),
        },
        ipAddress: getRequestIp(req),
      });
    }

    const shouldForceFaceIdForHighRisk =
      aiResult.riskLevel === "high" && hasTransferFaceId;
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
        requestKey: transferAdvisory?.requestKey || aiResult.requestKey || null,
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
          requestKey: aiResult.requestKey || null,
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
        requestKey: transferAdvisory?.requestKey || aiResult.requestKey || null,
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
          requestKey: aiResult.requestKey || null,
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
        requestKey: aiResult.requestKey || null,
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
      requestKey: transferAdvisory?.requestKey || aiResult.requestKey || null,
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
  };

  const eventType =
    typeof body.eventType === "string" ? body.eventType.trim() : "";
  if (eventType !== "STARTED" && eventType !== "CANCELLED") {
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

  await logAuditEvent({
    actor: req.user?.email,
    userId: senderUserId,
    action:
      eventType === "STARTED"
        ? "TRANSFER_FLOW_STARTED"
        : "TRANSFER_FLOW_CANCELLED",
    details: {
      amount: amount ?? null,
      toAccount: toAccount || null,
      step,
      reason,
    },
    metadata: {
      requestKey,
      toUserId,
      note,
      eventType,
      observedAt: new Date().toISOString(),
    },
    ipAddress: getRequestIp(req),
  });

  if (amount) {
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

    if (!amount || (!toAccount && !toUserId)) {
      return res
        .status(400)
        .json({ error: "Stored OTP transfer payload is invalid" });
    }
    const faceIdRequired =
      metadata.faceIdRequired === true || amount > TRANSFER_FACE_ID_THRESHOLD;
    const faceIdReason =
      typeof metadata.faceIdReason === "string" ? metadata.faceIdReason : null;
    const rollingOutflowAmount =
      typeof metadata.rollingOutflowAmount === "number"
        ? metadata.rollingOutflowAmount
        : null;

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
        requestKey:
          transferAiResult.requestKey || transferAdvisory?.requestKey || null,
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
      requestKey:
        transferAiResult.requestKey || transferAdvisory?.requestKey || null,
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
    const transferAiResult = normalizeAiResponse(
      metadata.txAiResult as Record<string, unknown> | undefined,
    );
    const transferAdvisory = normalizeTransferSafetyAdvisory(
      metadata.transferAdvisory,
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
      metadata.faceIdRequired === true || amount > TRANSFER_FACE_ID_THRESHOLD;
    const faceIdReason =
      typeof metadata.faceIdReason === "string" ? metadata.faceIdReason : null;
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
      verificationMethod: "otp",
      verifiedChallengeId: challenge.id,
      faceIdRequired,
      faceIdReason,
      transferFaceEnrollment,
    });

    await consumeOtpChallenge(challenge.id);

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
    if (err instanceof Error && err.message === "FACE_ID_LOW_LIVENESS") {
      return res.status(400).json({
        error: "FaceID liveness check failed. Real face required.",
      });
    }
    if (err instanceof Error && err.message === "FACE_ID_LOW_MOTION") {
      return res.status(400).json({
        error: "FaceID motion challenge failed. Please scan again.",
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

    const alerts = alertLogs
      .map((log) =>
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
      .filter((alert) => {
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
    void ensureLocalAiService();
    void initializeDatabase();
  } catch (err) {
    console.error("Failed to start API server", err);
    process.exit(1);
  }
};

start();
