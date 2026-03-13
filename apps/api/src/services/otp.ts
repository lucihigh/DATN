import crypto from "crypto";

import { prisma } from "../db/prisma";

const OTP_RESEND_COOLDOWN_SECONDS = Number(
  process.env.OTP_RESEND_COOLDOWN_SECONDS || "60",
);

export const generateOtpCode = () =>
  String(Math.floor(100000 + Math.random() * 900000));

export const hashOtpCode = (code: string) =>
  crypto.createHash("sha256").update(code).digest("hex");

export const maskEmail = (email: string) => {
  const [local, domain] = email.split("@");
  if (!local || !domain) return email;
  if (local.length <= 4) {
    const head = local.slice(0, 1);
    const tail = local.slice(-1);
    return `${head}${"*".repeat(Math.max(2, local.length - 2))}${tail}@${domain}`;
  }
  const head = local.slice(0, 2);
  const tail = local.slice(-2);
  return `${head}${"*".repeat(Math.max(2, local.length - 4))}${tail}@${domain}`;
};

export const maskPhone = (phone: string) => {
  const digits = phone.replace(/\D/g, "");
  if (digits.length < 4) return phone;
  const tail = digits.slice(-4);
  return `***-***-${tail}`;
};

export const getOtpCooldownRemainingSeconds = async (input: {
  userId: string;
  purpose: string;
  destination: string;
}) => {
  const latest = await prisma.otpChallenge.findFirst({
    where: {
      userId: input.userId,
      purpose: input.purpose,
      channel: "EMAIL",
      destination: input.destination,
      consumedAt: null,
    },
    orderBy: { createdAt: "desc" },
  });
  if (!latest) return 0;

  const elapsedMs = Date.now() - latest.createdAt.getTime();
  const remainingMs = OTP_RESEND_COOLDOWN_SECONDS * 1000 - elapsedMs;
  return remainingMs > 0 ? Math.ceil(remainingMs / 1000) : 0;
};

export const createEmailOtpChallenge = async (input: {
  userId: string;
  purpose: string;
  destination: string;
  ttlMinutes: number;
  maxAttempts: number;
  metadata?: Record<string, unknown>;
}) => {
  const retryAfterSeconds = await getOtpCooldownRemainingSeconds({
    userId: input.userId,
    purpose: input.purpose,
    destination: input.destination,
  });
  if (retryAfterSeconds > 0) {
    const error = new Error("OTP_COOLDOWN_ACTIVE") as Error & {
      retryAfterSeconds: number;
    };
    error.retryAfterSeconds = retryAfterSeconds;
    throw error;
  }

  const otpCode = generateOtpCode();
  const challengeId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + input.ttlMinutes * 60 * 1000);

  await prisma.otpChallenge.create({
    data: {
      id: challengeId,
      userId: input.userId,
      purpose: input.purpose,
      channel: "EMAIL",
      destination: input.destination,
      codeHash: hashOtpCode(otpCode),
      expiresAt,
      maxAttempts: input.maxAttempts,
      metadata: input.metadata as never,
    },
  });

  return {
    challengeId,
    otpCode,
    expiresAt,
    retryAfterSeconds: OTP_RESEND_COOLDOWN_SECONDS,
  };
};

export const createSmsOtpChallenge = async (input: {
  userId: string;
  purpose: string;
  destination: string;
  ttlMinutes: number;
  maxAttempts: number;
  metadata?: Record<string, unknown>;
}) =>
  createEmailOtpChallenge({
    ...input,
    metadata: {
      ...(input.metadata ?? {}),
      deliveryChannel: "SMS",
    },
  });

export const verifyEmailOtpChallenge = async (input: {
  userId: string;
  purpose: string;
  challengeId: string;
  otp: string;
}) => {
  const challenge = await prisma.otpChallenge.findFirst({
    where: {
      id: input.challengeId,
      userId: input.userId,
      purpose: input.purpose,
      channel: "EMAIL",
    },
  });
  if (!challenge) {
    throw new Error("OTP_CHALLENGE_NOT_FOUND");
  }
  if (challenge.consumedAt) {
    throw new Error("OTP_CHALLENGE_ALREADY_USED");
  }
  if (challenge.expiresAt.getTime() < Date.now()) {
    throw new Error("OTP_EXPIRED");
  }
  if (challenge.attempts >= challenge.maxAttempts) {
    throw new Error("OTP_TOO_MANY_ATTEMPTS");
  }

  const expectedHash = hashOtpCode(input.otp);
  if (expectedHash !== challenge.codeHash) {
    await prisma.otpChallenge.update({
      where: { id: challenge.id },
      data: { attempts: { increment: 1 } },
    });
    throw new Error("OTP_INCORRECT");
  }

  const metadata =
    challenge.metadata && typeof challenge.metadata === "object"
      ? (challenge.metadata as Record<string, unknown>)
      : {};

  return { challenge, metadata };
};

export const consumeOtpChallenge = async (challengeId: string) =>
  prisma.otpChallenge.update({
    where: { id: challengeId },
    data: { consumedAt: new Date() },
  });
