import crypto from "crypto";

import dotenv from "dotenv";
import { MongoClient, ObjectId } from "mongodb";
import { PrismaClient } from "@prisma/client";

type Role = "USER" | "ADMIN";
type UserStatus = "ACTIVE" | "DISABLED" | "PENDING";
type TransactionStatus = "PENDING" | "COMPLETED" | "FAILED" | "REVERSED";
type TransactionType = "DEPOSIT" | "WITHDRAW" | "TRANSFER";

dotenv.config();

const prisma = new PrismaClient();

const mongoUri = process.env.MONGODB_URI;
const mongoDbName = process.env.MONGODB_DB || "ComputerResearchProject";

if (!mongoUri) {
  throw new Error("MONGODB_URI is not set");
}

const mongo = new MongoClient(mongoUri);

const toId = (value: unknown): string => {
  if (value instanceof ObjectId) return value.toHexString();
  if (typeof value === "string" && value.trim()) return value;
  return crypto.randomUUID();
};

const toOptionalId = (value: unknown): string | null => {
  if (value instanceof ObjectId) return value.toHexString();
  if (typeof value === "string" && value.trim()) return value;
  return null;
};

const toDate = (value: unknown): Date => {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value;
  const parsed = new Date(value as string | number);
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
};

const toNumber = (value: unknown, fallback = 0): number => {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const safeJson = (value: unknown) =>
  (value === undefined ? undefined : value) as never;

async function migrateUsers(db: Awaited<ReturnType<MongoClient["db"]>>) {
  const docs = await db.collection("users").find({}).toArray();
  const userIds = new Set<string>();
  for (const doc of docs) {
    const id = toId(doc._id);
    userIds.add(id);
    const email =
      typeof doc.email === "string"
        ? doc.email.trim().toLowerCase()
        : `unknown-${id}@local`;
    const role: Role = doc.role === "ADMIN" ? "ADMIN" : "USER";
    const status: UserStatus =
      doc.status === "DISABLED" || doc.status === "PENDING"
        ? doc.status
        : "ACTIVE";

    await prisma.user.upsert({
      where: { id },
      update: {
        email,
        passwordHash: String(doc.passwordHash ?? ""),
        role,
        status,
        fullName: typeof doc.fullName === "string" ? doc.fullName : null,
        phone: safeJson(doc.phone),
        address: safeJson(doc.address),
        dob: safeJson(doc.dob),
        lastLoginAt: doc.lastLoginAt ? toDate(doc.lastLoginAt) : null,
        createdAt: toDate(doc.createdAt),
        updatedAt: toDate(doc.updatedAt),
        metadata: safeJson(doc.metadata ?? {}),
      },
      create: {
        id,
        email,
        passwordHash: String(doc.passwordHash ?? ""),
        role,
        status,
        fullName: typeof doc.fullName === "string" ? doc.fullName : null,
        phone: safeJson(doc.phone),
        address: safeJson(doc.address),
        dob: safeJson(doc.dob),
        lastLoginAt: doc.lastLoginAt ? toDate(doc.lastLoginAt) : null,
        createdAt: toDate(doc.createdAt),
        updatedAt: toDate(doc.updatedAt),
        metadata: safeJson(doc.metadata ?? {}),
      },
    });
  }
  return { count: docs.length, ids: userIds };
}

async function migrateWallets(
  db: Awaited<ReturnType<MongoClient["db"]>>,
  validUserIds: Set<string>,
) {
  const docs = await db.collection("wallets").find({}).toArray();
  const walletIds = new Set<string>();
  for (const doc of docs) {
    const id = toId(doc._id);
    walletIds.add(id);
    const userIdRaw = toOptionalId(doc.userId);
    const userId = userIdRaw && validUserIds.has(userIdRaw) ? userIdRaw : null;

    await prisma.wallet.upsert({
      where: { id },
      update: {
        userId,
        balance: toNumber(doc.balance, 0),
        currency: typeof doc.currency === "string" ? doc.currency : "USD",
        status: typeof doc.status === "string" ? doc.status : "ACTIVE",
        createdAt: toDate(doc.createdAt),
        updatedAt: toDate(doc.updatedAt),
        tags: safeJson(doc.tags ?? []),
        metadata: safeJson(doc.metadata ?? {}),
      },
      create: {
        id,
        userId,
        balance: toNumber(doc.balance, 0),
        currency: typeof doc.currency === "string" ? doc.currency : "USD",
        status: typeof doc.status === "string" ? doc.status : "ACTIVE",
        createdAt: toDate(doc.createdAt),
        updatedAt: toDate(doc.updatedAt),
        tags: safeJson(doc.tags ?? []),
        metadata: safeJson(doc.metadata ?? {}),
      },
    });
  }
  return { count: docs.length, ids: walletIds };
}

async function migrateTransactions(
  db: Awaited<ReturnType<MongoClient["db"]>>,
  validUserIds: Set<string>,
  validWalletIds: Set<string>,
) {
  const docs = await db.collection("transactions").find({}).toArray();
  for (const doc of docs) {
    const id = toId(doc._id);
    const type = ["DEPOSIT", "WITHDRAW", "TRANSFER"].includes(String(doc.type))
      ? String(doc.type)
      : "TRANSFER";
    const status = ["PENDING", "COMPLETED", "FAILED", "REVERSED"].includes(String(doc.status))
      ? String(doc.status)
      : "COMPLETED";
    const walletIdRaw = toOptionalId(doc.walletId);
    const counterpartyWalletIdRaw = toOptionalId(doc.counterpartyWalletId);
    const fromUserIdRaw = toOptionalId(doc.fromUserId);
    const toUserIdRaw = toOptionalId(doc.toUserId);

    await prisma.transaction.upsert({
      where: { id },
      update: {
        walletId:
          walletIdRaw && validWalletIds.has(walletIdRaw) ? walletIdRaw : null,
        counterpartyWalletId:
          counterpartyWalletIdRaw && validWalletIds.has(counterpartyWalletIdRaw)
            ? counterpartyWalletIdRaw
            : null,
        fromUserId:
          fromUserIdRaw && validUserIds.has(fromUserIdRaw)
            ? fromUserIdRaw
            : null,
        toUserId:
          toUserIdRaw && validUserIds.has(toUserIdRaw) ? toUserIdRaw : null,
        amount: toNumber(doc.amount, 0),
        type: type as TransactionType,
        status: status as TransactionStatus,
        description: typeof doc.description === "string" ? doc.description : null,
        createdAt: toDate(doc.createdAt),
        updatedAt: toDate(doc.updatedAt),
        metadata: safeJson(doc.metadata ?? {}),
      },
      create: {
        id,
        walletId:
          walletIdRaw && validWalletIds.has(walletIdRaw) ? walletIdRaw : null,
        counterpartyWalletId:
          counterpartyWalletIdRaw && validWalletIds.has(counterpartyWalletIdRaw)
            ? counterpartyWalletIdRaw
            : null,
        fromUserId:
          fromUserIdRaw && validUserIds.has(fromUserIdRaw)
            ? fromUserIdRaw
            : null,
        toUserId:
          toUserIdRaw && validUserIds.has(toUserIdRaw) ? toUserIdRaw : null,
        amount: toNumber(doc.amount, 0),
        type: type as TransactionType,
        status: status as TransactionStatus,
        description: typeof doc.description === "string" ? doc.description : null,
        createdAt: toDate(doc.createdAt),
        updatedAt: toDate(doc.updatedAt),
        metadata: safeJson(doc.metadata ?? {}),
      },
    });
  }
  return docs.length;
}

async function migrateLoginEvents(db: Awaited<ReturnType<MongoClient["db"]>>) {
  const docs = await db.collection("loginEvents").find({}).toArray();
  const validUserIds = new Set(
    (await prisma.user.findMany({ select: { id: true } })).map((u) => u.id),
  );
  for (const doc of docs) {
    const id = toId(doc._id);
    const userIdRaw = toOptionalId(doc.userId);

    await prisma.loginEvent.upsert({
      where: { id },
      update: {
        userId: userIdRaw && validUserIds.has(userIdRaw) ? userIdRaw : null,
        email: typeof doc.email === "string" ? doc.email.trim().toLowerCase() : null,
        ipAddress: typeof doc.ipAddress === "string" ? doc.ipAddress : null,
        userAgent: typeof doc.userAgent === "string" ? doc.userAgent : null,
        success: Boolean(doc.success),
        anomaly: toNumber(doc.anomaly, 0),
        location: typeof doc.location === "string" ? doc.location : null,
        createdAt: toDate(doc.createdAt),
        metadata: safeJson(doc.metadata ?? {}),
      },
      create: {
        id,
        userId: userIdRaw && validUserIds.has(userIdRaw) ? userIdRaw : null,
        email: typeof doc.email === "string" ? doc.email.trim().toLowerCase() : null,
        ipAddress: typeof doc.ipAddress === "string" ? doc.ipAddress : null,
        userAgent: typeof doc.userAgent === "string" ? doc.userAgent : null,
        success: Boolean(doc.success),
        anomaly: toNumber(doc.anomaly, 0),
        location: typeof doc.location === "string" ? doc.location : null,
        createdAt: toDate(doc.createdAt),
        metadata: safeJson(doc.metadata ?? {}),
      },
    });
  }
  return docs.length;
}

async function migrateAuditLogs(db: Awaited<ReturnType<MongoClient["db"]>>) {
  const docs = await db.collection("auditLogs").find({}).toArray();
  const validUserIds = new Set(
    (await prisma.user.findMany({ select: { id: true } })).map((u) => u.id),
  );
  for (const doc of docs) {
    const id = toId(doc._id);
    const userIdRaw = toOptionalId(doc.userId);

    await prisma.auditLog.upsert({
      where: { id },
      update: {
        userId: userIdRaw && validUserIds.has(userIdRaw) ? userIdRaw : null,
        actor: typeof doc.actor === "string" ? doc.actor : "system",
        action: typeof doc.action === "string" ? doc.action : "UNKNOWN",
        details: safeJson(doc.details ?? ""),
        ipAddress: typeof doc.ipAddress === "string" ? doc.ipAddress : null,
        createdAt: toDate(doc.createdAt),
        metadata: safeJson(doc.metadata ?? {}),
      },
      create: {
        id,
        userId: userIdRaw && validUserIds.has(userIdRaw) ? userIdRaw : null,
        actor: typeof doc.actor === "string" ? doc.actor : "system",
        action: typeof doc.action === "string" ? doc.action : "UNKNOWN",
        details: safeJson(doc.details ?? ""),
        ipAddress: typeof doc.ipAddress === "string" ? doc.ipAddress : null,
        createdAt: toDate(doc.createdAt),
        metadata: safeJson(doc.metadata ?? {}),
      },
    });
  }
  return docs.length;
}

async function migrateSecurityPolicies(db: Awaited<ReturnType<MongoClient["db"]>>) {
  const docs = await db.collection("securityPolicies").find({}).toArray();
  for (const doc of docs) {
    const id = toId(doc._id);
    await prisma.securityPolicy.upsert({
      where: { id },
      update: {
        maxLoginAttempts: Math.floor(toNumber(doc.maxLoginAttempts, 5)),
        lockoutMinutes: Math.floor(toNumber(doc.lockoutMinutes, 15)),
        rateLimitPerMin: Math.floor(toNumber(doc.rateLimitPerMin, 60)),
        passwordMinLength: Math.floor(toNumber(doc.passwordMinLength, 12)),
        mfaRequired: Boolean(doc.mfaRequired),
        anomalyAlertThreshold: toNumber(doc.anomalyAlertThreshold, 0.7),
        createdAt: toDate(doc.createdAt),
        updatedAt: toDate(doc.updatedAt),
      },
      create: {
        id,
        maxLoginAttempts: Math.floor(toNumber(doc.maxLoginAttempts, 5)),
        lockoutMinutes: Math.floor(toNumber(doc.lockoutMinutes, 15)),
        rateLimitPerMin: Math.floor(toNumber(doc.rateLimitPerMin, 60)),
        passwordMinLength: Math.floor(toNumber(doc.passwordMinLength, 12)),
        mfaRequired: Boolean(doc.mfaRequired),
        anomalyAlertThreshold: toNumber(doc.anomalyAlertThreshold, 0.7),
        createdAt: toDate(doc.createdAt),
        updatedAt: toDate(doc.updatedAt),
      },
    });
  }
  return docs.length;
}

async function main() {
  await mongo.connect();
  await prisma.$connect();

  const db = mongo.db(mongoDbName);

  const users = await migrateUsers(db);
  const wallets = await migrateWallets(db, users.ids);
  const transactions = await migrateTransactions(db, users.ids, wallets.ids);
  const loginEvents = await migrateLoginEvents(db);
  const auditLogs = await migrateAuditLogs(db);
  const securityPolicies = await migrateSecurityPolicies(db);

  console.log("Mongo -> PostgreSQL migration completed.");
  console.log({
    users: users.count,
    wallets: wallets.count,
    transactions,
    loginEvents,
    auditLogs,
    securityPolicies,
  });
}

main()
  .catch((err) => {
    console.error("Migration failed", err);
    process.exit(1);
  })
  .finally(async () => {
    await mongo.close();
    await prisma.$disconnect();
  });



