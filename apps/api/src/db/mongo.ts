import path from "path";

import dotenv from "dotenv";
import { MongoClient, Db, Collection, ObjectId } from "mongodb";

import { ensureIndexes } from "./indexes";
import type {
  AuditLogDoc,
  LoginEventDoc,
  SecurityPolicyDoc,
  TransactionDoc,
  UserDoc,
  WalletDoc,
} from "./schemas";
import { COLLECTIONS, validators } from "./schemas";

// Load env from current working dir, then fall back to repo root
dotenv.config();
if (!process.env.MONGODB_URI) {
  const rootEnv = path.resolve(process.cwd(), "..", "..", ".env");
  dotenv.config({ path: rootEnv });
}

let client: MongoClient | null = null;
let mongoDb: Db | null = null;
let connectPromise: Promise<{ client: MongoClient; db: Db }> | null = null;

const getUri = () => process.env.MONGODB_URI || "";
const getDbName = () => process.env.MONGODB_DB || "ComputerResearchProject";

export const connectMongo = async () => {
  if (client && mongoDb) return { client, db: mongoDb };
  if (connectPromise) return connectPromise;

  const uri = getUri();
  if (!uri) throw new Error("MONGODB_URI is not set");

  connectPromise = (async () => {
    const nextClient = new MongoClient(uri);
    await nextClient.connect();

    const nextDb = nextClient.db(getDbName());
    client = nextClient;
    mongoDb = nextDb;

    return { client: nextClient, db: nextDb };
  })();

  try {
    return await connectPromise;
  } finally {
    connectPromise = null;
  }
};

export const getDb = () => {
  if (!mongoDb) throw new Error("MongoDB not connected. Call connectMongo() first.");
  return mongoDb;
};

export type MongoCollections = {
  users: Collection<UserDoc>;
  wallets: Collection<WalletDoc>;
  transactions: Collection<TransactionDoc>;
  loginEvents: Collection<LoginEventDoc>;
  auditLogs: Collection<AuditLogDoc>;
  securityPolicies: Collection<SecurityPolicyDoc>;
};

export type MongoCollectionAccessors = {
  users: () => Collection<UserDoc>;
  wallets: () => Collection<WalletDoc>;
  transactions: () => Collection<TransactionDoc>;
  loginEvents: () => Collection<LoginEventDoc>;
  auditLogs: () => Collection<AuditLogDoc>;
  securityPolicies: () => Collection<SecurityPolicyDoc>;
};

/**
 * Access collections with db.<collection>() style.
 */
export const db: MongoCollectionAccessors = {
  users: () => getDb().collection<UserDoc>(COLLECTIONS.users),
  wallets: () => getDb().collection<WalletDoc>(COLLECTIONS.wallets),
  transactions: () => getDb().collection<TransactionDoc>(COLLECTIONS.transactions),
  loginEvents: () => getDb().collection<LoginEventDoc>(COLLECTIONS.loginEvents),
  auditLogs: () => getDb().collection<AuditLogDoc>(COLLECTIONS.auditLogs),
  securityPolicies: () => getDb().collection<SecurityPolicyDoc>(COLLECTIONS.securityPolicies),
};

export const collections = (): MongoCollections => {
  return {
    // Keeping collection names unchanged ensures existing Atlas data is reused.
    users: db.users(),
    wallets: db.wallets(),
    transactions: db.transactions(),
    loginEvents: db.loginEvents(),
    auditLogs: db.auditLogs(),
    securityPolicies: db.securityPolicies(),
  };
};

const asObject = <T extends object>(input: unknown): Partial<T> =>
  typeof input === "object" && input !== null ? (input as Partial<T>) : {};

const asRecord = (input: unknown): Record<string, unknown> =>
  typeof input === "object" && input !== null && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : {};

const asNumber = (value: unknown, fallback: number): number => {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const asBoolean = (value: unknown, fallback: boolean): boolean => {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["true", "1", "yes"].includes(normalized)) return true;
    if (["false", "0", "no"].includes(normalized)) return false;
  }
  return fallback;
};

const asDate = (value: unknown, fallback?: Date): Date | undefined => {
  if (value === undefined || value === null || value === "") return fallback;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? fallback : value;
  const parsed = new Date(value as string | number);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed;
};

const coerceObjectId = (value: unknown): ObjectId | undefined => {
  if (value === undefined || value === null || value === "") return undefined;
  if (value instanceof ObjectId) return value;
  if (typeof value === "string") {
    const normalized = value.trim();
    if (!normalized) return undefined;
    return ObjectId.isValid(normalized) ? new ObjectId(normalized) : undefined;
  }
  return undefined;
};

const requireObjectId = (value: unknown, field: string): ObjectId | undefined => {
  const normalized = coerceObjectId(value);
  if (value === undefined || value === null || value === "") return undefined;
  if (normalized) return normalized;
  throw new Error(`Invalid ObjectId for ${field}`);
};

const withTimestamps = <T extends { createdAt?: unknown; updatedAt?: unknown }>(
  input: T,
  options?: { createdAtDefaultToNow?: boolean; updatedAtDefaultToNow?: boolean },
) => {
  const now = new Date();
  const createdAt = asDate(input.createdAt, options?.createdAtDefaultToNow ? now : undefined);
  const updatedAt = asDate(input.updatedAt, options?.updatedAtDefaultToNow ? now : undefined);
  return {
    ...input,
    createdAt,
    updatedAt,
  };
};

const ensureValidated = <T>(collection: string, value: T | null): T => {
  if (value) return value;
  throw new Error(`Invalid document format for collection "${collection}"`);
};

export const readFromMongo = {
  user: (input: unknown) => {
    const doc = asObject<UserDoc>(input);
    return validators.user({
      ...doc,
      _id: coerceObjectId(doc?._id),
      role: doc?.role ?? "USER",
      status: doc?.status ?? "ACTIVE",
      lastLoginAt: asDate(doc?.lastLoginAt),
      createdAt: asDate(doc?.createdAt),
      updatedAt: asDate(doc?.updatedAt),
      metadata: asRecord(doc?.metadata),
    });
  },
  wallet: (input: unknown) => {
    const doc = asObject<WalletDoc>(input);
    return validators.wallet({
      ...doc,
      _id: coerceObjectId(doc?._id),
      userId: coerceObjectId(doc?.userId),
      balance: asNumber(doc?.balance, 0),
      currency: doc?.currency ?? "USD",
      status: doc?.status ?? "ACTIVE",
      createdAt: asDate(doc?.createdAt),
      updatedAt: asDate(doc?.updatedAt),
      tags: Array.isArray(doc?.tags) ? doc.tags : [],
      metadata: asRecord(doc?.metadata),
    });
  },
  transaction: (input: unknown) => {
    const doc = asObject<TransactionDoc>(input);
    return validators.transaction({
      ...doc,
      _id: coerceObjectId(doc?._id),
      walletId: coerceObjectId(doc?.walletId),
      counterpartyWalletId: coerceObjectId(doc?.counterpartyWalletId),
      amount: asNumber(doc?.amount, 0),
      type: doc?.type ?? "TRANSFER",
      status: doc?.status ?? "COMPLETED",
      createdAt: asDate(doc?.createdAt),
      updatedAt: asDate(doc?.updatedAt),
      metadata: asRecord(doc?.metadata),
    });
  },
  loginEvent: (input: unknown) => {
    const doc = asObject<LoginEventDoc>(input);
    return validators.loginEvent({
      ...doc,
      _id: coerceObjectId(doc?._id),
      userId: coerceObjectId(doc?.userId),
      success: asBoolean(doc?.success, false),
      anomaly: asNumber(doc?.anomaly, 0),
      createdAt: asDate(doc?.createdAt),
      metadata: asRecord(doc?.metadata),
    });
  },
  auditLog: (input: unknown) => {
    const doc = asObject<AuditLogDoc>(input);
    return validators.auditLog({
      ...doc,
      _id: coerceObjectId(doc?._id),
      userId: coerceObjectId(doc?.userId),
      actor: doc?.actor ?? "system",
      action: doc?.action ?? "UNKNOWN",
      details: doc?.details ?? "",
      createdAt: asDate(doc?.createdAt),
      metadata: asRecord(doc?.metadata),
    });
  },
  securityPolicy: (input: unknown) => {
    const doc = asObject<SecurityPolicyDoc>(input);
    return validators.securityPolicy({
      ...doc,
      _id: coerceObjectId(doc?._id),
      maxLoginAttempts: asNumber(doc?.maxLoginAttempts, 5),
      lockoutMinutes: asNumber(doc?.lockoutMinutes, 15),
      rateLimitPerMin: asNumber(doc?.rateLimitPerMin, 60),
      passwordMinLength: asNumber(doc?.passwordMinLength, 12),
      mfaRequired: asBoolean(doc?.mfaRequired, false),
      createdAt: asDate(doc?.createdAt),
      updatedAt: asDate(doc?.updatedAt),
    });
  },
};

/**
 * Validate + map payloads before writing to MongoDB.
 * This keeps ObjectId/timestamp fields consistent and prevents malformed docs.
 */
export const writeToMongo = {
  user: (input: unknown) => {
    const doc = asObject<UserDoc>(input);
    const normalized = withTimestamps(
      {
        ...doc,
        _id: requireObjectId(doc?._id, "users._id"),
        email: typeof doc?.email === "string" ? doc.email.trim().toLowerCase() : doc?.email,
        role: doc?.role ?? "USER",
        status: doc?.status ?? "ACTIVE",
        metadata: asRecord(doc?.metadata),
      },
      { createdAtDefaultToNow: true, updatedAtDefaultToNow: true },
    );
    return ensureValidated(COLLECTIONS.users, validators.user(normalized));
  },
  wallet: (input: unknown) => {
    const doc = asObject<WalletDoc>(input);
    const normalized = withTimestamps(
      {
        ...doc,
        _id: requireObjectId(doc?._id, "wallets._id"),
        userId: requireObjectId(doc?.userId, "wallets.userId"),
        balance: asNumber(doc?.balance, 0),
        currency: doc?.currency ?? "USD",
        status: doc?.status ?? "ACTIVE",
        tags: Array.isArray(doc?.tags) ? doc.tags : [],
        metadata: asRecord(doc?.metadata),
      },
      { createdAtDefaultToNow: true, updatedAtDefaultToNow: true },
    );
    return ensureValidated(COLLECTIONS.wallets, validators.wallet(normalized));
  },
  transaction: (input: unknown) => {
    const doc = asObject<TransactionDoc>(input);
    const normalized = withTimestamps(
      {
        ...doc,
        _id: requireObjectId(doc?._id, "transactions._id"),
        walletId: requireObjectId(doc?.walletId, "transactions.walletId"),
        counterpartyWalletId: requireObjectId(doc?.counterpartyWalletId, "transactions.counterpartyWalletId"),
        amount: asNumber(doc?.amount, 0),
        type: doc?.type ?? "TRANSFER",
        status: doc?.status ?? "COMPLETED",
        metadata: asRecord(doc?.metadata),
      },
      { createdAtDefaultToNow: true, updatedAtDefaultToNow: true },
    );
    return ensureValidated(COLLECTIONS.transactions, validators.transaction(normalized));
  },
  loginEvent: (input: unknown) => {
    const doc = asObject<LoginEventDoc>(input);
    const normalized = {
      ...doc,
      _id: requireObjectId(doc?._id, "loginEvents._id"),
      userId: requireObjectId(doc?.userId, "loginEvents.userId"),
      success: asBoolean(doc?.success, false),
      anomaly: asNumber(doc?.anomaly, 0),
      createdAt: asDate(doc?.createdAt, new Date()),
      metadata: asRecord(doc?.metadata),
    };
    return ensureValidated(COLLECTIONS.loginEvents, validators.loginEvent(normalized));
  },
  auditLog: (input: unknown) => {
    const doc = asObject<AuditLogDoc>(input);
    const normalized = {
      ...doc,
      _id: requireObjectId(doc?._id, "auditLogs._id"),
      userId: requireObjectId(doc?.userId, "auditLogs.userId"),
      actor: doc?.actor ?? "system",
      action: doc?.action ?? "UNKNOWN",
      details: doc?.details ?? "",
      createdAt: asDate(doc?.createdAt, new Date()),
      metadata: asRecord(doc?.metadata),
    };
    return ensureValidated(COLLECTIONS.auditLogs, validators.auditLog(normalized));
  },
  securityPolicy: (input: unknown) => {
    const doc = asObject<SecurityPolicyDoc>(input);
    const normalized = withTimestamps(
      {
        ...doc,
        _id: requireObjectId(doc?._id, "securityPolicies._id"),
        maxLoginAttempts: asNumber(doc?.maxLoginAttempts, 5),
        lockoutMinutes: asNumber(doc?.lockoutMinutes, 15),
        rateLimitPerMin: asNumber(doc?.rateLimitPerMin, 60),
        passwordMinLength: asNumber(doc?.passwordMinLength, 12),
        mfaRequired: asBoolean(doc?.mfaRequired, false),
      },
      { createdAtDefaultToNow: true, updatedAtDefaultToNow: true },
    );
    return ensureValidated(COLLECTIONS.securityPolicies, validators.securityPolicy(normalized));
  },
};

export const disconnectMongo = async () => {
  if (connectPromise) {
    await connectPromise.catch(() => undefined);
  }

  if (client) {
    await client.close();
    client = null;
    mongoDb = null;
  }
};

/**
 * Optional helper to ensure indexes after a successful connection.
 * This is non-destructive: it never drops collections and tolerates existing/legacy data.
 * No DB-level schema validators are applied; validation is handled in application code.
 */
export const ensureDbIndexes = async () => {
  const database = getDb();
  await ensureIndexes(database);
  return database;
};
