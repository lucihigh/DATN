import path from "path";

import dotenv from "dotenv";
import { MongoClient, Db, Collection } from "mongodb";

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

export const readFromMongo = {
  user: (input: unknown) => {
    const doc = asObject<UserDoc>(input);
    return validators.user({
      ...doc,
      role: doc?.role ?? "USER",
      status: doc?.status ?? "ACTIVE",
      metadata: asRecord(doc?.metadata),
    });
  },
  wallet: (input: unknown) => {
    const doc = asObject<WalletDoc>(input);
    return validators.wallet({
      ...doc,
      balance: asNumber(doc?.balance, 0),
      currency: doc?.currency ?? "USD",
      status: doc?.status ?? "ACTIVE",
      tags: Array.isArray(doc?.tags) ? doc.tags : [],
      metadata: asRecord(doc?.metadata),
    });
  },
  transaction: (input: unknown) => {
    const doc = asObject<TransactionDoc>(input);
    return validators.transaction({
      ...doc,
      amount: asNumber(doc?.amount, 0),
      type: doc?.type ?? "TRANSFER",
      status: doc?.status ?? "COMPLETED",
      metadata: asRecord(doc?.metadata),
    });
  },
  loginEvent: (input: unknown) => {
    const doc = asObject<LoginEventDoc>(input);
    return validators.loginEvent({
      ...doc,
      success: asBoolean(doc?.success, false),
      anomaly: asNumber(doc?.anomaly, 0),
      metadata: asRecord(doc?.metadata),
    });
  },
  auditLog: (input: unknown) => {
    const doc = asObject<AuditLogDoc>(input);
    return validators.auditLog({
      ...doc,
      actor: doc?.actor ?? "system",
      action: doc?.action ?? "UNKNOWN",
      details: doc?.details ?? "",
      metadata: asRecord(doc?.metadata),
    });
  },
  securityPolicy: (input: unknown) => {
    const doc = asObject<SecurityPolicyDoc>(input);
    return validators.securityPolicy({
      ...doc,
      maxLoginAttempts: asNumber(doc?.maxLoginAttempts, 5),
      lockoutMinutes: asNumber(doc?.lockoutMinutes, 15),
      rateLimitPerMin: asNumber(doc?.rateLimitPerMin, 60),
      passwordMinLength: asNumber(doc?.passwordMinLength, 12),
      mfaRequired: asBoolean(doc?.mfaRequired, false),
    });
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
