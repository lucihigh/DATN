import { MongoClient, Db, Collection } from "mongodb";
import dotenv from "dotenv";
import path from "path";
import { ensureIndexes } from "./indexes";
import type {
  AuditLogDoc,
  LoginEventDoc,
  SecurityPolicyDoc,
  TransactionDoc,
  UserDoc,
  WalletDoc,
} from "./schemas";
import { COLLECTIONS } from "./schemas";

// Load env from current working dir, then fall back to repo root
dotenv.config();
if (!process.env.MONGODB_URI) {
  const rootEnv = path.resolve(process.cwd(), "..", "..", ".env");
  dotenv.config({ path: rootEnv });
}

let client: MongoClient | null = null;
let db: Db | null = null;

const getUri = () => process.env.MONGODB_URI || "";
const getDbName = () => process.env.MONGODB_DB || "ComputerResearchProject";

export const connectMongo = async () => {
  if (client && db) return { client, db };
  const uri = getUri();
  if (!uri) throw new Error("MONGODB_URI is not set");
  client = new MongoClient(uri);
  await client.connect();
  db = client.db(getDbName());
  return { client, db };
};

export const getDb = () => {
  if (!db) throw new Error("MongoDB not connected. Call connectMongo() first.");
  return db;
};

export type MongoCollections = {
  users: Collection<UserDoc>;
  wallets: Collection<WalletDoc>;
  transactions: Collection<TransactionDoc>;
  loginEvents: Collection<LoginEventDoc>;
  auditLogs: Collection<AuditLogDoc>;
  securityPolicies: Collection<SecurityPolicyDoc>;
};

export const collections = (): MongoCollections => {
  const database = getDb();
  return {
    // Keeping collection names unchanged ensures existing Atlas data is reused.
    users: database.collection<UserDoc>(COLLECTIONS.users),
    wallets: database.collection<WalletDoc>(COLLECTIONS.wallets),
    transactions: database.collection<TransactionDoc>(COLLECTIONS.transactions),
    loginEvents: database.collection<LoginEventDoc>(COLLECTIONS.loginEvents),
    auditLogs: database.collection<AuditLogDoc>(COLLECTIONS.auditLogs),
    securityPolicies: database.collection<SecurityPolicyDoc>(COLLECTIONS.securityPolicies),
  };
};

export const disconnectMongo = async () => {
  if (client) {
    await client.close();
    client = null;
    db = null;
  }
};

/**
 * Optional helper to ensure indexes after a successful connection.
 * This is non-destructive: it never drops collections and tolerates existing/legacy data.
 */
export const ensureDbIndexes = async () => {
  const database = getDb();
  await ensureIndexes(database);
  return database;
};
