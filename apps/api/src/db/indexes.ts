import { MongoServerError } from "mongodb";
import type { CreateIndexesOptions, Db, IndexSpecification } from "mongodb";

import { COLLECTIONS } from "./schemas";

type IndexDefinition = {
  collection: (typeof COLLECTIONS)[keyof typeof COLLECTIONS];
  key: IndexSpecification;
  options?: CreateIndexesOptions;
};

const SAFE_UNIQUE_INDEX_NAMES = new Set(["users_email_unique"]);

// Indexes are additive-only to avoid dropping existing data or collections.
// Partial filters keep dirty/legacy documents from blocking index creation.
export const indexDefinitions: IndexDefinition[] = [
  {
    collection: COLLECTIONS.users,
    key: { email: 1 },
    options: {
      name: "users_email_unique",
      unique: true,
      partialFilterExpression: { email: { $type: "string" } },
    },
  },
  {
    collection: COLLECTIONS.users,
    key: { phone: 1 },
    options: { name: "users_phone_lookup", sparse: true },
  },
  {
    collection: COLLECTIONS.users,
    key: { status: 1, createdAt: -1 },
    options: { name: "users_status_createdAt" },
  },
  {
    collection: COLLECTIONS.wallets,
    key: { userId: 1 },
    options: {
      name: "wallets_userId",
      partialFilterExpression: { userId: { $exists: true } },
    },
  },
  {
    collection: COLLECTIONS.wallets,
    key: { status: 1, createdAt: -1 },
    options: { name: "wallets_status_createdAt" },
  },
  {
    collection: COLLECTIONS.transactions,
    key: { walletId: 1, createdAt: -1 },
    options: {
      name: "transactions_wallet_createdAt",
      partialFilterExpression: { walletId: { $exists: true } },
    },
  },
  {
    collection: COLLECTIONS.transactions,
    key: { type: 1, status: 1 },
    options: { name: "transactions_type_status" },
  },
  {
    collection: COLLECTIONS.loginEvents,
    key: { userId: 1, createdAt: -1 },
    options: {
      name: "loginEvents_user_createdAt",
      partialFilterExpression: { userId: { $exists: true } },
    },
  },
  {
    collection: COLLECTIONS.loginEvents,
    key: { ipAddress: 1, createdAt: -1 },
    options: {
      name: "loginEvents_ip_createdAt",
      partialFilterExpression: { ipAddress: { $exists: true } },
    },
  },
  {
    collection: COLLECTIONS.auditLogs,
    key: { userId: 1, createdAt: -1 },
    options: {
      name: "auditLogs_user_createdAt",
      partialFilterExpression: { userId: { $exists: true } },
    },
  },
  {
    collection: COLLECTIONS.auditLogs,
    key: { action: 1, createdAt: -1 },
    options: { name: "auditLogs_action_createdAt" },
  },
  {
    collection: COLLECTIONS.securityPolicies,
    key: { createdAt: -1 },
    options: { name: "securityPolicies_createdAt" },
  },
];

const isOptionsConflict = (error: unknown) =>
  error instanceof MongoServerError && error.code === 85; // IndexOptionsConflict

export const ensureIndexes = async (db: Db) => {
  for (const definition of indexDefinitions) {
    const collection = db.collection(definition.collection);
    const options: CreateIndexesOptions = { background: true, ...definition.options };
    if (options.unique && !SAFE_UNIQUE_INDEX_NAMES.has(options.name ?? "")) {
      console.warn(`Skipping unsafe unique index on ${definition.collection}`, {
        key: definition.key,
        name: options.name,
      });
      continue;
    }
    try {
      await collection.createIndex(definition.key, options);
    } catch (error) {
      if (isOptionsConflict(error)) {
        // Keep the existing index definition; do not drop or replace to avoid risk.
        console.warn(`Index already exists with different options for ${definition.collection}`, {
          key: definition.key,
          name: options.name,
        });
        continue;
      }
      console.warn(`Failed to create index on ${definition.collection}`, {
        key: definition.key,
        name: options.name,
        error,
      });
    }
  }
};
