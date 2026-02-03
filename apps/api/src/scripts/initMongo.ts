import { connectMongo, getDb, disconnectMongo } from "../db/mongo";

const collections = [
  { name: "users", indexes: [{ key: { email: 1 }, unique: true }] },
  { name: "wallets", indexes: [{ key: { userId: 1 } }] },
  { name: "transactions", indexes: [{ key: { walletId: 1, createdAt: -1 } }] },
  { name: "loginEvents", indexes: [{ key: { userId: 1, createdAt: -1 } }] },
  { name: "auditLogs", indexes: [{ key: { userId: 1, createdAt: -1 } }] },
  { name: "securityPolicies", indexes: [{ key: { createdAt: -1 } }] },
];

async function main() {
  await connectMongo();
  const db = getDb();

  for (const col of collections) {
    const collection = db.collection(col.name);
    for (const idx of col.indexes) {
      const options: Record<string, any> = {};
      if (idx.unique) options.unique = true;
      await collection.createIndex(idx.key, options);
    }
  }

  console.log("MongoDB initialized: collections and indexes ensured.");
}

main()
  .catch((err) => {
    console.error("Failed to init MongoDB", err);
    process.exit(1);
  })
  .finally(async () => {
    await disconnectMongo();
  });
