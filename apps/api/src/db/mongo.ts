import { MongoClient, Db } from "mongodb";
import dotenv from "dotenv";
import path from "path";

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

export const disconnectMongo = async () => {
  if (client) {
    await client.close();
    client = null;
    db = null;
  }
};
