import { connectMongo, ensureDbIndexes, disconnectMongo } from "../db/mongo";

async function main() {
  await connectMongo();
  await ensureDbIndexes();

  console.log(
    "MongoDB initialized: indexes ensured (background mode, no DB schema validators).",
  );
}

main()
  .catch((err) => {
    console.error("Failed to init MongoDB", err);
    process.exit(1);
  })
  .finally(async () => {
    await disconnectMongo();
  });
