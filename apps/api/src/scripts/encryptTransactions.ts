import path from "path";

import dotenv from "dotenv";

import { prisma } from "../db/prisma";
import {
  buildEncryptedTransactionUpdateData,
  generateEncryptedTransactionId,
  usesCompactTransactionPayloadFormat,
} from "../services/transactionSecurity";

dotenv.config({ path: path.resolve(process.cwd(), ".env"), override: true });
dotenv.config({
  path: path.resolve(process.cwd(), "../../.env"),
  override: true,
});

async function main() {
  const transactions = await prisma.transaction.findMany({
    orderBy: { createdAt: "asc" },
  });

  let migrated = 0;
  let skipped = 0;

  for (const transaction of transactions) {
    if (usesCompactTransactionPayloadFormat(transaction)) {
      skipped += 1;
      continue;
    }

    const nextId = generateEncryptedTransactionId();
    await prisma.transaction.update({
      where: { id: transaction.id },
      data: buildEncryptedTransactionUpdateData(transaction, {
        transactionId: nextId,
      }),
    });
    migrated += 1;
  }

  console.log(
    `Transaction security migration completed. migrated=${migrated} skipped=${skipped} total=${transactions.length}`,
  );
}

main()
  .catch((err) => {
    console.error("Failed to encrypt existing transactions", err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
