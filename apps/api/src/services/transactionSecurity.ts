import crypto from "crypto";

import type { EncryptedString } from "../db/schemas";
import {
  decryptField,
  encryptField,
  isEncryptedString,
} from "../security/encryption";

const ENCRYPTED_TRANSACTION_KEY = "secureTransaction";
const ENCRYPTION_METADATA_KEY = "transactionEncryption";
const ENCRYPTION_VERSION = 4;
const ENCRYPTED_STRING_PREFIX = "enc$";
const ENCRYPTED_ID_AAD = "transaction:id";
const MASKED_AMOUNT = 0;
const MASKED_TYPE: TransactionTypeValue = "TRANSFER";
const MASKED_STATUS: TransactionStatusValue = "PENDING";

const TYPE_VALUES = ["DEPOSIT", "WITHDRAW", "TRANSFER"] as const;
const STATUS_VALUES = ["PENDING", "COMPLETED", "FAILED", "REVERSED"] as const;

export type TransactionTypeValue = (typeof TYPE_VALUES)[number];
export type TransactionStatusValue = (typeof STATUS_VALUES)[number];

export type TransactionMetadata = Record<string, unknown>;

export type TransactionSensitiveFields = {
  amount: number;
  type: TransactionTypeValue;
  status: TransactionStatusValue;
  description?: string | null;
  counterpartyWalletId?: string | null;
  fromUserId?: string | null;
  toUserId?: string | null;
  metadata?: TransactionMetadata;
};

type EncryptedTransactionPayload = {
  publicId?: string;
  amount: number;
  type: TransactionTypeValue;
  status: TransactionStatusValue;
  description: string | null;
  counterpartyWalletId: string | null;
  fromUserId: string | null;
  toUserId: string | null;
  metadata?: TransactionMetadata;
};

type StoredTransactionShape = {
  id: string;
  publicId?: string | null;
  walletId: string | null;
  counterpartyWalletId: string | null;
  fromUserId: string | null;
  toUserId: string | null;
  amount: unknown;
  type: string;
  status: string;
  description: string | null;
  amountCipher?: string | null;
  typeCipher?: string | null;
  statusCipher?: string | null;
  metadataCipher?: string | null;
  createdAt: Date;
  updatedAt: Date;
  metadata: unknown;
};

export type DecryptedTransaction = {
  internalId: string;
  publicId: string;
  id: string;
  walletId: string | null;
  amount: number;
  type: TransactionTypeValue;
  status: TransactionStatusValue;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
  counterpartyWalletId: string | null;
  fromUserId: string | null;
  toUserId: string | null;
  metadata?: TransactionMetadata;
};

const asObject = (value: unknown) =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const asTransactionType = (value: unknown): TransactionTypeValue => {
  if (value === "DEPOSIT" || value === "WITHDRAW" || value === "TRANSFER") {
    return value;
  }
  return "TRANSFER";
};

const asTransactionStatus = (value: unknown): TransactionStatusValue => {
  if (
    value === "PENDING" ||
    value === "COMPLETED" ||
    value === "FAILED" ||
    value === "REVERSED"
  ) {
    return value;
  }
  return "COMPLETED";
};

const asAmount = (value: unknown) => {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

const serializeEncryptedEnvelope = (payload: EncryptedString) =>
  `${ENCRYPTED_STRING_PREFIX}${Buffer.from(
    JSON.stringify(payload),
    "utf8",
  ).toString("base64")}`;

const parseEncryptedEnvelope = (value?: string | null) => {
  if (!value || typeof value !== "string") return null;
  if (!value.startsWith(ENCRYPTED_STRING_PREFIX)) return null;
  try {
    const decoded = Buffer.from(
      value.slice(ENCRYPTED_STRING_PREFIX.length),
      "base64",
    ).toString("utf8");
    const parsed = JSON.parse(decoded) as unknown;
    return isEncryptedString(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const encryptOpaqueString = (
  transactionId: string,
  fieldName: string,
  plaintext: string,
) =>
  serializeEncryptedEnvelope(
    encryptField(plaintext, {
      aad: `transaction:${transactionId}:${fieldName}`,
    }),
  );

const decryptOpaqueString = (
  transactionId: string,
  fieldName: string,
  ciphertext?: string | null,
) => {
  const envelope = parseEncryptedEnvelope(ciphertext);
  if (!envelope) return null;
  return decryptField(envelope, {
    aad: `transaction:${transactionId}:${fieldName}`,
  });
};

const getEncryptedPayloadEnvelope = (metadata: unknown) => {
  const record = asObject(metadata);
  const payload = record[ENCRYPTED_TRANSACTION_KEY];
  return isEncryptedString(payload) ? payload : null;
};

const hashBytes = (seed: string) =>
  crypto.createHash("sha256").update(seed).digest();

const buildEncryptedPayload = (
  publicId: string,
  input: TransactionSensitiveFields,
): EncryptedTransactionPayload => ({
  publicId,
  amount: input.amount,
  type: input.type,
  status: input.status,
  description: input.description ?? null,
  counterpartyWalletId: input.counterpartyWalletId ?? null,
  fromUserId: input.fromUserId ?? null,
  toUserId: input.toUserId ?? null,
  metadata: input.metadata,
});

const decryptEncryptedPayload = (
  transactionId: string,
  metadata: unknown,
): EncryptedTransactionPayload | null => {
  const envelope = getEncryptedPayloadEnvelope(metadata);
  if (!envelope) return null;

  const raw = decryptField(envelope, {
    aad: `transaction:${transactionId}`,
  });
  const parsed = asObject(JSON.parse(raw));

  return {
    publicId: typeof parsed.publicId === "string" ? parsed.publicId : undefined,
    amount: asAmount(parsed.amount),
    type: asTransactionType(parsed.type),
    status: asTransactionStatus(parsed.status),
    description:
      typeof parsed.description === "string" ? parsed.description : null,
    counterpartyWalletId:
      typeof parsed.counterpartyWalletId === "string"
        ? parsed.counterpartyWalletId
        : null,
    fromUserId:
      typeof parsed.fromUserId === "string" ? parsed.fromUserId : null,
    toUserId: typeof parsed.toUserId === "string" ? parsed.toUserId : null,
    metadata:
      parsed.metadata && typeof parsed.metadata === "object"
        ? (parsed.metadata as TransactionMetadata)
        : undefined,
  };
};

const buildFallbackPublicId = (transactionId: string, createdAt: Date) => {
  const datePart = createdAt.toISOString().slice(0, 10).replace(/-/g, "");
  const suffix = hashBytes(transactionId)
    .toString("hex")
    .slice(0, 8)
    .toUpperCase();
  return `TXN-${datePart}-${suffix}`;
};

export const generateProfessionalTransactionId = (createdAt = new Date()) => {
  const datePart = createdAt.toISOString().slice(0, 10).replace(/-/g, "");
  const randomPart = crypto.randomBytes(4).toString("hex").toUpperCase();
  return `TXN-${datePart}-${randomPart}`;
};

export const generateEncryptedTransactionId = () =>
  serializeEncryptedEnvelope(
    encryptField(`txn:${crypto.randomUUID()}`, {
      aad: ENCRYPTED_ID_AAD,
    }),
  );

const isSplitCipherFormat = (transaction: StoredTransactionShape) =>
  Boolean(
    transaction.publicId ||
    transaction.amountCipher ||
    transaction.typeCipher ||
    transaction.statusCipher ||
    transaction.metadataCipher,
  );

const hasCompactEncryptedPayload = (transaction: StoredTransactionShape) =>
  Boolean(getEncryptedPayloadEnvelope(transaction.metadata));

const isLockedVisibleShape = (transaction: StoredTransactionShape) =>
  asAmount(transaction.amount) === MASKED_AMOUNT &&
  asTransactionType(transaction.type) === MASKED_TYPE &&
  asTransactionStatus(transaction.status) === MASKED_STATUS;

const isCurrentCompactVersion = (transaction: StoredTransactionShape) => {
  const metadataRecord = asObject(transaction.metadata);
  const encryptionRecord = asObject(metadataRecord[ENCRYPTION_METADATA_KEY]);
  return encryptionRecord.version === ENCRYPTION_VERSION;
};

export const usesCompactTransactionPayloadFormat = (
  transaction: StoredTransactionShape,
) =>
  hasCompactEncryptedPayload(transaction) &&
  !isSplitCipherFormat(transaction) &&
  isCurrentCompactVersion(transaction) &&
  isLockedVisibleShape(transaction);

export const usesModernTransactionCipherFormat = (
  transaction: StoredTransactionShape,
) =>
  isSplitCipherFormat(transaction) || hasCompactEncryptedPayload(transaction);

export const isEncryptedTransactionRecord = (
  transaction: StoredTransactionShape,
) => usesModernTransactionCipherFormat(transaction);

export const buildEncryptedTransactionCreateData = (
  transactionId: string,
  input: {
    walletId?: string | null;
    publicId?: string;
    occurredAt?: Date;
    sensitive: TransactionSensitiveFields;
  },
) => {
  const publicId =
    input.publicId || generateProfessionalTransactionId(input.occurredAt);

  return {
    walletId: input.walletId ?? undefined,
    counterpartyWalletId: encryptOpaqueString(
      transactionId,
      "counterpartyWalletId",
      input.sensitive.counterpartyWalletId ?? "",
    ),
    fromUserId: encryptOpaqueString(
      transactionId,
      "fromUserId",
      input.sensitive.fromUserId ?? "",
    ),
    toUserId: encryptOpaqueString(
      transactionId,
      "toUserId",
      input.sensitive.toUserId ?? "",
    ),
    amount: MASKED_AMOUNT,
    type: MASKED_TYPE,
    status: MASKED_STATUS,
    description: encryptOpaqueString(
      transactionId,
      "description",
      input.sensitive.description ?? "",
    ),
    metadata: {
      [ENCRYPTION_METADATA_KEY]: {
        encrypted: true,
        format: "compact-payload",
        version: ENCRYPTION_VERSION,
      },
      [ENCRYPTED_TRANSACTION_KEY]: encryptField(
        JSON.stringify(buildEncryptedPayload(publicId, input.sensitive)),
        {
          aad: `transaction:${transactionId}`,
        },
      ),
    } as never,
  };
};

export const buildEncryptedTransactionUpdateData = (
  transaction: StoredTransactionShape,
  options?: {
    transactionId?: string;
    publicId?: string;
  },
) => {
  const decrypted = decryptStoredTransaction(transaction);
  const nextInternalId = options?.transactionId ?? transaction.id;

  return {
    id: nextInternalId,
    ...buildEncryptedTransactionCreateData(nextInternalId, {
      walletId: decrypted.walletId,
      publicId: options?.publicId ?? decrypted.publicId,
      occurredAt: decrypted.createdAt,
      sensitive: {
        amount: decrypted.amount,
        type: decrypted.type,
        status: decrypted.status,
        description: decrypted.description,
        counterpartyWalletId: decrypted.counterpartyWalletId,
        fromUserId: decrypted.fromUserId,
        toUserId: decrypted.toUserId,
        metadata: decrypted.metadata,
      },
    }),
  };
};

export const decryptStoredTransaction = (
  transaction: StoredTransactionShape,
): DecryptedTransaction => {
  const encryptedPayload = decryptEncryptedPayload(
    transaction.id,
    transaction.metadata,
  );
  if (encryptedPayload) {
    const publicId =
      encryptedPayload.publicId ||
      buildFallbackPublicId(transaction.id, transaction.createdAt);

    return {
      internalId: transaction.id,
      publicId,
      id: publicId,
      walletId: transaction.walletId,
      amount: encryptedPayload.amount,
      type: encryptedPayload.type,
      status: encryptedPayload.status,
      description: encryptedPayload.description,
      createdAt: transaction.createdAt,
      updatedAt: transaction.updatedAt,
      counterpartyWalletId: encryptedPayload.counterpartyWalletId,
      fromUserId: encryptedPayload.fromUserId,
      toUserId: encryptedPayload.toUserId,
      metadata: encryptedPayload.metadata,
    };
  }

  const publicId =
    transaction.publicId ||
    buildFallbackPublicId(transaction.id, transaction.createdAt);

  if (isSplitCipherFormat(transaction)) {
    const amount = asAmount(
      decryptOpaqueString(transaction.id, "amount", transaction.amountCipher) ??
        transaction.amount,
    );
    const type = asTransactionType(
      decryptOpaqueString(transaction.id, "type", transaction.typeCipher) ??
        transaction.type,
    );
    const status = asTransactionStatus(
      decryptOpaqueString(transaction.id, "status", transaction.statusCipher) ??
        transaction.status,
    );
    const description =
      decryptOpaqueString(
        transaction.id,
        "description",
        transaction.description,
      ) ?? null;
    const counterpartyWalletId =
      decryptOpaqueString(
        transaction.id,
        "counterpartyWalletId",
        transaction.counterpartyWalletId,
      ) ?? null;
    const fromUserId =
      decryptOpaqueString(
        transaction.id,
        "fromUserId",
        transaction.fromUserId,
      ) ?? null;
    const toUserId =
      decryptOpaqueString(transaction.id, "toUserId", transaction.toUserId) ??
      null;
    const metadataRaw =
      decryptOpaqueString(
        transaction.id,
        "metadata",
        transaction.metadataCipher,
      ) ?? "{}";

    let metadata: TransactionMetadata | undefined;
    try {
      const parsed = JSON.parse(metadataRaw) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        metadata = parsed as TransactionMetadata;
      }
    } catch {
      metadata = undefined;
    }

    return {
      internalId: transaction.id,
      publicId,
      id: publicId,
      walletId: transaction.walletId,
      amount,
      type,
      status,
      description,
      createdAt: transaction.createdAt,
      updatedAt: transaction.updatedAt,
      counterpartyWalletId,
      fromUserId,
      toUserId,
      metadata,
    };
  }

  return {
    internalId: transaction.id,
    publicId,
    id: publicId,
    walletId: transaction.walletId,
    amount: asAmount(transaction.amount),
    type: asTransactionType(transaction.type),
    status: asTransactionStatus(transaction.status),
    description: transaction.description ?? null,
    createdAt: transaction.createdAt,
    updatedAt: transaction.updatedAt,
    counterpartyWalletId: transaction.counterpartyWalletId,
    fromUserId: transaction.fromUserId,
    toUserId: transaction.toUserId,
    metadata:
      transaction.metadata && typeof transaction.metadata === "object"
        ? (transaction.metadata as TransactionMetadata)
        : undefined,
  };
};
