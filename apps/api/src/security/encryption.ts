import crypto from "crypto";
import type { EncryptedString, MaybeEncryptedString, UserDoc } from "../db/schemas";

const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32; // AES-256 requires a 32-byte key
let cachedKey: Buffer | null = null;

const loadKey = () => {
  if (cachedKey) return cachedKey;
  const keyBase64 = process.env.ENCRYPTION_KEY;
  if (!keyBase64) {
    throw new Error("ENCRYPTION_KEY is missing. Set a base64-encoded 32-byte key in the environment.");
  }
  const key = Buffer.from(keyBase64, "base64");
  if (key.length !== KEY_BYTES) {
    throw new Error(`ENCRYPTION_KEY must decode to ${KEY_BYTES} bytes for AES-256-GCM; received ${key.length}.`);
  }
  cachedKey = key;
  return key;
};

export const isEncryptedString = (value: unknown): value is EncryptedString => {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.iv === "string" &&
    typeof candidate.tag === "string" &&
    typeof candidate.ciphertext === "string"
  );
};

export const encryptField = (plaintext: string): EncryptedString => {
  const key = loadKey();
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    algorithm: ALGORITHM,
    version: 1,
  };
};

export const decryptField = (payload: EncryptedString): string => {
  const key = loadKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(payload.iv, "base64"));
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
};

const PII_FIELDS: Array<keyof Pick<UserDoc, "phone" | "address">> = ["phone", "address"];

/**
 * Encrypts PII fields in a user document when they are plain text.
 * - Skips undefined/missing fields so legacy documents remain valid.
 * - Leaves already encrypted values untouched to avoid double-encryption.
 */
export const encryptUserPII = <T extends UserDoc>(user: T): T => {
  const clone: Record<string, unknown> = { ...user };

  for (const field of PII_FIELDS) {
    const value = user[field] as MaybeEncryptedString | undefined;
    if (!value) continue;
    if (isEncryptedString(value)) {
      clone[field] = value;
      continue;
    }
    if (typeof value === "string") {
      clone[field] = encryptField(value);
    }
  }

  return clone as T;
};

/**
 * Decrypts PII fields when an encryption envelope is present.
 * - Returns plain strings for encrypted fields.
 * - Leaves values unchanged if decryption fails or if the field is already plain.
 *   (This makes it safe for mixed/legacy data during migrations.)
 */
export const decryptUserPII = <T extends UserDoc>(user: T): T => {
  const clone: Record<string, unknown> = { ...user };

  for (const field of PII_FIELDS) {
    const value = user[field] as MaybeEncryptedString | undefined;
    if (!value) continue;
    if (isEncryptedString(value)) {
      try {
        clone[field] = decryptField(value);
      } catch (err) {
        // Fall back to the original encrypted payload so callers can decide what to do.
        clone[field] = value;
      }
    } else {
      clone[field] = value;
    }
  }

  return clone as T;
};
