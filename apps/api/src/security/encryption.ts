import crypto from "crypto";

import type { EncryptedString, MaybeEncryptedString, UserDoc } from "../db/schemas";

const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32; // AES-256 requires a 32-byte key
let cachedKey: Buffer | null = null;

const getKeyId = () => process.env.ENCRYPTION_KEY_ID || "default";

const decodeKey = (rawValue: string) => {
  const value = rawValue.trim();
  const asBase64 = Buffer.from(value, "base64");
  if (asBase64.length === KEY_BYTES) return asBase64;

  if (/^[0-9a-fA-F]{64}$/.test(value)) {
    const asHex = Buffer.from(value, "hex");
    if (asHex.length === KEY_BYTES) return asHex;
  }

  throw new Error(
    `ENCRYPTION_KEY must decode to ${KEY_BYTES} bytes (base64 or hex). Received length=${asBase64.length}.`,
  );
};

const loadKey = () => {
  if (cachedKey) return cachedKey;
  const keyValue = process.env.ENCRYPTION_KEY;
  if (!keyValue) {
    throw new Error("ENCRYPTION_KEY is missing. Set a base64 or hex encoded 32-byte key in the environment.");
  }
  const key = decodeKey(keyValue);
  cachedKey = key;
  return key;
};

const getPayloadData = (value: EncryptedString) => value.data || value.ciphertext;

export const isEncryptedString = (value: unknown): value is EncryptedString => {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.iv === "string" &&
    typeof candidate.tag === "string" &&
    (typeof candidate.data === "string" || typeof candidate.ciphertext === "string")
  );
};

const resolveAad = (fieldName: string, namespace?: string) => {
  if (!namespace) return fieldName;
  return `${namespace}:${fieldName}`;
};

type EncryptDecryptOptions = {
  aad?: string;
};

type FieldCryptoOptions = {
  aadNamespace?: string;
  strict?: boolean;
};

export const encryptField = (plaintext: string, options?: EncryptDecryptOptions): EncryptedString => {
  const key = loadKey();
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  if (options?.aad) {
    cipher.setAAD(Buffer.from(options.aad, "utf8"));
  }
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: ciphertext.toString("base64"),
    algorithm: ALGORITHM,
    keyId: getKeyId(),
    version: 1,
  };
};

export const decryptField = (payload: EncryptedString, options?: EncryptDecryptOptions): string => {
  const encryptedValue = getPayloadData(payload);
  if (!encryptedValue) {
    throw new Error("Encrypted payload is missing `data`/`ciphertext`.");
  }

  const key = loadKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(payload.iv, "base64"));
  if (options?.aad) {
    decipher.setAAD(Buffer.from(options.aad, "utf8"));
  }
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedValue, "base64")), decipher.final()]);
  return decrypted.toString("utf8");
};

export const encryptFields = <T extends Record<string, unknown>, K extends keyof T>(
  doc: T,
  fields: readonly K[],
  options?: FieldCryptoOptions,
) => {
  const clone: Record<string, unknown> = { ...doc };

  for (const field of fields) {
    const value = clone[field as string];
    if (value === undefined || value === null) continue;
    if (isEncryptedString(value)) continue;

    if (typeof value !== "string") {
      if (options?.strict) {
        throw new Error(`Cannot encrypt non-string value for field '${String(field)}'.`);
      }
      continue;
    }

    clone[field as string] = encryptField(value, {
      aad: resolveAad(String(field), options?.aadNamespace),
    });
  }

  return clone as T;
};

export const decryptFields = <T extends Record<string, unknown>, K extends keyof T>(
  doc: T,
  fields: readonly K[],
  options?: FieldCryptoOptions,
) => {
  const clone: Record<string, unknown> = { ...doc };

  for (const field of fields) {
    const value = clone[field as string] as MaybeEncryptedString | undefined;
    if (value === undefined || value === null) continue;
    if (typeof value === "string") continue;

    if (!isEncryptedString(value)) {
      if (options?.strict) {
        throw new Error(`Field '${String(field)}' is not a valid encrypted payload.`);
      }
      continue;
    }

    try {
      clone[field as string] = decryptField(value, {
        aad: resolveAad(String(field), options?.aadNamespace),
      });
    } catch (err) {
      // Backward compatibility: payloads created before AAD support can still be decrypted.
      if (options?.aadNamespace) {
        try {
          clone[field as string] = decryptField(value);
          continue;
        } catch {
          // Keep fallback behavior below.
        }
      }
      if (options?.strict) throw err;
      clone[field as string] = value;
    }
  }

  return clone as T;
};

const USER_PII_FIELDS = ["phone", "address", "dob"] as const;

/**
 * Encrypts PII fields in a user document when they are plain text.
 * - Skips undefined/missing fields so legacy documents remain valid.
 * - Leaves already encrypted values untouched to avoid double-encryption.
 */
export const encryptUserPII = <T extends UserDoc>(user: T): T => {
  return encryptFields(user as unknown as Record<string, unknown>, USER_PII_FIELDS, {
    aadNamespace: "user-pii",
  }) as T;
};

/**
 * Decrypts PII fields when an encryption envelope is present.
 * - Returns plain strings for encrypted fields.
 * - Leaves values unchanged if decryption fails or if the field is already plain.
 *   (This makes it safe for mixed/legacy data during migrations.)
 */
export const decryptUserPII = <T extends UserDoc>(user: T): T => {
  return decryptFields(user as unknown as Record<string, unknown>, USER_PII_FIELDS, {
    aadNamespace: "user-pii",
  }) as T;
};
