import crypto from "crypto";

import type { EncryptedString, MaybeEncryptedString, UserDoc } from "../db/schemas";

const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32; // AES-256 requires a 32-byte key
const DEFAULT_KEY_ID = "default";
let cachedKeys: Map<string, Buffer> | null = null;
let cachedActiveKeyId: string | null = null;

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

const parseKeyList = (rawValue: string) => {
  const keys = new Map<string, Buffer>();
  const entries = rawValue.split(",").map((entry) => entry.trim()).filter(Boolean);
  for (const entry of entries) {
    const separatorIndex = entry.indexOf(":");
    if (separatorIndex <= 0 || separatorIndex === entry.length - 1) {
      throw new Error("ENCRYPTION_KEYS must be a comma-separated list of keyId:value entries.");
    }
    const keyId = entry.slice(0, separatorIndex).trim();
    const keyValue = entry.slice(separatorIndex + 1).trim();
    if (!keyId) {
      throw new Error("ENCRYPTION_KEYS contains an empty keyId.");
    }
    if (keys.has(keyId)) {
      throw new Error(`ENCRYPTION_KEYS contains duplicate keyId "${keyId}".`);
    }
    keys.set(keyId, decodeKey(keyValue));
  }
  return keys;
};

const resolveActiveKeyId = (keys: Map<string, Buffer>) => {
  const configuredKeyId = process.env.ENCRYPTION_KEY_ID;
  if (configuredKeyId) return configuredKeyId;
  if (keys.size === 1) return Array.from(keys.keys())[0];
  if (keys.size > 1) {
    throw new Error("ENCRYPTION_KEY_ID is required when multiple ENCRYPTION_KEYS are configured.");
  }
  return DEFAULT_KEY_ID;
};

const loadKeys = () => {
  if (cachedKeys && cachedActiveKeyId) {
    return { keys: cachedKeys, activeKeyId: cachedActiveKeyId };
  }

  const rawKeys = process.env.ENCRYPTION_KEYS;
  const keys = rawKeys ? parseKeyList(rawKeys) : new Map<string, Buffer>();

  if (!rawKeys) {
    const keyValue = process.env.ENCRYPTION_KEY;
    if (!keyValue) {
      throw new Error(
        "ENCRYPTION_KEY is missing. Set a base64 or hex encoded 32-byte key in the environment.",
      );
    }
    const keyId = process.env.ENCRYPTION_KEY_ID || DEFAULT_KEY_ID;
    keys.set(keyId, decodeKey(keyValue));
  }

  if (!keys.size) {
    throw new Error("No encryption keys are configured. Set ENCRYPTION_KEY or ENCRYPTION_KEYS.");
  }

  const activeKeyId = resolveActiveKeyId(keys);
  if (!keys.has(activeKeyId)) {
    throw new Error(`ENCRYPTION_KEY_ID "${activeKeyId}" was not found in configured keys.`);
  }

  cachedKeys = keys;
  cachedActiveKeyId = activeKeyId;
  return { keys, activeKeyId };
};

const loadActiveKey = () => {
  const { keys, activeKeyId } = loadKeys();
  const key = keys.get(activeKeyId);
  if (!key) {
    throw new Error(`ENCRYPTION_KEY_ID "${activeKeyId}" was not found in configured keys.`);
  }
  return { keyId: activeKeyId, key };
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
  const { keyId, key } = loadActiveKey();
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
    keyId,
    version: 1,
  };
};

export const decryptField = (payload: EncryptedString, options?: EncryptDecryptOptions): string => {
  const encryptedValue = getPayloadData(payload);
  if (!encryptedValue) {
    throw new Error("Encrypted payload is missing `data`/`ciphertext`.");
  }
  if (payload.algorithm && payload.algorithm !== ALGORITHM) {
    throw new Error(`Unsupported encryption algorithm "${payload.algorithm}".`);
  }

  const { keys, activeKeyId } = loadKeys();
  const candidates: Array<{ keyId: string; key: Buffer }> = [];

  if (payload.keyId) {
    const key = keys.get(payload.keyId);
    if (!key) {
      throw new Error(`No encryption key configured for keyId "${payload.keyId}".`);
    }
    candidates.push({ keyId: payload.keyId, key });
  } else {
    const activeKey = keys.get(activeKeyId);
    if (activeKey) {
      candidates.push({ keyId: activeKeyId, key: activeKey });
    }
    for (const [keyId, key] of keys.entries()) {
      if (keyId === activeKeyId) continue;
      candidates.push({ keyId, key });
    }
  }

  let lastError: unknown;
  for (const candidate of candidates) {
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, candidate.key, Buffer.from(payload.iv, "base64"));
      if (options?.aad) {
        decipher.setAAD(Buffer.from(options.aad, "utf8"));
      }
      decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedValue, "base64")),
        decipher.final(),
      ]);
      return decrypted.toString("utf8");
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError instanceof Error ? lastError : new Error("Failed to decrypt payload.");
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
