import crypto from "crypto";

// ENCRYPTION_KEY must be a 32-byte key, base64-encoded (AES-256-GCM).
// Example to generate: `openssl rand -base64 32`
const keyBase64 = process.env.ENCRYPTION_KEY || "";
const key = keyBase64 ? Buffer.from(keyBase64, "base64") : crypto.randomBytes(32);

export const encryptField = (plaintext: string) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: encrypted.toString("base64"),
  };
};

export const decryptField = (payload: { iv: string; tag: string; ciphertext: string }) => {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(payload.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
};
