import crypto from "crypto";

const SCRYPT_KEYLEN = 64;
const SCRYPT_SALT_BYTES = 16;
const SCRYPT_PREFIX = "scrypt";

const scryptAsync = (password: string, salt: string) =>
  new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT_KEYLEN, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(derivedKey as Buffer);
    });
  });

export const hashPassword = async (password: string) => {
  const salt = crypto.randomBytes(SCRYPT_SALT_BYTES).toString("base64");
  const hash = await scryptAsync(password, salt);
  return `${SCRYPT_PREFIX}:${salt}:${hash.toString("base64")}`;
};

export const verifyPassword = async (password: string, storedHash: string) => {
  const [prefix, salt, encodedHash] = storedHash.split(":");
  if (prefix !== SCRYPT_PREFIX || !salt || !encodedHash) return false;

  const expectedHash = Buffer.from(encodedHash, "base64");
  const actualHash = await scryptAsync(password, salt);

  if (expectedHash.length !== actualHash.length) return false;
  return crypto.timingSafeEqual(expectedHash, actualHash);
};
