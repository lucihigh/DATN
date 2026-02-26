import bcrypt from "bcrypt";

const DEFAULT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);

export const hashPassword = async (password: string) => {
  const rounds = Number.isFinite(DEFAULT_ROUNDS) ? DEFAULT_ROUNDS : 12;
  return bcrypt.hash(password, rounds);
};

export const verifyPassword = async (password: string, storedHash: string) => {
  if (!storedHash) return false;
  return bcrypt.compare(password, storedHash);
};
