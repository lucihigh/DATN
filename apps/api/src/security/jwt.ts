import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";

import type { Role } from "../db/schemas";

type AuthTokenPayload = {
  sub: string;
  email: string;
  role: Role;
};

const getJwtSecret = () => {
  const secret = process.env.JWT_SECRET;
  if (secret) return secret;

  if (process.env.NODE_ENV === "production") {
    throw new Error("JWT_SECRET is required in production.");
  }

  return "dev-insecure-jwt-secret";
};

export const signAuthToken = (payload: AuthTokenPayload) =>
  jwt.sign(payload, getJwtSecret(), {
    expiresIn: (process.env.JWT_EXPIRES_IN ||
      "15m") as SignOptions["expiresIn"],
  });

export const verifyAuthToken = (token: string) =>
  jwt.verify(token, getJwtSecret()) as AuthTokenPayload & {
    iat: number;
    exp: number;
  };

export type AuthUser = AuthTokenPayload;
