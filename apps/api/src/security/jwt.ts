import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";

import type { Role } from "../db/schemas";

type AuthTokenPayload = {
  sub: string;
  email: string;
  role: Role;
  sid: string;
};

type SessionAlertTokenPayload = {
  sub: string;
  email: string;
  revokedSid: string;
  activeSid: string;
  activeSessionIssuedAt?: string;
  activeSessionIp?: string;
  activeSessionUserAgent?: string;
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
    expiresIn: (process.env.JWT_EXPIRES_IN || "7d") as SignOptions["expiresIn"],
  });

export const verifyAuthToken = (token: string) =>
  jwt.verify(token, getJwtSecret()) as AuthTokenPayload & {
    iat: number;
    exp: number;
  };

export const signSessionAlertToken = (payload: SessionAlertTokenPayload) =>
  jwt.sign(payload, getJwtSecret(), {
    expiresIn: "30m",
  });

export const verifySessionAlertToken = (token: string) =>
  jwt.verify(token, getJwtSecret()) as SessionAlertTokenPayload & {
    iat: number;
    exp: number;
  };

export type AuthUser = AuthTokenPayload;
