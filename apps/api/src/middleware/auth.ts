import type { Request, Response, NextFunction } from "express";

import { createUserRepository } from "../db/repositories";
import {
  signSessionAlertToken,
  verifyAuthToken,
  type AuthUser,
} from "../security/jwt";
import {
  getAuthSecurityState,
  isActiveAuthSession,
} from "../services/trustedIp";

declare global {
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/no-empty-interface
    interface Request {
      user?: AuthUser;
      sessionSecurity?: {
        riskLevel: "low" | "medium" | "high";
        reviewReason?: string;
        verificationMethod?: "password" | "email_otp" | "sms_otp";
        restrictLargeTransfers?: boolean;
        maxTransferAmount?: number;
      };
    }
  }
}

const extractToken = (req: Request) => {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const [scheme, value] = auth.split(" ");
  if (!/^Bearer$/i.test(scheme)) return null;
  return value;
};

export const requireAuth = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: "Missing bearer token" });
  try {
    const payload = verifyAuthToken(token);
    const userRepository = createUserRepository();
    const userDoc = await userRepository.findValidatedById(payload.sub);
    if (!userDoc || userDoc.status !== "ACTIVE") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const authSecurityState = getAuthSecurityState(userDoc.metadata);
    if (!isActiveAuthSession(authSecurityState, payload.sid)) {
      const activeSession = authSecurityState.activeSession;
      return res.status(401).json({
        error: "Session revoked by a newer sign-in",
        code: "SESSION_REPLACED",
        sessionAlert: activeSession
          ? {
              token: signSessionAlertToken({
                sub: userDoc.id,
                email: userDoc.email,
                revokedSid: payload.sid,
                activeSid: activeSession.sessionId,
                activeSessionIssuedAt: activeSession.issuedAt,
                activeSessionIp: activeSession.ipAddress,
                activeSessionUserAgent: activeSession.userAgent,
              }),
              email: userDoc.email,
              issuedAt: activeSession.issuedAt,
              ipAddress: activeSession.ipAddress,
              userAgent: activeSession.userAgent,
            }
          : undefined,
      });
    }

    req.user = {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
      sid: payload.sid,
    };
    req.sessionSecurity = authSecurityState.activeSession?.security;
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

export const requireRole = (roles: ("USER" | "ADMIN")[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    return next();
  };
};
