import type { Request, Response, NextFunction } from "express";

import { verifyAuthToken, type AuthUser } from "../security/jwt";

declare global {
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/no-empty-interface
    interface Request {
      user?: AuthUser;
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

export const requireAuth = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: "Missing bearer token" });
  try {
    const payload = verifyAuthToken(token);
    req.user = {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
    };
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
