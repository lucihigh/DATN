import { Request, Response, NextFunction } from "express";

import {
  createLoginEventRepository,
  createUserRepository,
} from "../db/repositories";
import { getSecurityPolicy } from "../services/securityPolicy";

export const lockoutGuard = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (req.path !== "/auth/login" || req.method !== "POST") return next();

  const email =
    typeof req.body?.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";
  if (!email) return next();

  const policy = await getSecurityPolicy();
  const repo = createLoginEventRepository();
  const userRepo = createUserRepository();
  const user = await userRepo.findByEmail(email);
  const windowStart = new Date(Date.now() - policy.lockoutMinutes * 60 * 1000);
  const lockoutResetAtRaw =
    user?.metadata &&
    typeof user.metadata === "object" &&
    typeof (user.metadata as Record<string, unknown>).lockoutResetAt ===
      "string"
      ? ((user.metadata as Record<string, unknown>).lockoutResetAt as string)
      : "";
  const lockoutResetAt = !lockoutResetAtRaw
    ? null
    : Number.isNaN(Date.parse(lockoutResetAtRaw))
      ? null
      : new Date(lockoutResetAtRaw);
  const effectiveWindowStart =
    lockoutResetAt && lockoutResetAt.getTime() > windowStart.getTime()
      ? lockoutResetAt
      : windowStart;
  const recentFailures = await repo.countRecentFailures(
    email,
    effectiveWindowStart,
  );

  if (recentFailures >= policy.maxLoginAttempts) {
    if (user?.id) {
      await userRepo.setStatus(user.id, "DISABLED");
    }
    return res
      .status(423)
      .json({ error: "Account temporarily locked due to repeated failures" });
  }

  return next();
};
