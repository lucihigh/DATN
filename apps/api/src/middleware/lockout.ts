import { Request, Response, NextFunction } from "express";

import {
  createLoginEventRepository,
  createUserRepository,
} from "../db/repositories";
import { readFromMongo } from "../db/mongo";
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
  const windowStart = new Date(Date.now() - policy.lockoutMinutes * 60 * 1000);
  const recentFailures = await repo.count({
    email,
    success: false,
    createdAt: { $gte: windowStart },
  } as never);

  if (recentFailures >= policy.maxLoginAttempts) {
    const userRepo = createUserRepository();
    const userDoc = await userRepo.findByEmail(email);
    const user = userDoc ? readFromMongo.user(userDoc) : null;
    if (user?._id) {
      await userRepo.updateOne({ _id: user._id } as never, {
        $set: { status: "DISABLED", updatedAt: new Date() },
      });
    }
    return res
      .status(423)
      .json({ error: "Account temporarily locked due to repeated failures" });
  }

  return next();
};
