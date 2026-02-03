import { Request, Response, NextFunction } from "express";

// TODO: plug a real rate limiter (e.g., express-rate-limit)
export const rateLimitPlaceholder = (_req: Request, _res: Response, next: NextFunction) => {
  return next();
};
