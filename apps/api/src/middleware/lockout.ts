import { Request, Response, NextFunction } from "express";

// TODO: track failed attempts in DB and enforce lockout windows
export const lockoutPlaceholder = (
  _req: Request,
  _res: Response,
  next: NextFunction,
) => {
  return next();
};
