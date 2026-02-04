import { ObjectId } from "mongodb";
import type { OptionalUnlessRequiredId } from "mongodb";

import { BaseRepository } from "../baseRepository";
import { db } from "../mongo";
import type { LoginEventDoc } from "../schemas";

export type CreateLoginEventInput = {
  userId?: string | ObjectId;
  ipAddress?: string;
  userAgent?: string;
  success: boolean;
  anomaly?: number;
  location?: string;
  metadata?: Record<string, unknown>;
};

const normalizeObjectId = (value?: string | ObjectId) => {
  if (!value) return undefined;
  if (value instanceof ObjectId) return value;
  return ObjectId.isValid(value) ? new ObjectId(value) : value;
};

export class LoginEventRepository extends BaseRepository<LoginEventDoc> {
  constructor() {
    super(db.loginEvents);
  }

  async createLoginEvent(input: CreateLoginEventInput) {
    const payload: OptionalUnlessRequiredId<LoginEventDoc> = {
      userId: normalizeObjectId(input.userId),
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      success: input.success,
      anomaly: input.anomaly,
      location: input.location,
      createdAt: new Date(),
      metadata: input.metadata ?? {},
    };

    return this.insertOne(payload);
  }
}

export const createLoginEventRepository = () => new LoginEventRepository();
