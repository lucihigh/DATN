import { ObjectId } from "mongodb";
import type { OptionalUnlessRequiredId } from "mongodb";

import { BaseRepository } from "../baseRepository";
import { db, writeToMongo } from "../mongo";
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

export class LoginEventRepository extends BaseRepository<LoginEventDoc> {
  constructor() {
    super(db.loginEvents);
  }

  async createLoginEvent(input: CreateLoginEventInput) {
    const payload = writeToMongo.loginEvent({
      userId: input.userId,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      success: input.success,
      anomaly: input.anomaly,
      location: input.location,
      createdAt: new Date(),
      metadata: input.metadata ?? {},
    });

    return this.insertOne(payload as OptionalUnlessRequiredId<LoginEventDoc>);
  }
}

export const createLoginEventRepository = () => new LoginEventRepository();
