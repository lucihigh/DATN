import { ObjectId } from "mongodb";
import type { OptionalUnlessRequiredId } from "mongodb";

import { BaseRepository } from "../baseRepository";
import { db, writeToMongo } from "../mongo";
import type { AuditLogDoc } from "../schemas";

export type CreateAuditLogInput = {
  userId?: string | ObjectId;
  actor?: string;
  action: string;
  details?: string | Record<string, unknown>;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
};

export class AuditLogRepository extends BaseRepository<AuditLogDoc> {
  constructor() {
    super(db.auditLogs);
  }

  async createAuditLog(input: CreateAuditLogInput) {
    const payload = writeToMongo.auditLog({
      userId: input.userId,
      actor: input.actor,
      action: input.action,
      details: input.details,
      ipAddress: input.ipAddress,
      createdAt: new Date(),
      metadata: input.metadata ?? {},
    });

    return this.insertOne(payload as OptionalUnlessRequiredId<AuditLogDoc>);
  }
}

export const createAuditLogRepository = () => new AuditLogRepository();
