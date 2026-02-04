import { ObjectId } from "mongodb";
import type { OptionalUnlessRequiredId } from "mongodb";

import { BaseRepository } from "../baseRepository";
import { db } from "../mongo";
import type { AuditLogDoc } from "../schemas";

export type CreateAuditLogInput = {
  userId?: string | ObjectId;
  actor?: string;
  action: string;
  details?: string | Record<string, unknown>;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
};

const normalizeObjectId = (value?: string | ObjectId) => {
  if (!value) return undefined;
  if (value instanceof ObjectId) return value;
  return ObjectId.isValid(value) ? new ObjectId(value) : value;
};

export class AuditLogRepository extends BaseRepository<AuditLogDoc> {
  constructor() {
    super(db.auditLogs);
  }

  async createAuditLog(input: CreateAuditLogInput) {
    const payload: OptionalUnlessRequiredId<AuditLogDoc> = {
      userId: normalizeObjectId(input.userId),
      actor: input.actor,
      action: input.action,
      details: input.details,
      ipAddress: input.ipAddress,
      createdAt: new Date(),
      metadata: input.metadata ?? {},
    };

    return this.insertOne(payload);
  }
}

export const createAuditLogRepository = () => new AuditLogRepository();
