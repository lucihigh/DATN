import crypto from "crypto";

import { prisma } from "../prisma";

export type CreateAuditLogInput = {
  userId?: string;
  actor?: string;
  action: string;
  details?: string | Record<string, unknown>;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
};

export type AuditLogEntity = {
  id: string;
  userId?: string;
  actor: string;
  action: string;
  details?: string | Record<string, unknown>;
  ipAddress?: string;
  createdAt: Date;
  metadata?: Record<string, unknown>;
};

const toEntity = (log: {
  id: string;
  userId: string | null;
  actor: string;
  action: string;
  details: unknown;
  ipAddress: string | null;
  createdAt: Date;
  metadata: unknown;
}): AuditLogEntity => ({
  id: log.id,
  userId: log.userId ?? undefined,
  actor: log.actor,
  action: log.action,
  details: (log.details as string | Record<string, unknown> | null) ?? undefined,
  ipAddress: log.ipAddress ?? undefined,
  createdAt: log.createdAt,
  metadata: (log.metadata as Record<string, unknown> | null) ?? undefined,
});

export class AuditLogRepository {
  async createAuditLog(input: CreateAuditLogInput) {
    return prisma.auditLog.create({
      data: {
        id: crypto.randomUUID(),
        userId: input.userId,
        actor: input.actor || "system",
        action: input.action,
        details: input.details as never,
        ipAddress: input.ipAddress,
        metadata: input.metadata as never,
      },
    });
  }

  async findLatest(limit = 100) {
    const logs = await prisma.auditLog.findMany({
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return logs.map(toEntity);
  }
}

export const createAuditLogRepository = () => new AuditLogRepository();

