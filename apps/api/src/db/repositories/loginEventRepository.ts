import crypto from "crypto";

import { prisma } from "../prisma";

export type CreateLoginEventInput = {
  userId?: string;
  email?: string;
  ipAddress?: string;
  userAgent?: string;
  success: boolean;
  anomaly?: number;
  location?: string;
  metadata?: Record<string, unknown>;
};

export type LoginEventEntity = {
  id: string;
  userId?: string;
  email?: string;
  ipAddress?: string;
  userAgent?: string;
  success: boolean;
  anomaly: number;
  location?: string;
  createdAt: Date;
  metadata?: Record<string, unknown>;
};

const toEntity = (event: {
  id: string;
  userId: string | null;
  email: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  success: boolean;
  anomaly: number;
  location: string | null;
  createdAt: Date;
  metadata: unknown;
}): LoginEventEntity => ({
  id: event.id,
  userId: event.userId ?? undefined,
  email: event.email ?? undefined,
  ipAddress: event.ipAddress ?? undefined,
  userAgent: event.userAgent ?? undefined,
  success: event.success,
  anomaly: event.anomaly,
  location: event.location ?? undefined,
  createdAt: event.createdAt,
  metadata: (event.metadata as Record<string, unknown> | null) ?? undefined,
});

export class LoginEventRepository {
  async createLoginEvent(input: CreateLoginEventInput) {
    return prisma.loginEvent.create({
      data: {
        id: crypto.randomUUID(),
        userId: input.userId,
        email: input.email?.trim().toLowerCase(),
        ipAddress: input.ipAddress,
        userAgent: input.userAgent,
        success: input.success,
        anomaly: input.anomaly ?? 0,
        location: input.location,
        metadata: (input.metadata as never) ?? undefined,
      },
    });
  }

  async countRecentFailures(email: string, since: Date) {
    return prisma.loginEvent.count({
      where: {
        email: email.trim().toLowerCase(),
        success: false,
        createdAt: { gte: since },
      },
    });
  }

  async findSince(since: Date, limit = 100) {
    const events = await prisma.loginEvent.findMany({
      where: { createdAt: { gte: since } },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return events.map(toEntity);
  }

  async findLatest(limit = 50) {
    const events = await prisma.loginEvent.findMany({
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return events.map(toEntity);
  }

  async findByUserSince(userId: string, since: Date, limit = 100) {
    const events = await prisma.loginEvent.findMany({
      where: {
        userId,
        createdAt: { gte: since },
      },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return events.map(toEntity);
  }
}

export const createLoginEventRepository = () => new LoginEventRepository();
