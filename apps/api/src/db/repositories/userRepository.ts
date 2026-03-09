import crypto from "crypto";

import { prisma } from "../prisma";
import { decryptUserPII, encryptUserPII } from "../../security/encryption";

export type CreateUserInput = {
  email: string;
  passwordHash: string;
  role?: "USER" | "ADMIN";
  fullName?: string;
  phone?: unknown;
  address?: unknown;
  dob?: unknown;
  metadata?: Record<string, unknown>;
};

export type UserEntity = {
  id: string;
  email: string;
  passwordHash: string;
  role: "USER" | "ADMIN";
  status: "ACTIVE" | "DISABLED" | "PENDING";
  fullName?: string;
  phone?: unknown;
  address?: unknown;
  dob?: unknown;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
  metadata?: Record<string, unknown>;
};

type UserStatusValue = "ACTIVE" | "DISABLED" | "PENDING";

const asJson = (value: unknown) => value as never;

const toEntity = (user: {
  id: string;
  email: string;
  passwordHash: string;
  role: "USER" | "ADMIN";
  status: "ACTIVE" | "DISABLED" | "PENDING";
  fullName: string | null;
  phone: unknown;
  address: unknown;
  dob: unknown;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  metadata: unknown;
}): UserEntity => {
  const decrypted = decryptUserPII({
    ...user,
    phone: user.phone ?? undefined,
    address: user.address ?? undefined,
    dob: user.dob ?? undefined,
  } as never) as Record<string, unknown>;

  return {
    id: user.id,
    email: user.email,
    passwordHash: user.passwordHash,
    role: user.role,
    status: user.status,
    fullName: user.fullName ?? undefined,
    phone: decrypted.phone,
    address: decrypted.address,
    dob: decrypted.dob,
    lastLoginAt: user.lastLoginAt ?? undefined,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    metadata: (user.metadata as Record<string, unknown> | null) ?? undefined,
  };
};

export class UserRepository {
  async findByEmail(email: string) {
    const user = await prisma.user.findUnique({
      where: { email: email.trim().toLowerCase() },
    });
    return user ? toEntity(user) : null;
  }

  async existsByEmail(email: string) {
    const total = await prisma.user.count({
      where: { email: email.trim().toLowerCase() },
    });
    return total > 0;
  }

  async createUser(input: CreateUserInput) {
    const encrypted = encryptUserPII({
      phone: input.phone,
      address: input.address,
      dob: input.dob,
    } as never) as Record<string, unknown>;

    return prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: input.email.trim().toLowerCase(),
        passwordHash: input.passwordHash,
        role: input.role ?? "USER",
        status: "ACTIVE",
        fullName: input.fullName,
        phone: encrypted.phone === undefined ? undefined : asJson(encrypted.phone),
        address:
          encrypted.address === undefined ? undefined : asJson(encrypted.address),
        dob: encrypted.dob === undefined ? undefined : asJson(encrypted.dob),
        metadata: input.metadata ? asJson(input.metadata) : undefined,
      },
    });
  }

  async findValidatedById(id: string) {
    const user = await prisma.user.findUnique({ where: { id } });
    return user ? toEntity(user) : null;
  }

  async touchLastLogin(id: string) {
    return prisma.user.update({
      where: { id },
      data: { lastLoginAt: new Date() },
    });
  }

  async updatePassword(id: string, passwordHash: string) {
    return prisma.user.update({
      where: { id },
      data: { passwordHash },
    });
  }

  async setStatus(id: string, status: UserStatusValue) {
    return prisma.user.update({
      where: { id },
      data: { status },
    });
  }

  async findMany(limit = 200) {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return users.map(toEntity);
  }
}

export const createUserRepository = () => new UserRepository();

