// Logical schemas (Mongo collections) with standardized field names.
// Keep these in sync with prisma/schema.prisma and OpenAPI contract.

export type Role = "USER" | "ADMIN";

export interface UserDoc {
  _id?: string;
  email: string;
  passwordHash: string;
  role: Role;
  createdAt?: Date;
}

export interface WalletDoc {
  _id?: string;
  userId: string;
  balance: number;
  currency: string; // e.g. "USD"
  createdAt?: Date;
  updatedAt?: Date;
}

export interface TransactionDoc {
  _id?: string;
  walletId: string;
  amount: number;
  type: "DEPOSIT" | "WITHDRAW" | "TRANSFER";
  description?: string;
  createdAt?: Date;
}

export interface LoginEventDoc {
  _id?: string;
  userId?: string;
  ipAddress: string;
  userAgent?: string;
  anomaly?: number;
  createdAt?: Date;
}

export interface AuditLogDoc {
  _id?: string;
  userId?: string;
  action: string;
  details?: string;
  createdAt?: Date;
}

export interface SecurityPolicyDoc {
  _id?: string;
  maxLoginAttempts: number;
  lockoutMinutes: number;
  rateLimitPerMin: number;
  createdAt?: Date;
}

export const COLLECTIONS = {
  users: "users",
  wallets: "wallets",
  transactions: "transactions",
  loginEvents: "loginEvents",
  auditLogs: "auditLogs",
  securityPolicies: "securityPolicies",
} as const;
