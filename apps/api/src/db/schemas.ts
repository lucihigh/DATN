import { ObjectId } from "mongodb";
import { z } from "zod";

/**
 * Collection names are kept stable so existing Atlas collections are reused.
 * Do NOT rename these values or MongoDB will create new collections.
 */
export const COLLECTIONS = {
  users: "users",
  wallets: "wallets",
  transactions: "transactions",
  loginEvents: "loginEvents",
  auditLogs: "auditLogs",
  securityPolicies: "securityPolicies",
} as const;

// ---- Shared helpers -------------------------------------------------------

const optionalDate = z
  .preprocess((val) => (val === null || val === undefined ? undefined : val), z.coerce.date())
  .optional();

const optionalNumber = z
  .preprocess((val) => (val === null || val === undefined || val === "" ? undefined : val), z.coerce.number())
  .optional();

const optionalBoolean = z
  .preprocess((val) => {
    if (val === null || val === undefined || val === "") return undefined;
    if (typeof val === "string") {
      const normalized = val.trim().toLowerCase();
      if (["true", "1", "yes"].includes(normalized)) return true;
      if (["false", "0", "no"].includes(normalized)) return false;
    }
    return val;
  }, z.boolean())
  .optional();

export const objectIdSchema = z.union([z.instanceof(ObjectId), z.string().trim().min(1)]);

export const encryptionEnvelopeSchema = z
  .object({
    iv: z.string().min(16),
    tag: z.string().min(16),
    data: z.string().min(16).optional(),
    ciphertext: z.string().min(16).optional(),
    algorithm: z.literal("aes-256-gcm").optional(),
    keyId: z.string().optional(),
    version: z.number().optional(),
  })
  .refine((value) => typeof value.data === "string" || typeof value.ciphertext === "string", {
    message: "Encrypted payload must include `data` or `ciphertext`",
  })
  // passthrough keeps backward compatibility if older fields exist
  .passthrough();

export type EncryptedString = z.infer<typeof encryptionEnvelopeSchema>;
export type MaybeEncryptedString = string | EncryptedString;

const piiFieldSchema = z.union([z.string(), encryptionEnvelopeSchema]).optional();

// ---- Users ----------------------------------------------------------------

export const userSchema = z
  .object({
    _id: objectIdSchema.optional(),
    email: z.string().email(),
    passwordHash: z.string().min(1),
    role: z.enum(["USER", "ADMIN"]).catch("USER"),
    fullName: z.string().trim().min(1).optional(),
    phone: piiFieldSchema, // encrypted via field-level crypto; keep optional for legacy docs
    address: piiFieldSchema,
    dob: piiFieldSchema,
    status: z.enum(["ACTIVE", "DISABLED", "PENDING"]).catch("ACTIVE"),
    lastLoginAt: optionalDate,
    createdAt: optionalDate,
    updatedAt: optionalDate,
    metadata: z.record(z.any()).optional(),
  })
  .passthrough();

export type Role = z.infer<typeof userSchema>["role"];
export type UserDoc = z.infer<typeof userSchema>;

// ---- Wallets --------------------------------------------------------------

export const walletSchema = z
  .object({
    _id: objectIdSchema.optional(),
    userId: objectIdSchema.optional(), // optional to avoid rejecting legacy docs; enforce on writes in services
    balance: optionalNumber.default(0),
    currency: z
      .string()
      .trim()
      .min(3)
      .max(6)
      .transform((val) => val.toUpperCase())
      .catch("USD"),
    status: z.enum(["ACTIVE", "FROZEN", "CLOSED"]).catch("ACTIVE"),
    createdAt: optionalDate,
    updatedAt: optionalDate,
    tags: z.array(z.string().trim()).optional(),
    metadata: z.record(z.any()).optional(),
  })
  .passthrough();

export type WalletDoc = z.infer<typeof walletSchema>;

// ---- Transactions ---------------------------------------------------------

export const transactionSchema = z
  .object({
    _id: objectIdSchema.optional(),
    walletId: objectIdSchema.optional(),
    counterpartyWalletId: objectIdSchema.optional(),
    amount: optionalNumber.default(0),
    type: z.enum(["DEPOSIT", "WITHDRAW", "TRANSFER"]).catch("TRANSFER"),
    status: z.enum(["PENDING", "COMPLETED", "FAILED", "REVERSED"]).catch("COMPLETED"),
    description: z.string().trim().max(500).optional(),
    createdAt: optionalDate,
    updatedAt: optionalDate,
    metadata: z.record(z.any()).optional(),
  })
  .passthrough();

export type TransactionDoc = z.infer<typeof transactionSchema>;

// ---- Login events ---------------------------------------------------------

export const loginEventSchema = z
  .object({
    _id: objectIdSchema.optional(),
    userId: objectIdSchema.optional(),
    ipAddress: z.string().trim().min(3).optional(),
    userAgent: z.string().trim().optional(),
    success: optionalBoolean,
    anomaly: optionalNumber,
    location: z.string().trim().optional(),
    createdAt: optionalDate,
    metadata: z.record(z.any()).optional(),
  })
  .passthrough();

export type LoginEventDoc = z.infer<typeof loginEventSchema>;

// ---- Audit logs -----------------------------------------------------------

export const auditLogSchema = z
  .object({
    _id: objectIdSchema.optional(),
    userId: objectIdSchema.optional(),
    actor: z.string().trim().optional(),
    action: z.string().trim(),
    details: z.union([z.string(), z.record(z.any())]).optional(),
    ipAddress: z.string().trim().optional(),
    createdAt: optionalDate,
    metadata: z.record(z.any()).optional(),
  })
  .passthrough();

export type AuditLogDoc = z.infer<typeof auditLogSchema>;

// ---- Security policies ----------------------------------------------------

export const securityPolicySchema = z
  .object({
    _id: objectIdSchema.optional(),
    maxLoginAttempts: optionalNumber.default(5),
    lockoutMinutes: optionalNumber.default(15),
    rateLimitPerMin: optionalNumber.default(60),
    passwordMinLength: optionalNumber.default(12),
    mfaRequired: optionalBoolean.default(false),
    createdAt: optionalDate,
    updatedAt: optionalDate,
  })
  .passthrough();

export type SecurityPolicyDoc = z.infer<typeof securityPolicySchema>;

// ---- Convenience validators ----------------------------------------------

const buildSafeValidator =
  <T>(schema: z.ZodSchema<T>) =>
  (input: unknown) => {
    const parsed = schema.safeParse(input);
    return parsed.success ? parsed.data : null; // null => caller can decide what to do without throwing
  };

export const validators = {
  user: buildSafeValidator(userSchema),
  wallet: buildSafeValidator(walletSchema),
  transaction: buildSafeValidator(transactionSchema),
  loginEvent: buildSafeValidator(loginEventSchema),
  auditLog: buildSafeValidator(auditLogSchema),
  securityPolicy: buildSafeValidator(securityPolicySchema),
};
