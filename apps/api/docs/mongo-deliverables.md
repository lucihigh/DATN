# MongoDB Deliverables (Team Handover)

This file is the handover checklist for MongoDB work in `apps/api`.

## 1) Final DB schema (collections + field types)

Defined in `src/db/schemas.ts`:

- `users`
  - `_id: ObjectId`
  - `email: string (email)`
  - `passwordHash: string`
  - `role: "USER" | "ADMIN"`
  - `fullName?: string`
  - `phone?: string | EncryptedString`
  - `address?: string | EncryptedString`
  - `dob?: string | EncryptedString`
  - `status: "ACTIVE" | "DISABLED" | "PENDING"`
  - `lastLoginAt?: Date`
  - `createdAt?: Date`
  - `updatedAt?: Date`
  - `metadata?: Record<string, unknown>`

- `wallets`
  - `_id: ObjectId`
  - `userId?: ObjectId`
  - `balance?: number`
  - `currency?: string`
  - `status?: "ACTIVE" | "FROZEN" | "CLOSED"`
  - `createdAt?: Date`
  - `updatedAt?: Date`
  - `tags?: string[]`
  - `metadata?: Record<string, unknown>`

- `transactions`
  - `_id: ObjectId`
  - `walletId?: ObjectId`
  - `counterpartyWalletId?: ObjectId`
  - `fromUserId?: ObjectId`
  - `toUserId?: ObjectId`
  - `amount?: number`
  - `type?: "DEPOSIT" | "WITHDRAW" | "TRANSFER"`
  - `status?: "PENDING" | "COMPLETED" | "FAILED" | "REVERSED"`
  - `description?: string`
  - `createdAt?: Date`
  - `updatedAt?: Date`
  - `metadata?: Record<string, unknown>`

- `loginEvents`
  - `_id: ObjectId`
  - `userId?: ObjectId`
  - `email?: string (email)`
  - `ipAddress?: string`
  - `userAgent?: string`
  - `success?: boolean`
  - `anomaly?: number`
  - `location?: string`
  - `createdAt?: Date`
  - `metadata?: Record<string, unknown>`

- `auditLogs`
  - `_id: ObjectId`
  - `userId?: ObjectId`
  - `actor?: string`
  - `action: string`
  - `details?: string | Record<string, unknown>`
  - `ipAddress?: string`
  - `createdAt?: Date`
  - `metadata?: Record<string, unknown>`

- `securityPolicies`
  - `_id: ObjectId`
  - `maxLoginAttempts?: number`
  - `lockoutMinutes?: number`
  - `rateLimitPerMin?: number`
  - `passwordMinLength?: number`
  - `mfaRequired?: boolean`
  - `createdAt?: Date`
  - `updatedAt?: Date`

## 2) `mongo.ts` connection and mapping

File: `src/db/mongo.ts`

- Loads env from current dir, with fallback to repo root `.env`
- Connects with `MONGODB_URI`, `MONGODB_DB`
- Exposes typed collection accessors via `db.<collection>()`
- Centralized normalization:
  - `readFromMongo.*` for defensive reads
  - `writeToMongo.*` for write-time validation/mapping
  - ObjectId and timestamp normalization

## 3) `encryption.ts` + key setup

File: `src/security/encryption.ts`

- Uses AES-256-GCM for field-level encryption
- Supports base64 or hex key input from env
- Env:
  - `ENCRYPTION_KEY` (32-byte key, base64 or hex)
  - `ENCRYPTION_KEY_ID` (optional key label)
  - `ENCRYPTION_KEYS` (optional comma-separated keyId:value list for rotation)

Example key generation:

```bash
openssl rand -base64 32
```

Example rotation setup:

```bash
ENCRYPTION_KEY_ID=primary
ENCRYPTION_KEYS=primary:<base64-key>,legacy:<base64-key>
```

## 4) Validation source of truth

File: `src/db/schemas.ts`

- All collection schemas are defined with Zod
- Shared validators (`validators.*`) are used by DB layer
- ObjectId/date coercion is centralized and consistent

## 5) Mongo Atlas + env config

- Put connection values in `.env`:
  - `MONGODB_URI=mongodb+srv://<user>:<pass>@<cluster>/<db>?retryWrites=true&w=majority`
  - `MONGODB_DB=ComputerResearchProject`
- Initialize indexes:

```bash
pnpm --filter @secure-wallet/api db:init
```

- Index definitions are in `src/db/indexes.ts`.
