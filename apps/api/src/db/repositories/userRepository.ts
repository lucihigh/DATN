import type { ObjectId, OptionalUnlessRequiredId } from "mongodb";

import { BaseRepository } from "../baseRepository";
import { db, readFromMongo } from "../mongo";
import type { Role, UserDoc } from "../schemas";
import { decryptUserPII, encryptUserPII } from "../../security/encryption";

export type CreateUserInput = {
  email: string;
  passwordHash: string;
  role?: Role;
  fullName?: string;
  phone?: UserDoc["phone"];
  address?: UserDoc["address"];
  dob?: UserDoc["dob"];
  metadata?: Record<string, unknown>;
};

export class UserRepository extends BaseRepository<UserDoc> {
  constructor() {
    super(db.users);
  }

  async findByEmail(email: string) {
    return this.findOne({ email: email.trim().toLowerCase() });
  }

  async existsByEmail(email: string) {
    const total = await this.count({ email: email.trim().toLowerCase() });
    return total > 0;
  }

  async createUser(input: CreateUserInput) {
    const now = new Date();
    const payload: OptionalUnlessRequiredId<UserDoc> = {
      email: input.email.trim().toLowerCase(),
      passwordHash: input.passwordHash,
      role: input.role ?? "USER",
      fullName: input.fullName,
      phone: input.phone,
      address: input.address,
      dob: input.dob,
      status: "ACTIVE",
      createdAt: now,
      updatedAt: now,
      metadata: input.metadata ?? {},
    };

    const encryptedPayload = encryptUserPII(payload as UserDoc);
    return this.insertOne(encryptedPayload as OptionalUnlessRequiredId<UserDoc>);
  }

  async findValidatedById(id: string | ObjectId) {
    const doc = await this.findById(id);
    const validated = doc ? readFromMongo.user(doc) : null;
    return validated ? decryptUserPII(validated) : null;
  }

  async touchLastLogin(id: string | ObjectId) {
    return this.updateOne({ _id: id } as never, { $set: { lastLoginAt: new Date(), updatedAt: new Date() } });
  }
}

export const createUserRepository = () => new UserRepository();
