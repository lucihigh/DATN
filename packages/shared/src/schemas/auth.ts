import { z } from "zod";

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  fullName: z.string().min(2).max(120).optional(),
  userName: z.string().min(2).max(80).optional(),
  phone: z.string().min(6).max(30).optional(),
  address: z.string().min(2).max(255).optional(),
  dob: z.string().min(4).max(20).optional(),
  role: z.enum(["USER", "ADMIN"]).default("USER"),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
