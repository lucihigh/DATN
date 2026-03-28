import { z } from "zod";

export const PROFESSIONAL_PASSWORD_MIN_LENGTH = 12;

export type PasswordPolicyCheck = {
  id: "length" | "uppercase" | "lowercase" | "number" | "special" | "no_spaces";
  label: string;
  met: boolean;
};

export const getPasswordPolicyChecks = (
  password: string,
): PasswordPolicyCheck[] => {
  const value = password || "";

  return [
    {
      id: "length",
      label: `At least ${PROFESSIONAL_PASSWORD_MIN_LENGTH} characters`,
      met: value.length >= PROFESSIONAL_PASSWORD_MIN_LENGTH,
    },
    {
      id: "uppercase",
      label: "At least 1 uppercase letter",
      met: /[A-Z]/.test(value),
    },
    {
      id: "lowercase",
      label: "At least 1 lowercase letter",
      met: /[a-z]/.test(value),
    },
    {
      id: "number",
      label: "At least 1 number",
      met: /\d/.test(value),
    },
    {
      id: "special",
      label: "At least 1 special character",
      met: /[^A-Za-z0-9\s]/.test(value),
    },
    {
      id: "no_spaces",
      label: "No spaces",
      met: !/\s/.test(value),
    },
  ];
};

export const getPasswordStrength = (password: string) => {
  const checks = getPasswordPolicyChecks(password);
  const passedChecks = checks.filter((check) => check.met).length;
  const meetsPolicy = checks.every((check) => check.met);

  if (!password) {
    return {
      checks,
      passedChecks,
      totalChecks: checks.length,
      meetsPolicy: false,
      level: "empty" as const,
      label: "No password yet",
      message: "Use a strong password to protect your account.",
    };
  }

  if (meetsPolicy) {
    return {
      checks,
      passedChecks,
      totalChecks: checks.length,
      meetsPolicy: true,
      level: "strong" as const,
      label: "Strong",
      message: "Professional password standard met.",
    };
  }

  if (passedChecks >= 5) {
    return {
      checks,
      passedChecks,
      totalChecks: checks.length,
      meetsPolicy: false,
      level: "good" as const,
      label: "Good",
      message: "Almost there. Add the missing requirement to meet the policy.",
    };
  }

  if (passedChecks >= 3) {
    return {
      checks,
      passedChecks,
      totalChecks: checks.length,
      meetsPolicy: false,
      level: "fair" as const,
      label: "Fair",
      message: "Improve this password before using it for a real account.",
    };
  }

  return {
    checks,
    passedChecks,
    totalChecks: checks.length,
    meetsPolicy: false,
    level: "weak" as const,
    label: "Weak",
    message: "This password is too easy to guess.",
  };
};

export const meetsProfessionalPasswordPolicy = (password: string) =>
  getPasswordPolicyChecks(password).every((check) => check.met);

export const professionalPasswordSchema = z
  .string()
  .min(
    PROFESSIONAL_PASSWORD_MIN_LENGTH,
    `Password must be at least ${PROFESSIONAL_PASSWORD_MIN_LENGTH} characters long.`,
  )
  .superRefine((password, ctx) => {
    if (meetsProfessionalPasswordPolicy(password)) return;
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message:
        "Password must include uppercase, lowercase, number, special character, and must not contain spaces.",
    });
  });

export const faceIdStepSchema = z.enum([
  "center",
  "move_left",
  "move_right",
  "move_closer",
]);

export const faceIdStepCaptureSchema = z.object({
  step: faceIdStepSchema,
  image: z.string().startsWith("data:image/jpeg;base64,").max(800_000),
  centerX: z.number().min(0).max(1),
  centerY: z.number().min(0).max(1),
  coverage: z.number().min(0).max(1),
  motion: z.number().min(0).max(1),
  aligned: z.boolean().optional(),
});

export const faceIdEnrollmentSchema = z.object({
  challengeToken: z.string().min(24).max(2048),
  descriptor: z.string().min(64).max(4096),
  livenessScore: z.number().min(0).max(1),
  motionScore: z.number().min(0).max(1),
  faceCoverage: z.number().min(0).max(1),
  sampleCount: z.number().int().min(2).max(240),
  completedSteps: z.array(faceIdStepSchema).min(1).max(4),
  stepCaptures: z.array(faceIdStepCaptureSchema).min(1).max(4),
  previewImage: z
    .string()
    .startsWith("data:image/jpeg;base64,")
    .max(2_000_000)
    .optional(),
});

export const registerSchema = z.object({
  email: z.string().email(),
  password: professionalPasswordSchema,
  fullName: z.string().min(2).max(120).optional(),
  userName: z.string().min(2).max(80).optional(),
  phone: z.string().min(6).max(30).optional(),
  address: z.string().min(2).max(255).optional(),
  dob: z.string().min(4).max(20).optional(),
  faceIdEnrollment: faceIdEnrollmentSchema,
  role: z.enum(["USER", "ADMIN"]).default("USER"),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
