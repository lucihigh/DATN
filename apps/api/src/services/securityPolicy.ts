import { prisma } from "../db/prisma";

const DEFAULT_SECURITY_POLICY = {
  maxLoginAttempts: 5,
  lockoutMinutes: 15,
  anomalyAlertThreshold: 0.7,
};

export type SecurityPolicy = typeof DEFAULT_SECURITY_POLICY;

export const getSecurityPolicy = async (): Promise<SecurityPolicy> => {
  try {
    const policy = await prisma.securityPolicy.findFirst({
      orderBy: { createdAt: "desc" },
    });

    if (!policy) return { ...DEFAULT_SECURITY_POLICY };

    return {
      maxLoginAttempts: policy.maxLoginAttempts,
      lockoutMinutes: policy.lockoutMinutes,
      anomalyAlertThreshold: policy.anomalyAlertThreshold,
    };
  } catch (err) {
    console.warn("Falling back to default security policy", err);
    return { ...DEFAULT_SECURITY_POLICY };
  }
};

export const getDefaultSecurityPolicy = () => ({ ...DEFAULT_SECURITY_POLICY });

