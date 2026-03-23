import { prisma } from "../db/prisma";

const DEFAULT_SECURITY_POLICY = {
  maxLoginAttempts: 5,
  lockoutMinutes: 15,
  anomalyAlertThreshold: 0.7,
};

export type SecurityPolicy = typeof DEFAULT_SECURITY_POLICY;

const SECURITY_POLICY_CACHE_TTL_MS = Number(
  process.env.SECURITY_POLICY_CACHE_TTL_MS || "15000",
);

let cachedSecurityPolicy: {
  value: SecurityPolicy;
  expiresAt: number;
} | null = null;
let pendingSecurityPolicy: Promise<SecurityPolicy> | null = null;

export const invalidateSecurityPolicyCache = () => {
  cachedSecurityPolicy = null;
  pendingSecurityPolicy = null;
};

export const getSecurityPolicy = async (): Promise<SecurityPolicy> => {
  if (cachedSecurityPolicy && cachedSecurityPolicy.expiresAt > Date.now()) {
    return { ...cachedSecurityPolicy.value };
  }

  if (pendingSecurityPolicy) {
    return pendingSecurityPolicy.then((policy) => ({ ...policy }));
  }

  pendingSecurityPolicy = (async () => {
    try {
      const policy = await prisma.securityPolicy.findFirst({
        orderBy: { createdAt: "desc" },
      });

      const value = !policy
        ? { ...DEFAULT_SECURITY_POLICY }
        : {
            maxLoginAttempts: policy.maxLoginAttempts,
            lockoutMinutes: policy.lockoutMinutes,
            anomalyAlertThreshold: policy.anomalyAlertThreshold,
          };

      cachedSecurityPolicy = {
        value,
        expiresAt: Date.now() + SECURITY_POLICY_CACHE_TTL_MS,
      };

      return value;
    } catch (err) {
      console.warn("Falling back to default security policy", err);
      return { ...DEFAULT_SECURITY_POLICY };
    } finally {
      pendingSecurityPolicy = null;
    }
  })();

  return pendingSecurityPolicy.then((policy) => ({ ...policy }));
};

export const getDefaultSecurityPolicy = () => ({ ...DEFAULT_SECURITY_POLICY });
