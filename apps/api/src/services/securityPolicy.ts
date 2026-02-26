import { getDb, readFromMongo } from "../db/mongo";

const DEFAULT_SECURITY_POLICY = {
  maxLoginAttempts: 5,
  lockoutMinutes: 15,
  anomalyAlertThreshold: 0.7,
};

export type SecurityPolicy = typeof DEFAULT_SECURITY_POLICY;

export const getSecurityPolicy = async (): Promise<SecurityPolicy> => {
  try {
    const raw = await getDb()
      .collection("securityPolicies")
      .findOne({}, { sort: { createdAt: -1 } });
    const validated = raw ? readFromMongo.securityPolicy(raw) : null;
    return { ...DEFAULT_SECURITY_POLICY, ...(validated ?? {}) };
  } catch (err) {
    console.warn("Falling back to default security policy", err);
    return { ...DEFAULT_SECURITY_POLICY };
  }
};

export const getDefaultSecurityPolicy = () => ({ ...DEFAULT_SECURITY_POLICY });
