export type TrustedIpEntry = {
  ipAddress: string;
  firstSeenAt: string;
  lastSeenAt: string;
  lastVerifiedAt: string;
};

export type ActiveAuthSession = {
  sessionId: string;
  issuedAt: string;
  ipAddress?: string;
  userAgent?: string;
};

export type AuthSecurityState = {
  trustedIps: TrustedIpEntry[];
  lastLoginIp?: string;
  lastLoginAt?: string;
  activeSession?: ActiveAuthSession;
};

const AUTH_SECURITY_KEY = "authSecurity";
const MAX_TRUSTED_IPS = 10;
const LOOPBACK_IPS = new Set(["127.0.0.1", "::1", "0:0:0:0:0:0:0:1"]);

const asObject = (value: unknown) =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const asIsoString = (value: unknown) => {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)))
    return undefined;
  return value;
};

const asTrimmedString = (value: unknown) =>
  typeof value === "string" && value.trim() ? value.trim() : undefined;

const sortTrustedIps = (entries: TrustedIpEntry[]) =>
  [...entries]
    .sort((left, right) => {
      const leftTime = Date.parse(left.lastSeenAt);
      const rightTime = Date.parse(right.lastSeenAt);
      return rightTime - leftTime;
    })
    .slice(0, MAX_TRUSTED_IPS);

export const normalizeIpAddress = (
  value?: string | null,
): string | undefined => {
  if (!value) return undefined;
  const normalized = value.trim().replace(/^for=/i, "").replace(/^"|"$/g, "");
  if (!normalized) return undefined;
  if (normalized.startsWith("[") && normalized.includes("]")) {
    return normalizeIpAddress(normalized.slice(1, normalized.indexOf("]")));
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(normalized)) {
    return normalizeIpAddress(normalized.slice(0, normalized.lastIndexOf(":")));
  }
  if (normalized === "::1") return "127.0.0.1";
  if (normalized.startsWith("::ffff:")) return normalized.slice(7);
  const zoneIndex = normalized.indexOf("%");
  return zoneIndex >= 0 ? normalized.slice(0, zoneIndex) : normalized;
};

const isLoopbackIpAddress = (value?: string | null) => {
  const normalized = normalizeIpAddress(value);
  return normalized ? LOOPBACK_IPS.has(normalized) : false;
};

const isPrivateIpv4 = (value: string) => {
  const parts = value.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return false;
  }

  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
};

const isPrivateIpv6 = (value: string) => {
  const normalized = value.toLowerCase();
  return (
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
};

const isPrivateIpAddress = (value?: string | null) => {
  const normalized = normalizeIpAddress(value);
  if (!normalized) return false;
  if (isLoopbackIpAddress(normalized)) return true;
  if (normalized.includes(".")) return isPrivateIpv4(normalized);
  if (normalized.includes(":")) return isPrivateIpv6(normalized);
  return false;
};

const readHeaderValues = (value: unknown) => {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string");
  }
  return typeof value === "string" ? [value] : [];
};

const parseForwardedHeader = (value: string) =>
  value
    .split(",")
    .flatMap((segment) => segment.split(";"))
    .map((part) => part.trim())
    .filter((part) => /^for=/i.test(part))
    .map((part) => part.replace(/^for=/i, "").trim())
    .filter(Boolean);

type RequestIpInput = {
  ip?: string | null;
  headers?: Record<string, unknown>;
  socket?: { remoteAddress?: string | null } | null;
};

export const resolveRequestIpAddress = (input: RequestIpInput) => {
  const headers = input.headers ?? {};
  const candidates = [
    ...readHeaderValues(headers["cf-connecting-ip"]),
    ...readHeaderValues(headers["true-client-ip"]),
    ...readHeaderValues(headers["x-real-ip"]),
    ...readHeaderValues(headers["x-forwarded-for"]).flatMap((value) =>
      value.split(","),
    ),
    ...readHeaderValues(headers.forwarded).flatMap(parseForwardedHeader),
    input.ip ?? undefined,
    input.socket?.remoteAddress ?? undefined,
  ]
    .map((value) =>
      normalizeIpAddress(typeof value === "string" ? value : undefined),
    )
    .filter((value): value is string => Boolean(value) && value !== "unknown");

  const publicIp = candidates.find((value) => !isPrivateIpAddress(value));
  if (publicIp) return publicIp;

  const nonLoopbackIp = candidates.find((value) => !isLoopbackIpAddress(value));
  if (nonLoopbackIp) return nonLoopbackIp;

  return undefined;
};

const toTrustedIpEntry = (value: unknown): TrustedIpEntry | null => {
  const raw = asObject(value);
  const ipAddress = normalizeIpAddress(
    typeof raw.ipAddress === "string" ? raw.ipAddress : undefined,
  );
  const firstSeenAt = asIsoString(raw.firstSeenAt);
  const lastSeenAt = asIsoString(raw.lastSeenAt);
  const lastVerifiedAt = asIsoString(raw.lastVerifiedAt);
  if (!ipAddress || !firstSeenAt || !lastSeenAt || !lastVerifiedAt) return null;
  return {
    ipAddress,
    firstSeenAt,
    lastSeenAt,
    lastVerifiedAt,
  };
};

const toActiveAuthSession = (value: unknown): ActiveAuthSession | null => {
  const raw = asObject(value);
  const sessionId = asTrimmedString(raw.sessionId);
  const issuedAt = asIsoString(raw.issuedAt);
  if (!sessionId || !issuedAt) return null;
  return {
    sessionId,
    issuedAt,
    ipAddress: normalizeIpAddress(
      typeof raw.ipAddress === "string" ? raw.ipAddress : undefined,
    ),
    userAgent: asTrimmedString(raw.userAgent),
  };
};

export const getAuthSecurityState = (
  metadata?: Record<string, unknown>,
): AuthSecurityState => {
  const raw = asObject(metadata?.[AUTH_SECURITY_KEY]);
  const trustedIps = Array.isArray(raw.trustedIps)
    ? raw.trustedIps
        .map((entry) => toTrustedIpEntry(entry))
        .filter((entry): entry is TrustedIpEntry => Boolean(entry))
    : [];

  return {
    trustedIps: sortTrustedIps(trustedIps),
    lastLoginIp: normalizeIpAddress(
      typeof raw.lastLoginIp === "string" ? raw.lastLoginIp : undefined,
    ),
    lastLoginAt: asIsoString(raw.lastLoginAt),
    activeSession: toActiveAuthSession(raw.activeSession) ?? undefined,
  };
};

export const setAuthSecurityState = (
  metadata: Record<string, unknown> | undefined,
  state: AuthSecurityState,
) => ({
  ...(metadata ?? {}),
  [AUTH_SECURITY_KEY]: {
    trustedIps: sortTrustedIps(state.trustedIps),
    lastLoginIp: state.lastLoginIp,
    lastLoginAt: state.lastLoginAt,
    activeSession: state.activeSession,
  },
});

export const isTrustedIp = (
  state: AuthSecurityState,
  ipAddress?: string | null,
) => {
  const normalized = normalizeIpAddress(ipAddress);
  if (!normalized) return false;
  return state.trustedIps.some((entry) => entry.ipAddress === normalized);
};

export const recordSuccessfulLoginIp = (
  state: AuthSecurityState,
  ipAddress?: string | null,
  options?: {
    trustIp?: boolean;
    occurredAt?: Date;
  },
): AuthSecurityState => {
  const normalized = normalizeIpAddress(ipAddress);
  const occurredAt = options?.occurredAt ?? new Date();
  const nowIso = occurredAt.toISOString();
  if (!normalized) {
    return {
      ...state,
      lastLoginAt: nowIso,
    };
  }

  const trustedIps = [...state.trustedIps];
  const existingIndex = trustedIps.findIndex(
    (entry) => entry.ipAddress === normalized,
  );

  if (existingIndex >= 0) {
    const existing = trustedIps[existingIndex];
    trustedIps[existingIndex] = {
      ...existing,
      lastSeenAt: nowIso,
      lastVerifiedAt: options?.trustIp ? nowIso : existing.lastVerifiedAt,
    };
  } else if (options?.trustIp) {
    trustedIps.push({
      ipAddress: normalized,
      firstSeenAt: nowIso,
      lastSeenAt: nowIso,
      lastVerifiedAt: nowIso,
    });
  }

  return {
    trustedIps: sortTrustedIps(trustedIps),
    lastLoginIp: normalized,
    lastLoginAt: nowIso,
    activeSession: state.activeSession,
  };
};

export const activateAuthSession = (
  state: AuthSecurityState,
  input: {
    sessionId: string;
    ipAddress?: string | null;
    userAgent?: string | null;
    occurredAt?: Date;
  },
): AuthSecurityState => {
  const sessionId = input.sessionId.trim();
  const occurredAt = input.occurredAt ?? new Date();
  if (!sessionId) return state;

  return {
    ...state,
    activeSession: {
      sessionId,
      issuedAt: occurredAt.toISOString(),
      ipAddress: normalizeIpAddress(input.ipAddress),
      userAgent: asTrimmedString(input.userAgent),
    },
  };
};

export const clearActiveAuthSession = (
  state: AuthSecurityState,
): AuthSecurityState => ({
  ...state,
  activeSession: undefined,
});

export const isActiveAuthSession = (
  state: AuthSecurityState,
  sessionId?: string | null,
) => {
  const normalized = typeof sessionId === "string" ? sessionId.trim() : "";
  if (!normalized) return false;
  return state.activeSession?.sessionId === normalized;
};

export const getLatestDifferentTrustedIp = (
  state: AuthSecurityState,
  currentIp?: string | null,
) => {
  const normalized = normalizeIpAddress(currentIp);
  return state.trustedIps.find((entry) => entry.ipAddress !== normalized);
};

export const buildRecentIpNotice = (
  state: AuthSecurityState,
  currentIp: string | undefined,
  timeZone: string,
) => {
  const normalized = normalizeIpAddress(currentIp);
  const previousIp = normalizeIpAddress(state.lastLoginIp);
  if (!normalized || !previousIp || previousIp === normalized) return undefined;

  const previousTime = state.lastLoginAt ? new Date(state.lastLoginAt) : null;
  const formattedTime =
    previousTime && !Number.isNaN(previousTime.getTime())
      ? new Intl.DateTimeFormat("en-US", {
          dateStyle: "medium",
          timeStyle: "short",
          timeZone,
        }).format(previousTime)
      : null;

  return formattedTime
    ? `Recent successful sign-in detected from IP ${previousIp} at ${formattedTime}.`
    : `Recent successful sign-in detected from IP ${previousIp}.`;
};
