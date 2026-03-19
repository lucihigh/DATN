import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";

export type User = {
  id: string;
  name: string;
  email: string;
  avatar: string;
  role: "USER" | "ADMIN";
};

export type LoginOtpRequiredResult = {
  status: "otp_required";
  challengeId: string;
  destination: string;
  expiresAt: string;
  availableAt?: string;
  retryAfterSeconds: number;
  notice?: string;
  monitoring?: LoginMonitoring | null;
};

export type LoginAuthenticatedResult = {
  status: "authenticated";
  notice?: string;
  monitoring?: LoginMonitoring | null;
  security?: SessionSecurity;
};

export type LoginResult = LoginOtpRequiredResult | LoginAuthenticatedResult;

export type AuthCompletionResult = {
  notice?: string;
  security?: SessionSecurity;
};

export type SliderCaptchaProof = {
  captchaToken: string;
  captchaOffset: number;
};

export type FaceIdEnrollmentProof = {
  challengeToken: string;
  descriptor: string;
  livenessScore: number;
  motionScore: number;
  faceCoverage: number;
  sampleCount: number;
  completedSteps: ("center" | "move_left" | "move_right" | "move_closer")[];
  stepCaptures: Array<{
    step: "center" | "move_left" | "move_right" | "move_closer";
    image: string;
    centerX: number;
    centerY: number;
    coverage: number;
    motion: number;
    aligned?: boolean;
  }>;
  previewImage?: string;
};

type BrowserDeviceContext = {
  browser?: string;
  browserVersion?: string;
  platform?: string;
  platformVersion?: string;
  deviceType?: string;
  mobile?: boolean;
  deviceTitle?: string;
  deviceDetail?: string;
};

type NavigatorUADataBrand = {
  brand: string;
  version: string;
};

type NavigatorUAData = {
  brands: NavigatorUADataBrand[];
  mobile: boolean;
  platform: string;
  getHighEntropyValues?: (
    hints: string[],
  ) => Promise<
    Record<string, unknown> & { fullVersionList?: NavigatorUADataBrand[] }
  >;
};

declare global {
  interface Navigator {
    userAgentData?: NavigatorUAData;
  }
}

export type SessionSecurity = {
  riskLevel: string;
  reviewReason?: string;
  verificationMethod?: string | null;
  restrictLargeTransfers: boolean;
  maxTransferAmount?: number | null;
};

export type SessionReplacementAlert = {
  token: string;
  email: string;
  issuedAt?: string;
  ipAddress?: string;
  userAgent?: string;
};

export type SessionAlertResponse =
  | {
      status: "acknowledged";
      message: string;
      active: boolean;
    }
  | {
      status: "secured";
      message: string;
      email: string;
      destination: string;
      challengeId?: string;
      expiresAt?: string;
      retryAfterSeconds: number;
    };

export type LoginMonitoring = {
  score: number;
  riskLevel: string;
  reasons: string[];
  monitoringOnly: boolean;
  action?: string;
  requireOtp: boolean;
  otpChannel?: string | null;
  otpReason?: string | null;
  modelSource?: string | null;
  modelVersion?: string | null;
  requestKey?: string | null;
};

const USER_STORAGE_KEY = "fpipay_user";
const TOKEN_STORAGE_KEY = "fpipay_token";
const TOKEN_EXPIRES_AT_STORAGE_KEY = "fpipay_token_expires_at";
const SESSION_SECURITY_STORAGE_KEY = "fpipay_session_security";
const DEFAULT_AVATAR = "https://i.pravatar.cc/80?img=12";
const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://localhost:4000";
const SESSION_EXPIRED_EVENT = "auth:session-expired";
const SESSION_VERIFY_INTERVAL_MS = 10000;
const PUBLIC_IP_CACHE_KEY = "fpipay_public_ip_cache";
const PUBLIC_IP_CACHE_TTL_MS = 30 * 1000;
const PUBLIC_IP_FETCH_TIMEOUT_MS = 5000;

type SessionExpiredReason = "expired" | "replaced";

const AuthContext = createContext<{
  user: User | null;
  token: string | null;
  requestLoginOtp: (
    email: string,
    password: string,
    captcha: SliderCaptchaProof,
  ) => Promise<LoginResult>;
  verifyLoginOtp: (
    challengeId: string,
    otp: string,
    captcha: SliderCaptchaProof,
  ) => Promise<AuthCompletionResult>;
  requestRegisterOtp: (payload: {
    fullName: string;
    userName: string;
    email: string;
    phone: string;
    address: string;
    dob: string;
    password: string;
    captcha: SliderCaptchaProof;
    faceEnrollment: FaceIdEnrollmentProof;
  }) => Promise<{
    challengeId: string;
    destination: string;
    expiresAt: string;
    retryAfterSeconds: number;
  }>;
  verifyRegisterOtp: (
    challengeId: string,
    otp: string,
  ) => Promise<AuthCompletionResult>;
  requestPasswordResetOtp: (
    email: string,
    captcha: SliderCaptchaProof,
  ) => Promise<{
    challengeId: string;
    destination: string;
    expiresAt: string;
    retryAfterSeconds: number;
  }>;
  resetPasswordWithOtp: (payload: {
    email: string;
    challengeId: string;
    otp: string;
    newPassword: string;
  }) => Promise<void>;
  respondToSessionAlert: (
    alertToken: string,
    action: "confirm" | "secure_account",
  ) => Promise<SessionAlertResponse>;
  sessionSecurity: SessionSecurity;
  lastLoginMonitoring: LoginMonitoring | null;
  clearLoginMonitoring: () => void;
  updateUser: (patch: Partial<User>) => void;
  logout: () => void;
} | null>(null);

const toDisplayName = (email: string) => {
  const base = email.split("@")[0]?.trim() || "User";
  return base
    .split(/[._-]+/)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
};

const parseApiError = (err: unknown) => {
  if (err instanceof TypeError) {
    return `Cannot connect to API server (${API_BASE}). Start backend first.`;
  }
  if (err instanceof Error) return err.message;
  return "Request failed";
};

const extractApiErrorMessage = (data: unknown, fallback: string) => {
  if (!data || typeof data !== "object") return fallback;
  const asRecord = data as Record<string, unknown>;
  const rawError = asRecord.error;
  if (typeof rawError === "string" && rawError.trim()) return rawError;
  if (rawError && typeof rawError === "object") {
    const errObj = rawError as Record<string, unknown>;
    const fieldErrors =
      errObj.fieldErrors && typeof errObj.fieldErrors === "object"
        ? (errObj.fieldErrors as Record<string, unknown>)
        : null;
    if (fieldErrors) {
      for (const value of Object.values(fieldErrors)) {
        if (Array.isArray(value) && value[0] && typeof value[0] === "string") {
          return value[0];
        }
      }
    }
    const formErrors = errObj.formErrors;
    if (
      Array.isArray(formErrors) &&
      formErrors[0] &&
      typeof formErrors[0] === "string"
    ) {
      return formErrors[0];
    }
  }
  return fallback;
};

const decodeJwtExpiresAt = (token: string) => {
  try {
    const [, payload] = token.split(".");
    if (!payload) return null;
    const normalized = payload
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(Math.ceil(payload.length / 4) * 4, "=");
    const parsed = JSON.parse(atob(normalized)) as { exp?: unknown };
    return typeof parsed.exp === "number" ? parsed.exp * 1000 : null;
  } catch {
    return null;
  }
};

const toStringArray = (value: unknown) =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

const parseSessionSecurity = (value: unknown): SessionSecurity => {
  if (!value || typeof value !== "object") {
    return {
      riskLevel: "low",
      restrictLargeTransfers: false,
      maxTransferAmount: null,
    };
  }
  const data = value as Record<string, unknown>;
  return {
    riskLevel:
      typeof data.riskLevel === "string" ? data.riskLevel.toLowerCase() : "low",
    reviewReason:
      typeof data.reviewReason === "string" ? data.reviewReason : undefined,
    verificationMethod:
      typeof data.verificationMethod === "string"
        ? data.verificationMethod
        : null,
    restrictLargeTransfers: Boolean(data.restrictLargeTransfers),
    maxTransferAmount:
      typeof data.maxTransferAmount === "number" &&
      Number.isFinite(data.maxTransferAmount)
        ? data.maxTransferAmount
        : null,
  };
};

const parseLoginMonitoring = (value: unknown): LoginMonitoring | null => {
  if (!value || typeof value !== "object") return null;
  const data = value as Record<string, unknown>;
  const scoreRaw = data.score ?? data.anomaly_score;
  const score =
    typeof scoreRaw === "number" && Number.isFinite(scoreRaw) ? scoreRaw : 0;

  return {
    score,
    riskLevel:
      typeof data.riskLevel === "string"
        ? data.riskLevel
        : typeof data.risk_level === "string"
          ? data.risk_level
          : "low",
    reasons: toStringArray(data.reasons),
    monitoringOnly: Boolean(
      data.monitoringOnly ?? data.monitoring_only ?? true,
    ),
    action: typeof data.action === "string" ? data.action : undefined,
    requireOtp: Boolean(data.requireOtp ?? data.require_otp_sms),
    otpChannel:
      typeof data.otpChannel === "string"
        ? data.otpChannel
        : typeof data.otp_channel === "string"
          ? data.otp_channel
          : null,
    otpReason:
      typeof data.otpReason === "string"
        ? data.otpReason
        : typeof data.otp_reason === "string"
          ? data.otp_reason
          : null,
    modelSource:
      typeof data.modelSource === "string"
        ? data.modelSource
        : typeof data.model_source === "string"
          ? data.model_source
          : null,
    modelVersion:
      typeof data.modelVersion === "string"
        ? data.modelVersion
        : typeof data.model_version === "string"
          ? data.model_version
          : null,
    requestKey:
      typeof data.requestKey === "string"
        ? data.requestKey
        : typeof data.request_key === "string"
          ? data.request_key
          : null,
  };
};

const readCachedPublicIp = () => {
  try {
    const raw = sessionStorage.getItem(PUBLIC_IP_CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as {
      ip?: unknown;
      fetchedAt?: unknown;
    };
    if (
      typeof parsed.ip !== "string" ||
      !parsed.ip.trim() ||
      typeof parsed.fetchedAt !== "number" ||
      !Number.isFinite(parsed.fetchedAt)
    ) {
      return null;
    }
    if (Date.now() - parsed.fetchedAt > PUBLIC_IP_CACHE_TTL_MS) {
      return null;
    }
    return parsed.ip.trim();
  } catch {
    return null;
  }
};

const cachePublicIp = (ip: string) => {
  try {
    sessionStorage.setItem(
      PUBLIC_IP_CACHE_KEY,
      JSON.stringify({
        ip,
        fetchedAt: Date.now(),
      }),
    );
  } catch {
    // ignore storage errors
  }
};

type PublicIpProvider = {
  url: string;
  responseType: "json" | "text";
  field?: string;
};

const PUBLIC_IP_PROVIDERS: PublicIpProvider[] = [
  {
    url: "https://api64.ipify.org?format=json",
    responseType: "json",
    field: "ip",
  },
  {
    url: "https://api.ipify.org?format=json",
    responseType: "json",
    field: "ip",
  },
  {
    url: "https://ipwho.is/",
    responseType: "json",
    field: "ip",
  },
  {
    url: "https://api.myip.com",
    responseType: "json",
    field: "ip",
  },
];

const normalizePublicIpCandidate = (value: unknown) => {
  if (typeof value !== "string") return "";
  return value.trim().replace(/\s+/g, "");
};

const fetchPublicIpFromProvider = async (provider: PublicIpProvider) => {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(
    () => controller.abort(),
    PUBLIC_IP_FETCH_TIMEOUT_MS,
  );

  try {
    const resp = await fetch(provider.url, {
      cache: "no-store",
      headers:
        provider.responseType === "json"
          ? { Accept: "application/json" }
          : undefined,
      signal: controller.signal,
    });

    if (!resp.ok) return "";

    if (provider.responseType === "text") {
      return normalizePublicIpCandidate(await resp.text().catch(() => ""));
    }

    const data = (await resp.json().catch(() => null)) as Record<
      string,
      unknown
    > | null;
    return normalizePublicIpCandidate(
      provider.field ? data?.[provider.field] : "",
    );
  } catch {
    return "";
  } finally {
    window.clearTimeout(timeoutId);
  }
};

const resolvePublicIpAddress = async () => {
  const cachedIp = readCachedPublicIp();
  if (cachedIp) return cachedIp;

  for (const provider of PUBLIC_IP_PROVIDERS) {
    const ip = await fetchPublicIpFromProvider(provider);
    if (ip) {
      cachePublicIp(ip);
      return ip;
    }
  }

  return "";
};

const buildApiHeaders = async (headers?: Record<string, string>) => {
  const publicIp = await resolvePublicIpAddress();
  return {
    ...(headers ?? {}),
    ...(publicIp ? { "x-demo-public-ip": publicIp } : {}),
  };
};

const normalizeBrowserBrand = (value?: string) => {
  const normalized = value?.trim().toLowerCase() || "";
  if (!normalized) return "";
  if (normalized.includes("edge")) return "Edge";
  if (normalized.includes("chrome")) return "Chrome";
  if (normalized.includes("firefox")) return "Firefox";
  if (normalized.includes("safari")) return "Safari";
  if (normalized.includes("opera")) return "Opera";
  if (normalized.includes("chromium")) return "Chromium";
  return value?.trim() || "";
};

const formatPlatformLabel = (platform?: string, platformVersion?: string) => {
  const normalized = platform?.trim().toLowerCase() || "";
  if (!normalized) return "";
  if (normalized === "windows") {
    const majorVersion = Number(platformVersion?.split(".")[0] || Number.NaN);
    if (Number.isFinite(majorVersion)) {
      return majorVersion >= 13 ? "Windows 11" : "Windows 10";
    }
    return "Windows";
  }
  if (normalized === "macos") return "macOS";
  if (normalized === "ios") return "iOS";
  if (normalized === "android") return "Android";
  if (normalized === "linux") return "Linux";
  return platform?.trim() || "";
};

const deriveDeviceTitle = (
  platform?: string,
  mobile?: boolean,
  userAgent?: string,
) => {
  const normalized = platform?.trim().toLowerCase() || "";
  if (normalized === "windows") return "Windows PC";
  if (normalized === "macos") return "Mac device";
  if (normalized === "ios" && /ipad/i.test(userAgent || "")) return "iPad";
  if (normalized === "ios") return "iPhone";
  if (normalized === "android")
    return mobile ? "Android phone" : "Android device";
  if (normalized === "linux") return "Linux device";
  if (/iphone/i.test(userAgent || "")) return "iPhone";
  if (/ipad/i.test(userAgent || "")) return "iPad";
  if (/android/i.test(userAgent || ""))
    return /mobile/i.test(userAgent || "") ? "Android phone" : "Android device";
  if (/windows/i.test(userAgent || "")) return "Windows PC";
  if (/mac os/i.test(userAgent || "")) return "Mac device";
  if (/linux/i.test(userAgent || "")) return "Linux device";
  return "Unknown device";
};

const collectBrowserDeviceContext =
  async (): Promise<BrowserDeviceContext | null> => {
    if (typeof navigator === "undefined") return null;

    const rawUserAgent = navigator.userAgent || "";
    const uaData = navigator.userAgentData;
    let browser = "";
    let browserVersion = "";
    let platform = "";
    let platformVersion = "";
    let mobile = false;

    if (uaData) {
      platform = uaData.platform || "";
      mobile = Boolean(uaData.mobile);
      const highEntropy = await uaData
        .getHighEntropyValues?.(["platformVersion", "fullVersionList"])
        .catch(() => null);
      platformVersion =
        highEntropy && typeof highEntropy.platformVersion === "string"
          ? highEntropy.platformVersion
          : "";
      const fullVersionList = Array.isArray(highEntropy?.fullVersionList)
        ? highEntropy.fullVersionList
        : uaData.brands;
      const preferredBrowser =
        fullVersionList.find((item) =>
          /Google Chrome|Microsoft Edge|Firefox|Safari|Opera|Chromium/i.test(
            item.brand,
          ),
        ) || fullVersionList[0];
      browser = normalizeBrowserBrand(preferredBrowser?.brand);
      browserVersion = preferredBrowser?.version || "";
    }

    if (!browser) {
      const browserMatchers: Array<[RegExp, string]> = [
        [/Edg\/(\d+)/, "Edge"],
        [/Chrome\/(\d+)/, "Chrome"],
        [/Firefox\/(\d+)/, "Firefox"],
        [/Version\/(\d+).+Safari\//, "Safari"],
      ];
      for (const [pattern, label] of browserMatchers) {
        const match = rawUserAgent.match(pattern);
        if (match) {
          browser = label;
          browserVersion = match[1] || "";
          break;
        }
      }
    }

    if (!platform) {
      if (/Windows/i.test(rawUserAgent)) platform = "Windows";
      else if (/Mac OS X/i.test(rawUserAgent)) platform = "macOS";
      else if (/iPhone|iPad|iPod/i.test(rawUserAgent)) platform = "iOS";
      else if (/Android/i.test(rawUserAgent)) platform = "Android";
      else if (/Linux/i.test(rawUserAgent)) platform = "Linux";
    }

    const platformLabel = formatPlatformLabel(platform, platformVersion);
    const browserLabel = [browser, browserVersion].filter(Boolean).join(" ");
    return {
      browser: browser || undefined,
      browserVersion: browserVersion || undefined,
      platform: platform || undefined,
      platformVersion: platformVersion || undefined,
      deviceType: mobile ? "mobile" : "desktop",
      mobile,
      deviceTitle: deriveDeviceTitle(platform, mobile, rawUserAgent),
      deviceDetail:
        [browserLabel, platformLabel].filter(Boolean).join(" | ") || undefined,
    };
  };

export function AuthProvider({ children }: { children: ReactNode }) {
  const expireSession = useCallback(
    (
      reason: SessionExpiredReason = "expired",
      sessionAlert?: SessionReplacementAlert,
    ) => {
      setUser(null);
      setToken(null);
      setTokenExpiresAt(null);
      setSessionSecurity(parseSessionSecurity(null));
      window.dispatchEvent(
        new CustomEvent(SESSION_EXPIRED_EVENT, {
          detail: { reason, sessionAlert },
        }),
      );
    },
    [],
  );

  const getSessionExpiredReason = useCallback(
    (status: number, data: { error?: string; code?: string } | null) => {
      const message = (data?.error || "").toLowerCase();
      if (
        data?.code === "SESSION_REPLACED" ||
        message.includes("session revoked") ||
        message.includes("newer sign-in")
      ) {
        return "replaced" as const;
      }
      if (
        status === 401 ||
        message.includes("invalid") ||
        message.includes("expired") ||
        message.includes("token")
      ) {
        return "expired" as const;
      }
      return null;
    },
    [],
  );

  const [user, setUser] = useState<User | null>(() => {
    try {
      const s = sessionStorage.getItem(USER_STORAGE_KEY);
      if (!s) return null;
      const raw = JSON.parse(s) as Partial<User> & { email?: string };
      if (!raw?.email) return null;
      return {
        id: raw.id || raw.email,
        role: raw.role || "USER",
        email: raw.email,
        name: raw.name || toDisplayName(raw.email),
        avatar: raw.avatar || DEFAULT_AVATAR,
      };
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState<string | null>(() => {
    try {
      return sessionStorage.getItem(TOKEN_STORAGE_KEY);
    } catch {
      return null;
    }
  });
  const [tokenExpiresAt, setTokenExpiresAt] = useState<number | null>(() => {
    try {
      const raw = sessionStorage.getItem(TOKEN_EXPIRES_AT_STORAGE_KEY);
      if (raw) {
        const parsed = Number(raw);
        if (Number.isFinite(parsed)) return parsed;
      }
      const storedToken = sessionStorage.getItem(TOKEN_STORAGE_KEY);
      return storedToken ? decodeJwtExpiresAt(storedToken) : null;
    } catch {
      return null;
    }
  });
  const [sessionSecurity, setSessionSecurity] = useState<SessionSecurity>(
    () => {
      try {
        const raw = sessionStorage.getItem(SESSION_SECURITY_STORAGE_KEY);
        return parseSessionSecurity(raw ? JSON.parse(raw) : null);
      } catch {
        return parseSessionSecurity(null);
      }
    },
  );
  const [lastLoginMonitoring, setLastLoginMonitoring] =
    useState<LoginMonitoring | null>(null);

  useEffect(() => {
    try {
      if (user) sessionStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
      else sessionStorage.removeItem(USER_STORAGE_KEY);
    } catch (err) {
      // Avoid crashing the app if storage is full (e.g., large avatar data URL).
      console.warn("Cannot persist auth user to sessionStorage", err);
    }
  }, [user]);

  useEffect(() => {
    try {
      if (token) sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
      else sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch (err) {
      console.warn("Cannot persist auth token to sessionStorage", err);
    }
  }, [token]);

  useEffect(() => {
    try {
      if (tokenExpiresAt) {
        sessionStorage.setItem(
          TOKEN_EXPIRES_AT_STORAGE_KEY,
          String(tokenExpiresAt),
        );
      } else {
        sessionStorage.removeItem(TOKEN_EXPIRES_AT_STORAGE_KEY);
      }
    } catch (err) {
      console.warn("Cannot persist token expiration to sessionStorage", err);
    }
  }, [tokenExpiresAt]);

  useEffect(() => {
    try {
      sessionStorage.setItem(
        SESSION_SECURITY_STORAGE_KEY,
        JSON.stringify(sessionSecurity),
      );
    } catch (err) {
      console.warn("Cannot persist session security to sessionStorage", err);
    }
  }, [sessionSecurity]);

  useEffect(() => {
    try {
      // Remove legacy persistent auth data so closing/reopening web always requires login.
      localStorage.removeItem(USER_STORAGE_KEY);
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      localStorage.removeItem(TOKEN_EXPIRES_AT_STORAGE_KEY);
      localStorage.removeItem(SESSION_SECURITY_STORAGE_KEY);
    } catch {
      // ignore storage permission errors
    }
  }, []);

  useEffect(() => {
    if (!token) return;
    const now = Date.now();
    const expiry = tokenExpiresAt ?? decodeJwtExpiresAt(token);
    if (expiry && expiry !== tokenExpiresAt) {
      setTokenExpiresAt(expiry);
    }
    if (!expiry) return;
    if (expiry <= now) {
      expireSession();
      return;
    }

    const timeout = window.setTimeout(() => {
      expireSession();
    }, expiry - now);

    return () => window.clearTimeout(timeout);
  }, [expireSession, token, tokenExpiresAt]);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    const verifyToken = async () => {
      try {
        const headers = await buildApiHeaders({
          Authorization: `Bearer ${token}`,
        });
        const resp = await fetch(`${API_BASE}/auth/me`, {
          headers,
        });
        const data = (await resp.json().catch(() => null)) as {
          id?: string;
          email?: string;
          role?: "USER" | "ADMIN";
          fullName?: string;
          avatar?: string;
          error?: string;
          code?: string;
          sessionAlert?: SessionReplacementAlert;
          security?: unknown;
        } | null;
        if (!resp.ok) {
          const reason = getSessionExpiredReason(resp.status, data);
          if (!cancelled && reason) {
            expireSession(reason, data?.sessionAlert);
          }
        } else if (!cancelled) {
          setSessionSecurity(parseSessionSecurity(data?.security));
          setUser((prev) => {
            const email = data?.email?.trim() || prev?.email || "";
            const fullName = data?.fullName?.trim() || "";
            const nextName =
              fullName || prev?.name || (email ? toDisplayName(email) : "User");

            if (!email && !prev) return prev;

            return {
              id: data?.id || prev?.id || "",
              role: data?.role || prev?.role || "USER",
              email,
              name: nextName,
              avatar: data?.avatar || prev?.avatar || DEFAULT_AVATAR,
            };
          });
        }
      } catch {
        // ignore temporary network errors here
      }
    };

    void verifyToken();
    const interval = window.setInterval(() => {
      void verifyToken();
    }, SESSION_VERIFY_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [expireSession, getSessionExpiredReason, token]);

  const completeLogin = useCallback(
    (data: {
      token: string;
      user: { id: string; email: string; role: "USER" | "ADMIN" };
      security?: SessionSecurity | null;
    }) => {
      setToken(data.token);
      setTokenExpiresAt(decodeJwtExpiresAt(data.token));
      setSessionSecurity(
        data.security
          ? parseSessionSecurity(data.security)
          : parseSessionSecurity(null),
      );
      setUser((prev) => ({
        id: data.user.id,
        role: data.user.role,
        email: data.user.email,
        name:
          prev && prev.email.toLowerCase() === data.user.email.toLowerCase()
            ? prev.name
            : toDisplayName(data.user.email),
        avatar: prev?.avatar || DEFAULT_AVATAR,
      }));
    },
    [],
  );

  const requestLoginOtp = useCallback(
    async (
      email: string,
      password: string,
      captcha: SliderCaptchaProof,
    ): Promise<LoginResult> => {
      try {
        const deviceContext = await collectBrowserDeviceContext();
        const headers = await buildApiHeaders({
          "Content-Type": "application/json",
        });
        const resp = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            email,
            password,
            captchaToken: captcha.captchaToken,
            captchaOffset: captcha.captchaOffset,
            deviceContext,
          }),
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: unknown;
          status?: string;
          challengeId?: string;
          destination?: string;
          expiresAt?: string;
          availableAt?: string;
          retryAfterSeconds?: number;
          notice?: string;
          anomaly?: unknown;
          security?: unknown;
          token?: string;
          user?: { id: string; email: string; role: "USER" | "ADMIN" };
        } | null;
        const monitoring = parseLoginMonitoring(data?.anomaly);
        setLastLoginMonitoring(monitoring);

        if (!resp.ok) {
          throw new Error(extractApiErrorMessage(data, "Login failed"));
        }

        if (data?.token && data.user) {
          completeLogin({
            token: data.token,
            user: data.user,
            security: parseSessionSecurity(data.security),
          });
          return {
            status: "authenticated",
            notice: data.notice,
            monitoring,
            security: parseSessionSecurity(data.security),
          };
        }

        if (!data?.challengeId || !data.destination || !data.expiresAt) {
          throw new Error("Login response is missing OTP challenge data");
        }

        return {
          status: "otp_required",
          challengeId: data.challengeId,
          destination: data.destination,
          expiresAt: data.expiresAt,
          availableAt: data.availableAt,
          retryAfterSeconds: Number(data.retryAfterSeconds || 60),
          notice: data.notice,
          monitoring,
        };
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [completeLogin],
  );

  const verifyLoginOtp = useCallback(
    async (
      challengeId: string,
      otp: string,
      captcha: SliderCaptchaProof,
    ): Promise<AuthCompletionResult> => {
      try {
        const deviceContext = await collectBrowserDeviceContext();
        const headers = await buildApiHeaders({
          "Content-Type": "application/json",
        });
        const resp = await fetch(`${API_BASE}/auth/login/verify`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            challengeId,
            otp,
            captchaToken: captcha.captchaToken,
            captchaOffset: captcha.captchaOffset,
            deviceContext,
          }),
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: unknown;
          notice?: string;
          security?: unknown;
          token?: string;
          user?: { id: string; email: string; role: "USER" | "ADMIN" };
        } | null;

        if (!resp.ok || !data?.token || !data.user) {
          throw new Error(
            extractApiErrorMessage(data, "OTP verification failed"),
          );
        }

        completeLogin({
          token: data.token,
          user: data.user,
          security: parseSessionSecurity(data.security),
        });
        return {
          notice: data.notice,
          security: parseSessionSecurity(data.security),
        };
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [completeLogin],
  );

  const requestPasswordResetOtp = useCallback(
    async (email: string, captcha: SliderCaptchaProof) => {
      try {
        const headers = await buildApiHeaders({
          "Content-Type": "application/json",
        });
        const resp = await fetch(`${API_BASE}/auth/password/otp/send`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            email,
            captchaToken: captcha.captchaToken,
            captchaOffset: captcha.captchaOffset,
          }),
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: unknown;
          challengeId?: string;
          destination?: string;
          expiresAt?: string;
          retryAfterSeconds?: number;
        } | null;

        if (
          !resp.ok ||
          !data?.challengeId ||
          !data.destination ||
          !data.expiresAt
        ) {
          throw new Error(
            extractApiErrorMessage(data, "Failed to send reset OTP"),
          );
        }

        return {
          challengeId: data.challengeId,
          destination: data.destination,
          expiresAt: data.expiresAt,
          retryAfterSeconds: Number(data.retryAfterSeconds || 60),
        };
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [],
  );

  const resetPasswordWithOtp = useCallback(
    async (payload: {
      email: string;
      challengeId: string;
      otp: string;
      newPassword: string;
    }) => {
      try {
        const headers = await buildApiHeaders({
          "Content-Type": "application/json",
        });
        const resp = await fetch(`${API_BASE}/auth/password/reset`, {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
        });
        if (!resp.ok) {
          const data = (await resp.json().catch(() => null)) as {
            error?: unknown;
          } | null;
          throw new Error(
            extractApiErrorMessage(data, "Failed to reset password"),
          );
        }
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [],
  );

  const respondToSessionAlert = useCallback(
    async (
      alertToken: string,
      action: "confirm" | "secure_account",
    ): Promise<SessionAlertResponse> => {
      try {
        const headers = await buildApiHeaders({
          "Content-Type": "application/json",
        });
        const resp = await fetch(`${API_BASE}/auth/session-alert/respond`, {
          method: "POST",
          headers,
          body: JSON.stringify({ alertToken, action }),
        });
        const data = (await resp.json().catch(() => null)) as
          | (SessionAlertResponse & { error?: unknown })
          | { error?: unknown }
          | null;

        if (
          !resp.ok ||
          !data ||
          typeof data !== "object" ||
          !("status" in data) ||
          typeof data.status !== "string"
        ) {
          throw new Error(
            extractApiErrorMessage(data, "Failed to process session alert"),
          );
        }

        return data;
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [],
  );

  const requestRegisterOtp = useCallback(
    async (payload: {
      fullName: string;
      userName: string;
      email: string;
      phone: string;
      address: string;
      dob: string;
      password: string;
      captcha: SliderCaptchaProof;
      faceEnrollment: FaceIdEnrollmentProof;
    }) => {
      try {
        const headers = await buildApiHeaders({
          "Content-Type": "application/json",
        });
        const resp = await fetch(`${API_BASE}/auth/register`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            email: payload.email,
            password: payload.password,
            role: "USER",
            fullName: payload.fullName.trim() || undefined,
            userName: payload.userName.trim() || undefined,
            phone: payload.phone.trim() || undefined,
            address: payload.address.trim() || undefined,
            dob: payload.dob.trim() || undefined,
            captchaToken: payload.captcha.captchaToken,
            captchaOffset: payload.captcha.captchaOffset,
            faceIdEnrollment: payload.faceEnrollment,
          }),
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: unknown;
          challengeId?: string;
          destination?: string;
          expiresAt?: string;
          retryAfterSeconds?: number;
        } | null;

        if (
          !resp.ok ||
          !data?.challengeId ||
          !data.destination ||
          !data.expiresAt
        ) {
          throw new Error(extractApiErrorMessage(data, "Sign up failed"));
        }

        return {
          challengeId: data.challengeId,
          destination: data.destination,
          expiresAt: data.expiresAt,
          retryAfterSeconds: Number(data.retryAfterSeconds || 60),
        };
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [],
  );

  const verifyRegisterOtp = useCallback(
    async (challengeId: string, otp: string): Promise<AuthCompletionResult> => {
      try {
        const headers = await buildApiHeaders({
          "Content-Type": "application/json",
        });
        const resp = await fetch(`${API_BASE}/auth/register/verify`, {
          method: "POST",
          headers,
          body: JSON.stringify({ challengeId, otp }),
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: unknown;
          notice?: string;
          token?: string;
          user?: { id: string; email: string; role: "USER" | "ADMIN" };
        } | null;

        if (!resp.ok || !data?.token || !data.user) {
          throw new Error(
            extractApiErrorMessage(data, "OTP verification failed"),
          );
        }

        completeLogin({
          token: data.token,
          user: data.user,
        });
        return { notice: data.notice };
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [completeLogin],
  );

  const updateUser = useCallback((patch: Partial<User>) => {
    setUser((prev) => (prev ? { ...prev, ...patch } : prev));
  }, []);

  const clearLoginMonitoring = useCallback(() => {
    setLastLoginMonitoring(null);
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    setToken(null);
    setTokenExpiresAt(null);
    setSessionSecurity(parseSessionSecurity(null));
    setLastLoginMonitoring(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        requestLoginOtp,
        verifyLoginOtp,
        requestRegisterOtp,
        verifyRegisterOtp,
        requestPasswordResetOtp,
        resetPasswordWithOtp,
        respondToSessionAlert,
        sessionSecurity,
        lastLoginMonitoring,
        clearLoginMonitoring,
        updateUser,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
