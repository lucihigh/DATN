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
  retryAfterSeconds: number;
  notice?: string;
};

export type LoginAuthenticatedResult = {
  status: "authenticated";
  notice?: string;
};

export type LoginResult = LoginOtpRequiredResult | LoginAuthenticatedResult;

export type AuthCompletionResult = {
  notice?: string;
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

const USER_STORAGE_KEY = "fpipay_user";
const TOKEN_STORAGE_KEY = "fpipay_token";
const TOKEN_EXPIRES_AT_STORAGE_KEY = "fpipay_token_expires_at";
const DEFAULT_AVATAR = "https://i.pravatar.cc/80?img=12";
const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://localhost:4000";
const SESSION_EXPIRED_EVENT = "auth:session-expired";
const SESSION_VERIFY_INTERVAL_MS = 10000;

type SessionExpiredReason = "expired" | "replaced";

const AuthContext = createContext<{
  user: User | null;
  token: string | null;
  requestLoginOtp: (email: string, password: string) => Promise<LoginResult>;
  verifyLoginOtp: (
    challengeId: string,
    otp: string,
  ) => Promise<AuthCompletionResult>;
  requestRegisterOtp: (payload: {
    fullName: string;
    userName: string;
    email: string;
    phone: string;
    address: string;
    dob: string;
    password: string;
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
  requestPasswordResetOtp: (email: string) => Promise<{
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

export function AuthProvider({ children }: { children: ReactNode }) {
  const expireSession = useCallback(
    (
      reason: SessionExpiredReason = "expired",
      sessionAlert?: SessionReplacementAlert,
    ) => {
      setUser(null);
      setToken(null);
      setTokenExpiresAt(null);
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
      // Remove legacy persistent auth data so closing/reopening web always requires login.
      localStorage.removeItem(USER_STORAGE_KEY);
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      localStorage.removeItem(TOKEN_EXPIRES_AT_STORAGE_KEY);
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
        const resp = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!resp.ok) {
          const data = (await resp.json().catch(() => null)) as {
            error?: string;
            code?: string;
            sessionAlert?: SessionReplacementAlert;
          } | null;
          const reason = getSessionExpiredReason(resp.status, data);
          if (!cancelled && reason) {
            expireSession(reason, data?.sessionAlert);
          }
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
    }) => {
      setToken(data.token);
      setTokenExpiresAt(decodeJwtExpiresAt(data.token));
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
    async (email: string, password: string): Promise<LoginResult> => {
      try {
        const resp = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: unknown;
          status?: string;
          challengeId?: string;
          destination?: string;
          expiresAt?: string;
          retryAfterSeconds?: number;
          notice?: string;
          token?: string;
          user?: { id: string; email: string; role: "USER" | "ADMIN" };
        } | null;

        if (!resp.ok) {
          throw new Error(extractApiErrorMessage(data, "Login failed"));
        }

        if (data?.token && data.user) {
          completeLogin({
            token: data.token,
            user: data.user,
          });
          return {
            status: "authenticated",
            notice: data.notice,
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
          retryAfterSeconds: Number(data.retryAfterSeconds || 60),
          notice: data.notice,
        };
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [completeLogin],
  );

  const verifyLoginOtp = useCallback(
    async (challengeId: string, otp: string): Promise<AuthCompletionResult> => {
      try {
        const resp = await fetch(`${API_BASE}/auth/login/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
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

  const requestPasswordResetOtp = useCallback(async (email: string) => {
    try {
      const resp = await fetch(`${API_BASE}/auth/password/otp/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
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
  }, []);

  const resetPasswordWithOtp = useCallback(
    async (payload: {
      email: string;
      challengeId: string;
      otp: string;
      newPassword: string;
    }) => {
      try {
        const resp = await fetch(`${API_BASE}/auth/password/reset`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
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
        const resp = await fetch(`${API_BASE}/auth/session-alert/respond`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
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
    }) => {
      try {
        const resp = await fetch(`${API_BASE}/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: payload.email,
            password: payload.password,
            role: "USER",
            fullName: payload.fullName.trim() || undefined,
            userName: payload.userName.trim() || undefined,
            phone: payload.phone.trim() || undefined,
            address: payload.address.trim() || undefined,
            dob: payload.dob.trim() || undefined,
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
        const resp = await fetch(`${API_BASE}/auth/register/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
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

  const logout = useCallback(() => {
    setUser(null);
    setToken(null);
    setTokenExpiresAt(null);
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
