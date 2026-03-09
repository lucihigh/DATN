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

const USER_STORAGE_KEY = "moneyfarm_user";
const TOKEN_STORAGE_KEY = "moneyfarm_token";
const TOKEN_EXPIRES_AT_STORAGE_KEY = "moneyfarm_token_expires_at";
const DEFAULT_AVATAR = "https://i.pravatar.cc/80?img=12";
const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://localhost:4000";
const SESSION_TIMEOUT_MS = 5 * 60 * 1000;

const AuthContext = createContext<{
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  signUp: (payload: {
    fullName: string;
    userName: string;
    email: string;
    phone: string;
    address: string;
    dob: string;
    password: string;
  }) => Promise<void>;
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

export function AuthProvider({ children }: { children: ReactNode }) {
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
      if (!raw) return null;
      const parsed = Number(raw);
      return Number.isFinite(parsed) ? parsed : null;
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
    const expiry = tokenExpiresAt ?? now + SESSION_TIMEOUT_MS;
    if (!tokenExpiresAt) {
      setTokenExpiresAt(expiry);
    }
    if (expiry <= now) {
      setToken(null);
      setUser(null);
      setTokenExpiresAt(null);
      return;
    }

    const timeout = window.setTimeout(() => {
      setToken(null);
      setUser(null);
      setTokenExpiresAt(null);
    }, expiry - now);

    return () => window.clearTimeout(timeout);
  }, [token, tokenExpiresAt]);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    const verifyToken = async () => {
      try {
        const resp = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!resp.ok) {
          const data = (await resp.json().catch(() => null)) as
            | { error?: string }
            | null;
          const msg = (data?.error || "").toLowerCase();
          if (
            resp.status === 401 ||
            msg.includes("invalid") ||
            msg.includes("expired") ||
            msg.includes("token")
          ) {
            if (!cancelled) {
              setToken(null);
              setUser(null);
            }
          }
        }
      } catch {
        // ignore temporary network errors here
      }
    };

    void verifyToken();
    return () => {
      cancelled = true;
    };
  }, [token]);

  const login = useCallback(async (email: string, password: string) => {
    try {
      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: unknown;
        token?: string;
        user?: { id: string; email: string; role: "USER" | "ADMIN" };
      } | null;

      if (!resp.ok || !data?.token || !data.user) {
        throw new Error(extractApiErrorMessage(data, "Login failed"));
      }

      setToken(data.token);
      setTokenExpiresAt(Date.now() + SESSION_TIMEOUT_MS);
      setUser((prev) => ({
        id: data.user!.id,
        role: data.user!.role,
        email: data.user!.email,
        name:
          prev && prev.email.toLowerCase() === data.user!.email.toLowerCase()
            ? prev.name
            : toDisplayName(data.user!.email),
        avatar: prev?.avatar || DEFAULT_AVATAR,
      }));
    } catch (err) {
      throw new Error(parseApiError(err));
    }
  }, []);

  const signUp = useCallback(
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
          token?: string;
          user?: { id: string; email: string; role: "USER" | "ADMIN" };
        } | null;

        if (!resp.ok || !data?.token || !data.user) {
          throw new Error(extractApiErrorMessage(data, "Sign up failed"));
        }

        setToken(data.token);
        setTokenExpiresAt(Date.now() + SESSION_TIMEOUT_MS);
        setUser({
          id: data.user.id,
          role: data.user.role,
          email: data.user.email,
          name: payload.fullName.trim() || toDisplayName(data.user.email),
          avatar: DEFAULT_AVATAR,
        });
      } catch (err) {
        throw new Error(parseApiError(err));
      }
    },
    [],
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
      value={{ user, token, login, signUp, updateUser, logout }}
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
