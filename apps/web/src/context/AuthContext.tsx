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
const DEFAULT_AVATAR = "https://i.pravatar.cc/80?img=12";
const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://localhost:4000";

const AuthContext = createContext<{
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  signUp: (name: string, email: string, password: string) => Promise<void>;
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

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    try {
      const s = localStorage.getItem(USER_STORAGE_KEY);
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
      return localStorage.getItem(TOKEN_STORAGE_KEY);
    } catch {
      return null;
    }
  });

  useEffect(() => {
    try {
      if (user) localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
      else localStorage.removeItem(USER_STORAGE_KEY);
    } catch (err) {
      // Avoid crashing the app if storage is full (e.g., large avatar data URL).
      console.warn("Cannot persist auth user to localStorage", err);
    }
  }, [user]);

  useEffect(() => {
    try {
      if (token) localStorage.setItem(TOKEN_STORAGE_KEY, token);
      else localStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch (err) {
      console.warn("Cannot persist auth token to localStorage", err);
    }
  }, [token]);

  const login = useCallback(async (email: string, password: string) => {
    try {
      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        token?: string;
        user?: { id: string; email: string; role: "USER" | "ADMIN" };
      } | null;

      if (!resp.ok || !data?.token || !data.user) {
        throw new Error(data?.error || "Login failed");
      }

      setToken(data.token);
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
    async (name: string, email: string, password: string) => {
      try {
        const resp = await fetch(`${API_BASE}/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email,
            password,
            role: "USER",
            fullName: name.trim() || undefined,
          }),
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: string;
          token?: string;
          user?: { id: string; email: string; role: "USER" | "ADMIN" };
        } | null;

        if (!resp.ok || !data?.token || !data.user) {
          throw new Error(data?.error || "Sign up failed");
        }

        setToken(data.token);
        setUser({
          id: data.user.id,
          role: data.user.role,
          email: data.user.email,
          name: name.trim() || toDisplayName(data.user.email),
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
