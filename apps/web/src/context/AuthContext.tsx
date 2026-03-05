import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";

export type User = { name: string; email: string; avatar: string };

const STORAGE_KEY = "moneyfarm_user";

const AuthContext = createContext<{
  user: User | null;
  login: (email: string, password: string) => boolean;
  signUp: (name: string, email: string, password: string) => boolean;
  updateUser: (patch: Partial<User>) => void;
  logout: () => void;
} | null>(null);

const defaultUser: User = {
  name: "John Doe",
  email: "johndoe.banking@gmail.com",
  avatar: "https://i.pravatar.cc/80?img=12",
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    try {
      const s = localStorage.getItem(STORAGE_KEY);
      return s ? (JSON.parse(s) as User) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    try {
      if (user) localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
      else localStorage.removeItem(STORAGE_KEY);
    } catch (err) {
      // Avoid crashing the app if storage is full (e.g., large avatar data URL).
      console.warn("Cannot persist auth user to localStorage", err);
    }
  }, [user]);

  const login = useCallback((email: string, password: string) => {
    void password; // keep signature for future auth backend integration
    setUser({ ...defaultUser, email });
    return true;
  }, []);

  const signUp = useCallback(
    (name: string, email: string, password: string) => {
      void password; // quiet lint; password would be sent to backend when wired up
      setUser({ name, email, avatar: defaultUser.avatar });
      return true;
    },
    [],
  );

  const updateUser = useCallback((patch: Partial<User>) => {
    setUser((prev) => (prev ? { ...prev, ...patch } : prev));
  }, []);

  const logout = useCallback(() => setUser(null), []);

  return (
    <AuthContext.Provider value={{ user, login, signUp, updateUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
