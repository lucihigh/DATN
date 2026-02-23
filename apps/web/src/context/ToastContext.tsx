import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

type Toast = { id: number; message: string; type?: "success" | "error" | "info" };

const ToastContext = createContext<{
  toasts: Toast[];
  toast: (message: string, type?: Toast["type"]) => void;
  removeToast: (id: number) => void;
} | null>(null);

let nextId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = useCallback((message: string, type: Toast["type"] = "success") => {
    const id = ++nextId;
    setToasts((t) => [...t, { id, message, type }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3000);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts((t) => t.filter((x) => x.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, toast, removeToast }}>
      {children}
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}

export function ToastContainer() {
  const { toasts, removeToast } = useToast();
  return (
    <div className="toast-container" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast toast-${t.type ?? "success"}`} role="alert">
          <span>{t.message}</span>
          <button type="button" className="toast-close" onClick={() => removeToast(t.id)} aria-label="Close">×</button>
        </div>
      ))}
    </div>
  );
}
