import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { AuthProvider } from "./context/AuthContext";
import { useAuth } from "./context/AuthContext";
import { ThemeProvider } from "./context/ThemeContext";
import { ToastProvider, ToastContainer } from "./context/ToastContext";
import App from "./App";
import AdminApp from "./admin/AdminApp";
import "./index.css";

function RoleRouter() {
  const { user } = useAuth();

  if (user?.role === "ADMIN") return <AdminApp />;
  return <App />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <RoleRouter />
          <ToastContainer />
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  </StrictMode>,
);
