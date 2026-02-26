import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { AuthProvider } from "./context/AuthContext";
import { ThemeProvider } from "./context/ThemeContext";
import { ToastProvider, ToastContainer } from "./context/ToastContext";
import App from "./App";
import AdminApp from "./admin/AdminApp";
import "./index.css";

const isAdminRoute = window.location.pathname.startsWith("/admin");

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          {isAdminRoute ? <AdminApp /> : <App />}
          <ToastContainer />
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  </StrictMode>,
);
