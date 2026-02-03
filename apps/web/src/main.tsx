import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import AdminApp from "./admin/AdminApp";

const isAdminRoute = window.location.pathname.startsWith("/admin");

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>{isAdminRoute ? <AdminApp /> : <App />}</React.StrictMode>
);
