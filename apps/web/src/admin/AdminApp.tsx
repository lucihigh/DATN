import { useEffect, useMemo, useState } from "react";

import { useToast } from "../context/ToastContext";
import { useAuth } from "../context/AuthContext";
import "../index.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:4000";

type AdminUser = {
  id: string;
  email: string;
  role?: string;
  status?: string;
  lastLoginAt?: string;
  createdAt?: string;
};

type Alert = {
  id: string;
  email: string;
  ipAddress: string;
  userAgent: string;
  anomaly: number;
  success: boolean;
  createdAt: string;
  severity?: string;
  reasons?: string[];
};

type LoginEvent = {
  id: string;
  email: string;
  success: boolean;
  ipAddress: string;
  userAgent: string;
  anomaly: number;
  createdAt: string;
};

type AuditLog = {
  id: string;
  actor: string;
  action: string;
  details: unknown;
  ipAddress?: string;
  createdAt: string;
};

type Profile = {
  name: string;
  username: string;
  email: string;
  password: string;
  dob: string;
  presentAddress: string;
  permanentAddress: string;
  postalCode: string;
  avatar?: string;
};

const loadProfile = (): Profile => {
  try {
    const raw = localStorage.getItem("mf_admin_profile");
    if (raw) return JSON.parse(raw) as Profile;
  } catch {
    // ignore
  }
  return {
    name: "John Doe",
    username: "john.doe",
    email: "john.doe@mail.com",
    password: "**********",
    dob: "1990-01-25",
    presentAddress: "San Jose, California, USA",
    permanentAddress: "San Jose, California, USA",
    postalCode: "45962",
    avatar: "https://i.pravatar.cc/220?img=12",
  };
};

const saveProfile = (profile: Profile) => {
  try {
    localStorage.setItem("mf_admin_profile", JSON.stringify(profile));
  } catch {
    // ignore
  }
};

const ProfilePanel = ({
  profile,
  onSave,
}: {
  profile: Profile;
  onSave: (p: Profile) => void;
}) => {
  const { toast } = useToast();
  const [form, setForm] = useState<Profile>(profile);

  const update =
    (field: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
      setForm((f) => ({ ...f, [field]: e.target.value }));

  const handleSave = () => {
    onSave(form);
    toast("Profile saved", "success");
  };

  return (
    <div className="mf-profile-page">
      <div className="mf-profile-hero">
        <div className="mf-profile-avatar">
          <img
            src={form.avatar || "https://i.pravatar.cc/220?img=12"}
            alt="avatar"
          />
          <span className="mf-profile-camera">
            <i className="fas fa-camera" />
          </span>
        </div>
      </div>
      <div className="mf-profile-form">
        <label>
          Name
          <input value={form.name} onChange={update("name")} />
        </label>
        <label>
          User Name
          <input value={form.username} onChange={update("username")} />
        </label>
        <label>
          Email
          <input value={form.email} onChange={update("email")} />
        </label>
        <label>
          Password
          <input
            type="password"
            value={form.password}
            onChange={update("password")}
          />
        </label>
        <label>
          Date of Birth
          <input type="date" value={form.dob} onChange={update("dob")} />
        </label>
        <label>
          Present Address
          <input
            value={form.presentAddress}
            onChange={update("presentAddress")}
          />
        </label>
        <label>
          Permanent Address
          <input
            value={form.permanentAddress}
            onChange={update("permanentAddress")}
          />
        </label>
        <label>
          Postal Code
          <input value={form.postalCode} onChange={update("postalCode")} />
        </label>
      </div>
      <div className="mf-profile-actions">
        <button
          className="mf-btn mf-btn-save"
          type="button"
          onClick={handleSave}
        >
          Save Changes
        </button>
      </div>
    </div>
  );
};

const apiFetch = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return (await response.json()) as T;
};

const formatDate = (value?: string | Date) => {
  if (!value) return "—";
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
};

function AdminApp() {
  const { toast } = useToast();
  const { user, logout } = useAuth();

  const [activePage, setActivePage] = useState<
    "dashboard" | "user-management" | "audit-log" | "profile"
  >("dashboard");
  const [menuOpen, setMenuOpen] = useState(false);
  const [profile, setProfile] = useState<Profile>(() => loadProfile());

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loginEvents, setLoginEvents] = useState<LoginEvent[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);

  const lockedUsers = useMemo(
    () => users.filter((u) => u.status === "DISABLED").length,
    [users],
  );
  const activeUsers = useMemo(
    () => users.filter((u) => u.status === "ACTIVE").length,
    [users],
  );

  const refreshAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const [u, a, l, logs] = await Promise.all([
        apiFetch<AdminUser[]>("/admin/users"),
        apiFetch<Alert[]>("/admin/alerts"),
        apiFetch<LoginEvent[]>("/admin/login-events?limit=80"),
        apiFetch<AuditLog[]>("/admin/audit-logs?limit=100"),
      ]);
      setUsers(u);
      setAlerts(a);
      setLoginEvents(l);
      setAuditLogs(logs);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to load admin data";
      setError(message);
      toast(message, "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refreshAll();
  }, []);

  const titleMap: Record<typeof activePage, string> = {
    dashboard: "Dashboard",
    "user-management": "User Management",
    "audit-log": "Audit Log",
    profile: "Profile",
  };

  const totalUsers = users.length;
  const suspiciousAlerts = alerts.length;
  const lockedCount = lockedUsers;
  const activeSessions = loginEvents.length;
  const displayName = profile?.name || user?.name || "Admin";
  const displayEmail = profile?.email || user?.email || "admin@moneyfarm.com";
  const displayAvatar =
    profile?.avatar || user?.avatar || "https://i.pravatar.cc/80?img=13";

  const handleLogout = () => {
    logout();
    window.location.href = "/";
  };

  return (
    <div className="mf-shell">
      <aside className="mf-sidebar">
        <div className="mf-logo">E-Wallet Admin</div>
        <ul className="mf-menu">
          <li>
            <button
              className={activePage === "dashboard" ? "active" : ""}
              onClick={() => setActivePage("dashboard")}
            >
              <i className="fas fa-tachometer-alt" />
              Dashboard
            </button>
          </li>
          <li>
            <button
              className={activePage === "user-management" ? "active" : ""}
              onClick={() => setActivePage("user-management")}
            >
              <i className="fas fa-users" />
              User Management
            </button>
          </li>
          <li>
            <button
              className={activePage === "audit-log" ? "active" : ""}
              onClick={() => setActivePage("audit-log")}
            >
              <i className="fas fa-file-alt" />
              Audit Log
            </button>
          </li>
        </ul>
      </aside>

      <main className="mf-main">
        <header className="mf-header">
          <h1>{titleMap[activePage]}</h1>
          <div className="mf-header-right">
            <div className="mf-search">
              <input type="text" placeholder="Search here..." />
              <i className="fas fa-search" />
            </div>
            <div className="mf-noti">
              <i className="fas fa-bell" />
              <span className="mf-badge">{Math.min(99, suspiciousAlerts)}</span>
            </div>
            <div
              className="mf-profile"
              onClick={() => setMenuOpen((v) => !v)}
              role="button"
              aria-haspopup="true"
              aria-expanded={menuOpen}
            >
              <img src={displayAvatar} alt="admin" />
              <div>
                <h3>{displayName}</h3>
                <p>{displayEmail}</p>
              </div>
              {menuOpen && (
                <div className="mf-profile-menu">
                  <button
                    type="button"
                    className="mf-profile-menu-item"
                    onClick={() => {
                      setActivePage("profile");
                      setMenuOpen(false);
                    }}
                  >
                    Profile
                  </button>
                  <button
                    type="button"
                    className="mf-profile-menu-item danger"
                    onClick={handleLogout}
                  >
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {loading && (
          <div className="mf-banner muted">Loading latest admin data…</div>
        )}
        {error && <div className="mf-banner danger">{error}</div>}

        {activePage === "dashboard" && (
          <>
            <div className="mf-stats">
              <div className="mf-stat-card">
                <i className="fas fa-users" />
                <h3>{totalUsers}</h3>
                <p>Total Users</p>
              </div>
              <div className="mf-stat-card">
                <i className="fas fa-user-clock" />
                <h3>{activeSessions}</h3>
                <p>Active Sessions</p>
              </div>
              <div className="mf-stat-card">
                <i className="fas fa-exclamation-triangle danger" />
                <h3>{suspiciousAlerts}</h3>
                <p>Suspicious Alerts</p>
              </div>
              <div className="mf-stat-card">
                <i className="fas fa-lock danger" />
                <h3>{lockedCount}</h3>
                <p>Locked Accounts</p>
              </div>
            </div>

            <div className="mf-card">
              <h2>Recent Suspicious Alerts</h2>
              <table>
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Event</th>
                    <th>Time</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 10).map((a) => (
                    <tr key={a.id}>
                      <td>{a.email}</td>
                      <td>
                        {(a.reasons ?? []).join(", ") ||
                          (a.success ? "Anomaly" : "Failed login")}
                      </td>
                      <td>{formatDate(a.createdAt)}</td>
                      <td
                        style={{
                          color:
                            a.severity === "high"
                              ? "var(--mf-red)"
                              : a.severity === "medium"
                                ? "#f59e0b"
                                : "var(--mf-green)",
                          fontWeight: 700,
                        }}
                      >
                        {a.severity ?? (a.success ? "Low" : "High")}
                      </td>
                    </tr>
                  ))}
                  {alerts.length === 0 && (
                    <tr>
                      <td colSpan={4} className="muted">
                        No alerts
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activePage === "user-management" && (
          <>
            <div className="mf-stats">
              <div className="mf-stat-card">
                <i className="fas fa-users" />
                <h3>{totalUsers}</h3>
                <p>Total Users</p>
              </div>
              <div className="mf-stat-card">
                <i
                  className="fas fa-user-check"
                  style={{ color: "var(--mf-green)" }}
                />
                <h3>{activeUsers}</h3>
                <p>Active Users</p>
              </div>
              <div className="mf-stat-card">
                <i className="fas fa-lock" style={{ color: "var(--mf-red)" }} />
                <h3>{lockedCount}</h3>
                <p>Locked Accounts</p>
              </div>
              <div className="mf-stat-card">
                <i className="fas fa-user-plus" />
                <h3>—</h3>
                <p>New Today</p>
              </div>
            </div>

            <div className="mf-card">
              <div className="mf-filter">
                <input type="text" placeholder="Search by email..." />
                <select>
                  <option>All Status</option>
                  <option>Active</option>
                  <option>Disabled</option>
                </select>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.slice(0, 12).map((u) => (
                    <tr key={u.id}>
                      <td>{u.email}</td>
                      <td>{u.role ?? "USER"}</td>
                      <td
                        className={
                          u.status === "DISABLED"
                            ? "mf-status-locked"
                            : "mf-status-active"
                        }
                      >
                        {u.status ?? "UNKNOWN"}
                      </td>
                      <td>{formatDate(u.lastLoginAt)}</td>
                      <td>
                        <button
                          className={
                            u.status === "DISABLED"
                              ? "mf-btn mf-btn-unlock"
                              : "mf-btn mf-btn-lock"
                          }
                        >
                          {u.status === "DISABLED" ? "Unlock" : "Lock"}
                        </button>
                      </td>
                    </tr>
                  ))}
                  {users.length === 0 && (
                    <tr>
                      <td colSpan={5} className="muted">
                        No users
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activePage === "audit-log" && (
          <>
            <div className="mf-stats">
              <div className="mf-stat-card">
                <i className="fas fa-file-alt" />
                <h3>{auditLogs.length}</h3>
                <p>Total Events</p>
              </div>
              <div className="mf-stat-card">
                <i
                  className="fas fa-sign-in-alt"
                  style={{ color: "var(--mf-green)" }}
                />
                <h3>{loginEvents.filter((e) => e.success).length}</h3>
                <p>Login Success</p>
              </div>
              <div className="mf-stat-card">
                <i
                  className="fas fa-exclamation-triangle"
                  style={{ color: "var(--mf-red)" }}
                />
                <h3>{loginEvents.filter((e) => !e.success).length}</h3>
                <p>Login Failed</p>
              </div>
              <div className="mf-stat-card">
                <i className="fas fa-shield-alt" />
                <h3>{alerts.length}</h3>
                <p>Security Alerts</p>
              </div>
            </div>

            <div className="mf-card">
              <div className="mf-filter">
                <input type="date" />
                <input type="date" />
                <select>
                  <option>All Events</option>
                  <option>Login Success</option>
                  <option>Login Failed</option>
                  <option>Account Lock</option>
                  <option>Admin Action</option>
                </select>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>User</th>
                    <th>Event</th>
                    <th>IP Address</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.slice(0, 20).map((log) => (
                    <tr key={log.id}>
                      <td>{formatDate(log.createdAt)}</td>
                      <td>{log.actor}</td>
                      <td>{log.action}</td>
                      <td>{log.ipAddress ?? "—"}</td>
                      <td>
                        {typeof log.details === "string"
                          ? log.details
                          : JSON.stringify(log.details)}
                      </td>
                    </tr>
                  ))}
                  {auditLogs.length === 0 && (
                    <tr>
                      <td colSpan={5} className="muted">
                        No audit events
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activePage === "profile" && (
          <ProfilePanel
            profile={profile}
            onSave={(p) => {
              saveProfile(p);
              setProfile(p);
            }}
          />
        )}
      </main>
    </div>
  );
}

export default AdminApp;
