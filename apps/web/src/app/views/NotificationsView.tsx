import { useState } from "react";

import type { ActivityNotification } from "../notifications";

type NotificationsViewProps = {
  notifications: Array<ActivityNotification & { read: boolean }>;
  busy: boolean;
  error: string;
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
};

export default function NotificationsView({
  notifications,
  busy,
  error,
  onMarkRead,
  onMarkAllRead,
}: NotificationsViewProps) {
  const [filter, setFilter] = useState<"all" | "transactions" | "security">(
    "all",
  );

  const filtered = notifications.filter(
    (notification) => filter === "all" || notification.type === filter,
  );
  const unreadCount = notifications.filter(
    (notification) => !notification.read,
  ).length;

  return (
    <section className="card notifications-card">
      <div className="card-head">
        <div>
          <h3>Activity Notifications</h3>
          <p className="muted">
            Balance movements and security events for this account.
          </p>
        </div>
        <div className="notifications-head-actions">
          <select
            className="pill"
            value={filter}
            onChange={(event) => setFilter(event.target.value as typeof filter)}
          >
            <option value="all">All</option>
            <option value="transactions">Balance</option>
            <option value="security">Security</option>
          </select>
          <button
            type="button"
            className="pill tiny"
            onClick={onMarkAllRead}
            disabled={unreadCount === 0}
          >
            Mark all read
          </button>
        </div>
      </div>
      <div className="notifications-list">
        {busy && notifications.length === 0 && (
          <p className="muted">Loading activity...</p>
        )}
        {!busy && error && notifications.length === 0 && (
          <p className="muted">{error}</p>
        )}
        {filtered.map((notification) => (
          <div
            key={notification.id}
            className={`notification-row ${!notification.read ? "unread" : ""}`}
          >
            <div className="notification-main">
              <div className="notification-topline">
                <div className={`notif-pill notif-${notification.type}`}>
                  {notification.type === "transactions"
                    ? "Balance"
                    : "Security"}
                </div>
                <span className="notification-time">
                  {notification.timeLabel}
                </span>
              </div>
              <strong className="notification-title">
                {notification.title}
              </strong>
              <div className="notification-message">{notification.message}</div>
              {notification.meta && (
                <div className="notification-meta" title={notification.meta}>
                  {notification.meta}
                </div>
              )}
            </div>
            {notification.amountText && (
              <div
                className={`notification-amount ${notification.amountTone ? `notification-amount-${notification.amountTone}` : ""}`}
              >
                {notification.amountText}
              </div>
            )}
            <button
              type="button"
              className="pill tiny"
              onClick={() => onMarkRead(notification.id)}
              disabled={notification.read}
            >
              {notification.read ? "Read" : "Mark read"}
            </button>
          </div>
        ))}
        {!busy && filtered.length === 0 && (
          <p className="muted">No notifications for this filter.</p>
        )}
      </div>
    </section>
  );
}
