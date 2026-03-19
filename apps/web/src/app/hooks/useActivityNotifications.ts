import { useCallback, useEffect, useState } from "react";

import {
  formatSecurityNotification,
  NOTIFICATION_READ_STORAGE_PREFIX,
  type ActivityNotification,
  type SecurityOverviewResponse,
} from "../notifications";

type UseActivityNotificationsOptions = {
  apiBase: string;
  token?: string | null;
  userId?: string;
};

export function useActivityNotifications({
  apiBase,
  token,
  userId,
}: UseActivityNotificationsOptions) {
  const [activityNotifications, setActivityNotifications] = useState<
    ActivityNotification[]
  >([]);
  const [notificationsBusy, setNotificationsBusy] = useState(false);
  const [notificationsError, setNotificationsError] = useState("");
  const [readNotificationIds, setReadNotificationIds] = useState<string[]>([]);

  const formatNotificationTime = useCallback((value: string) => {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return "Just now";
    const diffMs = Date.now() - parsed.getTime();
    const diffMinutes = Math.max(0, Math.round(diffMs / 60000));

    if (diffMinutes < 1) return "Just now";
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    if (diffMinutes < 24 * 60) {
      const diffHours = Math.round(diffMinutes / 60);
      return `${diffHours}h ago`;
    }

    return parsed.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  }, []);

  const formatCurrencyAmount = useCallback((amount: number) => {
    return `$${Math.abs(amount).toLocaleString("en-US", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}`;
  }, []);

  const notificationReadStorageKey = userId
    ? `${NOTIFICATION_READ_STORAGE_PREFIX}_${userId}`
    : "";

  useEffect(() => {
    if (!notificationReadStorageKey) {
      setReadNotificationIds([]);
      return;
    }
    try {
      const raw = localStorage.getItem(notificationReadStorageKey);
      if (!raw) {
        setReadNotificationIds([]);
        return;
      }
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed)) {
        setReadNotificationIds(
          parsed.filter((value): value is string => typeof value === "string"),
        );
        return;
      }
    } catch {
      // ignore storage permission errors
    }
    setReadNotificationIds([]);
  }, [notificationReadStorageKey]);

  useEffect(() => {
    if (!notificationReadStorageKey) return;
    try {
      localStorage.setItem(
        notificationReadStorageKey,
        JSON.stringify(readNotificationIds),
      );
    } catch {
      // ignore storage permission errors
    }
  }, [notificationReadStorageKey, readNotificationIds]);

  const refreshNotifications = useCallback(
    async (options?: { silent?: boolean }) => {
      if (!token || !userId) {
        setActivityNotifications([]);
        setNotificationsError("");
        setNotificationsBusy(false);
        return;
      }

      if (!options?.silent) {
        setNotificationsBusy(true);
      }

      const headers = { Authorization: `Bearer ${token}` };
      let nextNotifications: ActivityNotification[] = [];
      let hasSuccess = false;

      try {
        const [txResp, securityResp] = await Promise.all([
          fetch(`${apiBase}/transactions`, { headers }),
          fetch(`${apiBase}/security/overview`, { headers }),
        ]);

        if (txResp.ok) {
          const txs = (await txResp.json()) as Array<{
            id: string;
            amount: number;
            type: string;
            status?: string;
            description?: string;
            createdAt: string;
            metadata?: {
              entry?: "DEBIT" | "CREDIT";
            };
          }>;

          hasSuccess = true;
          nextNotifications = nextNotifications.concat(
            txs
              .filter(
                (tx) =>
                  (tx.status || "COMPLETED").toUpperCase() === "COMPLETED",
              )
              .slice(0, 20)
              .map((tx) => {
                const isCredit =
                  tx.type === "DEPOSIT" || tx.metadata?.entry === "CREDIT";
                const signedAmount = `${isCredit ? "+" : "-"}${formatCurrencyAmount(
                  Number(tx.amount || 0),
                )}`;
                const title =
                  tx.type === "DEPOSIT"
                    ? "Deposit received"
                    : isCredit
                      ? "Incoming transfer"
                      : "Outgoing transfer";
                const detail = tx.description?.trim();
                const message = detail
                  ? `${isCredit ? "Your balance increased" : "Your balance decreased"} by ${signedAmount}. ${detail}.`
                  : `${isCredit ? "Your balance increased" : "Your balance decreased"} by ${signedAmount}.`;

                return {
                  id: `tx:${tx.id}`,
                  type: "transactions" as const,
                  title,
                  message,
                  createdAt: tx.createdAt,
                  timeLabel: formatNotificationTime(tx.createdAt),
                  amountText: signedAmount,
                  amountTone: isCredit ? "positive" : "negative",
                };
              }),
          );
        }

        if (securityResp.ok) {
          const overview =
            (await securityResp.json()) as SecurityOverviewResponse;
          hasSuccess = true;
          nextNotifications = nextNotifications.concat(
            overview.alerts.slice(0, 10).map((alert, index) => {
              const formattedAlert = formatSecurityNotification(alert);
              const createdAt = alert.occurredAt || new Date().toISOString();
              return {
                id: `security:${alert.id || index}`,
                type: "security" as const,
                title: formattedAlert.title,
                message: formattedAlert.message,
                meta: formattedAlert.meta,
                createdAt,
                timeLabel: formatNotificationTime(createdAt),
              };
            }),
          );
        }

        nextNotifications.sort(
          (left, right) =>
            new Date(right.createdAt).getTime() -
            new Date(left.createdAt).getTime(),
        );

        setActivityNotifications(nextNotifications);
        setNotificationsError(
          hasSuccess ? "" : "Cannot load account notifications right now.",
        );
      } catch {
        setNotificationsError("Cannot load account notifications right now.");
        if (!hasSuccess) {
          setActivityNotifications([]);
        }
      } finally {
        setNotificationsBusy(false);
      }
    },
    [apiBase, formatCurrencyAmount, formatNotificationTime, token, userId],
  );

  useEffect(() => {
    if (!token || !userId) {
      setActivityNotifications([]);
      setNotificationsError("");
      setNotificationsBusy(false);
      return;
    }

    void refreshNotifications();

    const interval = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void refreshNotifications({ silent: true });
      }
    }, 15000);

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        void refreshNotifications({ silent: true });
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [refreshNotifications, token, userId]);

  const markNotificationRead = useCallback((id: string) => {
    setReadNotificationIds((current) =>
      current.includes(id) ? current : [...current, id],
    );
  }, []);

  const markAllNotificationsRead = useCallback(() => {
    setReadNotificationIds((current) => {
      const merged = new Set(current);
      for (const notification of activityNotifications) {
        merged.add(notification.id);
      }
      return Array.from(merged);
    });
  }, [activityNotifications]);

  const notifications = activityNotifications.map((notification) => ({
    ...notification,
    read: readNotificationIds.includes(notification.id),
  }));

  return {
    notifications,
    notificationsBusy,
    notificationsError,
    unreadNotificationCount: notifications.filter((item) => !item.read).length,
    markNotificationRead,
    markAllNotificationsRead,
    refreshNotifications,
  };
}
