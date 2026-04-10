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

type NotificationTransaction = {
  id: string;
  amount: number;
  type: string;
  status?: string;
  description?: string;
  createdAt: string;
  metadata?: {
    entry?: "DEBIT" | "CREDIT";
  };
};

type AssistantNotificationResponse = ActivityNotification[];

const getStartOfLocalDay = (value: Date) => {
  const next = new Date(value);
  next.setHours(0, 0, 0, 0);
  return next;
};

const getStartOfLocalWeek = (value: Date) => {
  const next = getStartOfLocalDay(value);
  const day = next.getDay();
  const diff = day === 0 ? -6 : 1 - day;
  next.setDate(next.getDate() + diff);
  return next;
};

const getStartOfLocalMonth = (value: Date) => {
  const next = getStartOfLocalDay(value);
  next.setDate(1);
  return next;
};

const formatSignedDelta = (value: number) =>
  `${value >= 0 ? "+" : "-"}$${Math.abs(value).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;

const sumDebitsInRange = (
  transactions: NotificationTransaction[],
  startInclusive: Date,
  endExclusive: Date,
) =>
  transactions.reduce((sum, transaction) => {
    const createdAt = new Date(transaction.createdAt);
    if (Number.isNaN(createdAt.getTime())) return sum;
    if (createdAt < startInclusive || createdAt >= endExclusive) return sum;
    const isCredit =
      transaction.type === "DEPOSIT" ||
      transaction.metadata?.entry === "CREDIT";
    return sum + (isCredit ? 0 : Math.max(0, Number(transaction.amount || 0)));
  }, 0);

const buildDailyDigestNotification = (
  transactions: NotificationTransaction[],
  now: Date,
): ActivityNotification | null => {
  const digestTime = new Date(now);
  digestTime.setHours(8, 0, 0, 0);
  if (now < digestTime) return null;

  const todayStart = getStartOfLocalDay(now);
  const yesterdayStart = new Date(todayStart);
  yesterdayStart.setDate(yesterdayStart.getDate() - 1);
  const weekStart = getStartOfLocalWeek(now);
  const prevWeekStart = new Date(weekStart);
  prevWeekStart.setDate(prevWeekStart.getDate() - 7);
  const monthStart = getStartOfLocalMonth(now);
  const prevMonthStart = new Date(monthStart);
  prevMonthStart.setMonth(prevMonthStart.getMonth() - 1);

  const weekSpanDays =
    Math.floor((todayStart.getTime() - weekStart.getTime()) / 86400000) + 1;
  const prevWeekEnd = new Date(prevWeekStart);
  prevWeekEnd.setDate(prevWeekEnd.getDate() + weekSpanDays);

  const prevMonthEnd = new Date(prevMonthStart);
  prevMonthEnd.setDate(
    Math.min(
      now.getDate(),
      new Date(
        prevMonthStart.getFullYear(),
        prevMonthStart.getMonth() + 1,
        0,
      ).getDate(),
    ),
  );
  prevMonthEnd.setHours(now.getHours(), now.getMinutes(), now.getSeconds(), 0);

  const todaySpend = sumDebitsInRange(transactions, todayStart, now);
  const yesterdaySpend = sumDebitsInRange(
    transactions,
    yesterdayStart,
    todayStart,
  );
  const thisWeekSpend = sumDebitsInRange(transactions, weekStart, now);
  const lastWeekSpend = sumDebitsInRange(
    transactions,
    prevWeekStart,
    prevWeekEnd,
  );
  const thisMonthSpend = sumDebitsInRange(transactions, monthStart, now);
  const lastMonthSpend = sumDebitsInRange(
    transactions,
    prevMonthStart,
    prevMonthEnd,
  );

  const message = [
    `Today ${todaySpend >= yesterdaySpend ? "is above" : "is below"} yesterday by ${formatSignedDelta(todaySpend - yesterdaySpend)}.`,
    `This week is ${thisWeekSpend >= lastWeekSpend ? "running above" : "running below"} last week by ${formatSignedDelta(thisWeekSpend - lastWeekSpend)}.`,
    `This month is ${thisMonthSpend >= lastMonthSpend ? "tracking above" : "tracking below"} last month by ${formatSignedDelta(thisMonthSpend - lastMonthSpend)}.`,
  ].join(" ");

  return {
    id: `digest:${todayStart.toISOString().slice(0, 10)}`,
    type: "transactions",
    title: "8:00 spending brief",
    message,
    meta: "Today vs yesterday | This week vs last week | This month vs last month",
    createdAt: digestTime.toISOString(),
    timeLabel: "Today 8:00 AM",
    amountText: `$${todaySpend.toLocaleString("en-US", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}`,
    amountTone: todaySpend > yesterdaySpend ? "negative" : "positive",
  };
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
        const [txResp, securityResp, assistantResp] = await Promise.all([
          fetch(`${apiBase}/transactions`, { headers }),
          fetch(`${apiBase}/security/overview`, { headers }),
          fetch(`${apiBase}/activity/assistant`, { headers }),
        ]);

        if (txResp.ok) {
          const txs = (await txResp.json()) as NotificationTransaction[];

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

        if (assistantResp.ok) {
          const assistantNotifications =
            (await assistantResp.json()) as AssistantNotificationResponse;
          hasSuccess = true;
          nextNotifications = nextNotifications.concat(
            assistantNotifications.slice(0, 12).map((notification) => ({
              ...notification,
              type: "assistant" as const,
              timeLabel: formatNotificationTime(notification.createdAt),
            })),
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
    }, 45000);

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
