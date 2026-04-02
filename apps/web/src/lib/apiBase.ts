const normalizeBaseUrl = (value: string) => value.replace(/\/$/, "");

const resolveDefaultApiBase = () => {
  if (typeof window === "undefined") {
    return "/api";
  }

  const { protocol, hostname } = window.location;
  const isLocalHost =
    hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";

  if (isLocalHost) {
    return `${protocol}//${hostname}:4000`;
  }

  return "/api";
};

export const API_BASE = normalizeBaseUrl(
  (import.meta.env.VITE_API_URL as string | undefined)?.trim() ||
    resolveDefaultApiBase(),
);
