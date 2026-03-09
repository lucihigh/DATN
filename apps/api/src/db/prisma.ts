import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  prisma?: PrismaClient;
};

const APP_TIMEZONE = process.env.APP_TIMEZONE || "Asia/Ho_Chi_Minh";

const buildDatasourceUrlWithTimezone = () => {
  const raw = process.env.DATABASE_URL;
  if (!raw) return undefined;

  try {
    const url = new URL(raw);
    const existingOptions = url.searchParams.get("options") || "";
    if (/timezone\s*=|TimeZone\s*=/.test(existingOptions)) {
      return raw;
    }

    const tzOption = `-c TimeZone=${APP_TIMEZONE}`;
    const mergedOptions = existingOptions
      ? `${existingOptions} ${tzOption}`
      : tzOption;
    url.searchParams.set("options", mergedOptions);
    return url.toString();
  } catch {
    return raw;
  }
};

const datasourceUrl = buildDatasourceUrlWithTimezone();

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    datasources: datasourceUrl ? { db: { url: datasourceUrl } } : undefined,
    log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

