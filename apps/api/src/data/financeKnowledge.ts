import { readFileSync, readdirSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

export type MarketIntent = {
  assetClass: "fx" | "crypto" | "commodity" | "stock" | "index";
  symbol: string;
  label: string;
  quoteHint?: string | null;
};

export type FinanceKnowledgeKind =
  | "bank"
  | "broker"
  | "insurer"
  | "fintech"
  | "finance-company"
  | "fund"
  | "etf"
  | "stock"
  | "index";

export type FinanceKnowledgeEntry = {
  canonical: string;
  aliases: string[];
  market?: MarketIntent;
  sector?: string;
  kind: FinanceKnowledgeKind;
};

type FinanceKnowledgeSeedEntry = {
  canonical: string;
  aliases?: string[];
  symbol?: string;
  label?: string;
  assetClass?: "stock" | "index";
  sector?: string;
  kind: FinanceKnowledgeKind;
  quoteHint?: string | null;
};

const DATA_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "finance-knowledge",
);

const normalizeAlias = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[_./-]+/g, " ")
    .replace(/\s+/g, " ");

const humanizeToken = (value: string) =>
  value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]{2,})([A-Z][a-z])/g, "$1 $2");

const compactAlias = (value: string) =>
  normalizeAlias(value).replace(/[^a-z0-9]+/g, "");

const buildAliasList = (entry: FinanceKnowledgeSeedEntry) => {
  const rawCandidates = [
    entry.canonical,
    humanizeToken(entry.canonical),
    entry.label,
    entry.label ? humanizeToken(entry.label) : "",
    ...(entry.aliases || []),
    entry.symbol,
    entry.symbol?.replace(/\.VN$/i, ""),
  ].filter((value): value is string => Boolean(value && value.trim()));

  const aliases = new Set<string>();
  for (const candidate of rawCandidates) {
    const normalized = normalizeAlias(candidate);
    const compact = compactAlias(candidate);
    if (normalized.length >= 2) aliases.add(normalized);
    if (compact.length >= 2) aliases.add(compact);
  }
  return Array.from(aliases);
};

const loadSeedEntries = (): FinanceKnowledgeSeedEntry[] => {
  const files = readdirSync(DATA_DIR)
    .filter((fileName) => fileName.endsWith(".json"))
    .sort((left, right) => left.localeCompare(right));

  return files.flatMap((fileName) => {
    const filePath = path.join(DATA_DIR, fileName);
    const raw = JSON.parse(
      readFileSync(filePath, "utf8"),
    ) as FinanceKnowledgeSeedEntry[];
    return Array.isArray(raw) ? raw : [];
  });
};

const toKnowledgeEntry = (
  entry: FinanceKnowledgeSeedEntry,
): FinanceKnowledgeEntry => ({
  canonical: entry.canonical,
  aliases: buildAliasList(entry),
  sector: entry.sector,
  kind: entry.kind,
  market: entry.symbol
    ? {
        assetClass: entry.assetClass || "stock",
        symbol: entry.symbol,
        label: entry.label || entry.canonical,
        quoteHint: entry.quoteHint ?? null,
      }
    : undefined,
});

export const COPILOT_FINANCE_KNOWLEDGE =
  loadSeedEntries().map(toKnowledgeEntry);

export const COPILOT_COMPANY_ALIASES = Object.fromEntries(
  COPILOT_FINANCE_KNOWLEDGE.flatMap((entry) =>
    entry.market && entry.market.assetClass === "stock"
      ? entry.aliases.map((alias) => [alias, entry.market] as const)
      : [],
  ),
) as Record<string, MarketIntent>;

export const COPILOT_INDEX_ALIASES = Object.fromEntries(
  COPILOT_FINANCE_KNOWLEDGE.flatMap((entry) =>
    entry.market && entry.market.assetClass === "index"
      ? entry.aliases.map((alias) => [alias, entry.market] as const)
      : [],
  ),
) as Record<string, MarketIntent>;

export const COPILOT_COMMON_MARKET_SYMBOLS = new Set([
  ...COPILOT_FINANCE_KNOWLEDGE.flatMap((entry) =>
    entry.market
      ? [entry.market.symbol.replace(/\.VN$/i, ""), entry.market.symbol]
      : [],
  ),
  "BTC",
  "DJI",
  "ETH",
  "EUR",
  "GC",
  "NASDAQ",
  "S&P",
  "SPY",
  "USD",
  "VND",
  "VNINDEX",
  "XAU",
]);
