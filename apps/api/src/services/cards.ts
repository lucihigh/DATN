import crypto from "crypto";

import {
  decryptField,
  encryptField,
  isEncryptedString,
} from "../security/encryption";

const CARD_VAULT_KEY = "cardVault";

export type CardType = "Mastercard" | "Visa" | "Payoneer" | "Skrill";
export type CardStatus = "ACTIVE" | "FROZEN";

export type StoredCard = {
  id: string;
  type: CardType;
  bank: string;
  holder: string;
  last4: string;
  maskedNumber: string;
  expiryMonth: string;
  expiryYear: string;
  status: CardStatus;
  isPrimary: boolean;
  createdAt: string;
  updatedAt: string;
  encryptedNumber?: unknown;
  encryptedCvv?: unknown;
};

const asObject = (value: unknown) =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const asTrimmedString = (value: unknown) =>
  typeof value === "string" && value.trim() ? value.trim() : undefined;

const asCardType = (value: unknown): CardType | undefined => {
  const normalized = asTrimmedString(value);
  if (
    normalized === "Mastercard" ||
    normalized === "Visa" ||
    normalized === "Payoneer" ||
    normalized === "Skrill"
  ) {
    return normalized;
  }
  return undefined;
};

const asCardStatus = (value: unknown): CardStatus | undefined => {
  const normalized = asTrimmedString(value);
  if (normalized === "ACTIVE" || normalized === "FROZEN") return normalized;
  return undefined;
};

const sanitizeCvv = (value: string) => {
  const digits = value.replace(/\D/g, "");
  return /^\d{3,4}$/.test(digits) ? digits : "";
};

const fallbackEncrypt = (value: string) => `plain:${value}`;
const fallbackDecrypt = (value: string) =>
  value.startsWith("plain:") ? value.slice("plain:".length) : value;

const encryptCardSecret = (value: string, aad: string) => {
  try {
    return encryptField(value, { aad });
  } catch {
    return fallbackEncrypt(value);
  }
};

const decryptCardSecret = (value: unknown, aad: string): string | undefined => {
  if (!value) return undefined;
  if (typeof value === "string") {
    return fallbackDecrypt(value);
  }
  if (!isEncryptedString(value)) return undefined;
  try {
    return decryptField(value, { aad });
  } catch {
    try {
      return decryptField(value);
    } catch {
      return undefined;
    }
  }
};

export const maskCardNumber = (value: string) => {
  const digits = value.replace(/\D/g, "");
  const last4 = digits.slice(-4).padStart(4, "*");
  return {
    last4,
    maskedNumber: `**** **** **** ${last4}`,
  };
};

const toStoredCard = (value: unknown): StoredCard | null => {
  const raw = asObject(value);
  const id = asTrimmedString(raw.id);
  const type = asCardType(raw.type);
  const bank = asTrimmedString(raw.bank);
  const holder = asTrimmedString(raw.holder);
  const last4 = asTrimmedString(raw.last4);
  const maskedNumber = asTrimmedString(raw.maskedNumber);
  const expiryMonth = asTrimmedString(raw.expiryMonth);
  const expiryYear = asTrimmedString(raw.expiryYear);
  const status = asCardStatus(raw.status);
  const createdAt = asTrimmedString(raw.createdAt);
  const updatedAt = asTrimmedString(raw.updatedAt);
  const encryptedNumber = raw.encryptedNumber;
  const encryptedCvv = raw.encryptedCvv;
  if (
    !id ||
    !type ||
    !bank ||
    !holder ||
    !last4 ||
    !maskedNumber ||
    !expiryMonth ||
    !expiryYear ||
    !status ||
    !createdAt ||
    !updatedAt
  ) {
    return null;
  }

  return {
    id,
    type,
    bank,
    holder,
    last4,
    maskedNumber,
    expiryMonth,
    expiryYear,
    status,
    isPrimary: Boolean(raw.isPrimary),
    createdAt,
    updatedAt,
    encryptedNumber,
    encryptedCvv,
  };
};

export const getStoredCards = (metadata?: Record<string, unknown>) => {
  const raw = asObject(metadata?.[CARD_VAULT_KEY]);
  const cards = Array.isArray(raw.cards)
    ? raw.cards
        .map((entry) => toStoredCard(entry))
        .filter((entry): entry is StoredCard => Boolean(entry))
    : [];

  return cards.sort(
    (left, right) =>
      Number(right.isPrimary) - Number(left.isPrimary) ||
      Date.parse(right.updatedAt) - Date.parse(left.updatedAt),
  );
};

export const setStoredCards = (
  metadata: Record<string, unknown> | undefined,
  cards: StoredCard[],
) => ({
  ...(metadata ?? {}),
  [CARD_VAULT_KEY]: {
    cards,
  },
});

export const createStoredCard = (input: {
  id: string;
  type: CardType;
  bank: string;
  holder: string;
  rawCardNumber: string;
  expiryMonth: string;
  expiryYear: string;
  rawCvv?: string;
  isPrimary: boolean;
  createdAt?: Date;
}): StoredCard => {
  const occurredAt = input.createdAt ?? new Date();
  const { last4, maskedNumber } = maskCardNumber(input.rawCardNumber);
  const sanitizedCvv = input.rawCvv ? sanitizeCvv(input.rawCvv) : "";
  const encryptedNumber = encryptCardSecret(
    input.rawCardNumber,
    `card:${input.id}:number`,
  );
  const encryptedCvv = sanitizedCvv
    ? encryptCardSecret(sanitizedCvv, `card:${input.id}:cvv`)
    : undefined;

  return {
    id: input.id,
    type: input.type,
    bank: input.bank.trim(),
    holder: input.holder.trim(),
    last4,
    maskedNumber,
    expiryMonth: input.expiryMonth,
    expiryYear: input.expiryYear,
    status: "ACTIVE",
    isPrimary: input.isPrimary,
    createdAt: occurredAt.toISOString(),
    updatedAt: occurredAt.toISOString(),
    encryptedNumber,
    encryptedCvv,
  };
};

export const getStoredCardFullNumber = (card: StoredCard) => {
  const decrypted = decryptCardSecret(
    card.encryptedNumber,
    `card:${card.id}:number`,
  );
  if (!decrypted) return undefined;
  const digits = decrypted.replace(/\D/g, "");
  return /^\d{12,19}$/.test(digits) ? digits : undefined;
};

export const getStoredCardCvv = (card: StoredCard) => {
  const decrypted = decryptCardSecret(card.encryptedCvv, `card:${card.id}:cvv`);
  if (!decrypted) return undefined;
  const digits = sanitizeCvv(decrypted);
  return digits || undefined;
};

export const deriveVirtualCardCvv = (seed: string) => {
  const hash = crypto.createHash("sha256").update(seed).digest();
  const value = (((hash[0] << 16) | (hash[1] << 8) | hash[2]) % 900) + 100;
  return String(value);
};

export const deriveVirtualCardNumber = (seed: string) => {
  const hash = crypto.createHash("sha256").update(seed).digest("hex");
  const digits = hash
    .split("")
    .map((char) => (Number.parseInt(char, 16) % 10).toString())
    .join("");
  return `4${digits.slice(0, 15)}`;
};

export const normalizePrimaryCard = (cards: StoredCard[]) => {
  const hasPrimary = cards.some((card) => card.isPrimary);
  if (hasPrimary) return cards;

  return cards.map((card, index) => ({
    ...card,
    isPrimary: index === 0,
  }));
};
