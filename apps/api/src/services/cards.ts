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
  isPrimary: boolean;
  createdAt?: Date;
}): StoredCard => {
  const occurredAt = input.createdAt ?? new Date();
  const { last4, maskedNumber } = maskCardNumber(input.rawCardNumber);
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
  };
};

export const normalizePrimaryCard = (cards: StoredCard[]) => {
  const hasPrimary = cards.some((card) => card.isPrimary);
  if (hasPrimary) return cards;

  return cards.map((card, index) => ({
    ...card,
    isPrimary: index === 0,
  }));
};
