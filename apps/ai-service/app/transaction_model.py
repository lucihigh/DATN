import hashlib
from datetime import datetime, timezone

import numpy as np
from pydantic import AliasChoices, BaseModel, Field

TX_FEATURE_NAMES = ["hour_of_day", "day_of_week", "amount_log10", "failed_tx_24h", "velocity_1h", "device_length"]


class TransactionEvent(BaseModel):
    transaction_event_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("transaction_event_id", "transactionEventId"),
    )
    transaction_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("transaction_id", "transactionId"),
    )
    request_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("request_id", "requestId"),
    )
    idempotency_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("idempotency_key", "idempotencyKey"),
    )
    user_id: str = Field(validation_alias=AliasChoices("user_id", "userId"))
    timestamp: datetime
    amount: float
    currency: str
    country: str = Field(validation_alias=AliasChoices("country", "location"))
    payment_method: str = Field(validation_alias=AliasChoices("payment_method", "paymentMethod"))
    merchant_category: str = Field(validation_alias=AliasChoices("merchant_category", "merchantCategory"))
    device: str = Field(default="")
    channel: str | None = None
    failed_tx_24h: int = Field(default=0, validation_alias=AliasChoices("failed_tx_24h", "failedTx24h"))
    velocity_1h: int = Field(default=0, validation_alias=AliasChoices("velocity_1h", "velocity1h"))
    daily_spend_avg_30d: float = Field(
        default=0.0,
        validation_alias=AliasChoices("daily_spend_avg_30d", "dailySpendAvg30d"),
    )
    today_spend_before: float = Field(
        default=0.0,
        validation_alias=AliasChoices("today_spend_before", "todaySpendBefore"),
    )
    projected_daily_spend: float = Field(
        default=0.0,
        validation_alias=AliasChoices("projected_daily_spend", "projectedDailySpend"),
    )


class TrainTransactionRequest(BaseModel):
    events: list[TransactionEvent]


def _as_utc(dt: datetime | None) -> datetime | None:
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalize_country(country: str) -> str:
    cleaned = (country or "").strip().upper()
    if not cleaned:
        return "UNK"
    return cleaned[:2] if len(cleaned) >= 2 else cleaned


def _normalize_region_city(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned if cleaned else None


def normalize_transaction_event(event: TransactionEvent) -> TransactionEvent:
    event.timestamp = _as_utc(event.timestamp) or event.timestamp
    event.currency = (event.currency or "").strip().upper()[:8] or "UNK"
    event.country = _normalize_country(event.country)
    event.payment_method = (event.payment_method or "").strip().lower()
    event.merchant_category = (event.merchant_category or "").strip().lower()
    event.device = (event.device or "").strip()
    event.channel = _normalize_region_city(event.channel)
    event.amount = float(max(event.amount, 0.0))
    event.failed_tx_24h = int(max(event.failed_tx_24h, 0))
    event.velocity_1h = int(max(event.velocity_1h, 0))
    event.daily_spend_avg_30d = float(max(event.daily_spend_avg_30d, 0.0))
    event.today_spend_before = float(max(event.today_spend_before, 0.0))
    event.projected_daily_spend = float(max(event.projected_daily_spend, 0.0))
    return event


def build_tx_request_fingerprint(event: TransactionEvent) -> str:
    payload = "|".join(
        [
            str(event.user_id),
            str(event.timestamp.isoformat()),
            str(event.amount),
            str(event.currency),
            str(event.country),
            str(event.payment_method),
            str(event.merchant_category),
            str(event.device),
            str(event.failed_tx_24h),
            str(event.velocity_1h),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def resolve_tx_request_key(event: TransactionEvent, header_key: str | None) -> str:
    for candidate in [header_key, event.idempotency_key, event.request_id, event.transaction_id]:
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    return build_tx_request_fingerprint(event)


def build_tx_features(event: TransactionEvent) -> np.ndarray:
    amount_log10 = float(np.log10(max(event.amount, 0.0) + 1.0))
    return np.array(
        [
            float(event.timestamp.hour),
            float(event.timestamp.weekday()),
            amount_log10,
            float(event.failed_tx_24h),
            float(event.velocity_1h),
            float(len(event.device or "")),
        ],
        dtype=float,
    )


def _max_risk_level(*levels: str) -> str:
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    best = "LOW"
    for level in levels:
        if rank.get(level, -1) > rank.get(best, -1):
            best = level
    return best


def adjust_tx_risk_level(base_risk: str, event: TransactionEvent) -> str:
    risk = base_risk
    if event.amount >= 10000:
        risk = _max_risk_level(risk, "HIGH")
    elif event.amount >= 3000:
        risk = _max_risk_level(risk, "MEDIUM")

    if event.failed_tx_24h >= 3:
        risk = _max_risk_level(risk, "HIGH")
    elif event.failed_tx_24h >= 1:
        risk = _max_risk_level(risk, "MEDIUM")

    if event.velocity_1h >= 6:
        risk = _max_risk_level(risk, "HIGH")
    elif event.velocity_1h >= 3:
        risk = _max_risk_level(risk, "MEDIUM")

    if event.daily_spend_avg_30d > 0:
        projected_ratio = event.projected_daily_spend / max(event.daily_spend_avg_30d, 1.0)
        projected_delta = event.projected_daily_spend - event.daily_spend_avg_30d
        if projected_ratio >= 100 and projected_delta >= 20000:
            risk = _max_risk_level(risk, "HIGH")
        elif projected_ratio >= 30 and projected_delta >= 5000:
            risk = _max_risk_level(risk, "MEDIUM")

    return risk


def build_tx_reasons(
    event: TransactionEvent,
    features: np.ndarray,
    feature_mean: np.ndarray,
    feature_std: np.ndarray,
    countries: set[str],
    payment_methods: set[str],
    merchant_categories: set[str],
) -> list[str]:
    reasons: list[str] = []

    if countries and event.country.strip().lower() not in countries:
        reasons.append("New transaction country compared to learned behavior")
    if payment_methods and event.payment_method not in payment_methods:
        reasons.append("New payment method")
    if merchant_categories and event.merchant_category not in merchant_categories:
        reasons.append("New merchant category")
    if event.amount >= 10000:
        reasons.append("Very high transaction amount")
    elif event.amount >= 3000:
        reasons.append("High transaction amount")
    if event.failed_tx_24h >= 1:
        reasons.append("Recent failed transactions within 24h")
    if event.velocity_1h >= 3:
        reasons.append("High transaction velocity in 1h")
    if event.daily_spend_avg_30d > 0:
        projected_ratio = event.projected_daily_spend / max(event.daily_spend_avg_30d, 1.0)
        if projected_ratio >= 100:
            reasons.append("Projected daily spend is far above normal behavior")
        elif projected_ratio >= 30:
            reasons.append("Projected daily spend is significantly above normal behavior")

    z_scores = (features - feature_mean) / feature_std
    if z_scores[0] > 2.0:
        reasons.append("Unusual transaction hour")
    if z_scores[2] > 2.0:
        reasons.append("Amount significantly above normal behavior")
    if z_scores[4] > 2.0:
        reasons.append("Abnormally high transaction velocity")

    if not reasons:
        reasons.append("No clear anomaly signals detected")

    deduped: list[str] = []
    seen: set[str] = set()
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            deduped.append(reason)
    return deduped
