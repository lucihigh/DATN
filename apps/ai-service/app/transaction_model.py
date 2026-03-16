import hashlib
from datetime import datetime, timezone

import numpy as np
from pydantic import AliasChoices, BaseModel, Field

TX_FEATURE_NAMES = [
    "hour_of_day",
    "day_of_week",
    "amount_log10",
    "failed_tx_24h",
    "velocity_1h",
    "device_length",
    "projected_spend_ratio_log10",
    "amount_to_daily_avg_ratio_log10",
    "today_spend_before_log10",
    "projected_spend_delta_log10",
    "balance_before_log10",
    "balance_drain_ratio",
    "remaining_balance_log10",
    "low_remaining_balance_flag",
]
BALANCE_DRAIN_RISK_MIN_AMOUNT = 1000.0


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
    balance_before: float = Field(
        default=0.0,
        validation_alias=AliasChoices("balance_before", "balanceBefore"),
    )
    remaining_balance: float = Field(
        default=0.0,
        validation_alias=AliasChoices("remaining_balance", "remainingBalance"),
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
    event.balance_before = float(max(event.balance_before, 0.0))
    if event.remaining_balance <= 0.0 and event.balance_before > 0.0:
        event.remaining_balance = max(event.balance_before - event.amount, 0.0)
    event.remaining_balance = float(max(event.remaining_balance, 0.0))
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


def _safe_log10(value: float) -> float:
    return float(np.log10(max(value, 0.0) + 1.0))


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator > 0:
        return float(max(numerator, 0.0) / denominator)
    return float(max(numerator, 0.0))


def build_tx_feature_map(event: TransactionEvent) -> dict[str, float]:
    projected_ratio = _safe_ratio(float(event.projected_daily_spend), float(event.daily_spend_avg_30d))
    amount_ratio = _safe_ratio(float(event.amount), float(event.daily_spend_avg_30d))
    projected_delta = max(float(event.projected_daily_spend) - float(event.daily_spend_avg_30d), 0.0)
    balance_drain_ratio = _safe_ratio(float(event.amount), float(event.balance_before))
    return {
        "hour_of_day": float(event.timestamp.hour),
        "day_of_week": float(event.timestamp.weekday()),
        "amount_log10": _safe_log10(float(event.amount)),
        "failed_tx_24h": float(event.failed_tx_24h),
        "velocity_1h": float(event.velocity_1h),
        "device_length": float(len(event.device or "")),
        "projected_spend_ratio_log10": _safe_log10(projected_ratio),
        "amount_to_daily_avg_ratio_log10": _safe_log10(amount_ratio),
        "today_spend_before_log10": _safe_log10(float(event.today_spend_before)),
        "projected_spend_delta_log10": _safe_log10(projected_delta),
        "balance_before_log10": _safe_log10(float(event.balance_before)),
        "balance_drain_ratio": float(balance_drain_ratio),
        "remaining_balance_log10": _safe_log10(float(event.remaining_balance)),
        "low_remaining_balance_flag": 1.0 if float(event.remaining_balance) <= 25.0 else 0.0,
    }


def build_tx_features(event: TransactionEvent, feature_names: list[str] | None = None) -> np.ndarray:
    feature_map = build_tx_feature_map(event)
    ordered_names = feature_names or TX_FEATURE_NAMES
    return np.array([float(feature_map.get(name, 0.0)) for name in ordered_names], dtype=float)


def _max_risk_level(*levels: str) -> str:
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    best = "LOW"
    for level in levels:
        if rank.get(level, -1) > rank.get(best, -1):
            best = level
    return best


def _is_material_balance_drain(event: TransactionEvent) -> bool:
    return float(event.amount) >= BALANCE_DRAIN_RISK_MIN_AMOUNT


def adjust_tx_risk_level(base_risk: str, event: TransactionEvent, feedback_profile: dict | None = None) -> str:
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
        amount_ratio = event.amount / max(event.daily_spend_avg_30d, 1.0)
        if amount_ratio >= 10 and event.amount >= 2000:
            risk = _max_risk_level(risk, "HIGH")
        elif amount_ratio >= 4 and event.amount >= 500:
            risk = _max_risk_level(risk, "MEDIUM")

    if event.balance_before > 0 and _is_material_balance_drain(event):
        drain_ratio = event.amount / max(event.balance_before, 1.0)
        if drain_ratio >= 0.95:
            risk = _max_risk_level(risk, "HIGH")
        elif drain_ratio >= 0.85:
            risk = _max_risk_level(risk, "MEDIUM")

    if _is_material_balance_drain(event) and event.remaining_balance <= 5:
        risk = _max_risk_level(risk, "HIGH")
    elif _is_material_balance_drain(event) and event.remaining_balance <= 25:
        risk = _max_risk_level(risk, "MEDIUM")

    if feedback_profile:
        profile_drain = float(feedback_profile.get("median_balance_drain_ratio") or 0.0)
        profile_amount_ratio = float(feedback_profile.get("median_amount_to_daily_avg_ratio") or 0.0)
        profile_projected_ratio = float(feedback_profile.get("median_projected_spend_ratio") or 0.0)
        amount_ratio = (
            event.amount / max(event.daily_spend_avg_30d, 1.0)
            if event.daily_spend_avg_30d > 0
            else 0.0
        )
        projected_ratio = (
            event.projected_daily_spend / max(event.daily_spend_avg_30d, 1.0)
            if event.daily_spend_avg_30d > 0
            else 0.0
        )
        if (
            profile_drain >= 0.8
            and event.balance_before > 0
            and _is_material_balance_drain(event)
        ):
            drain_ratio = event.amount / max(event.balance_before, 1.0)
            if drain_ratio >= max(0.85, profile_drain * 0.95):
                risk = _max_risk_level(risk, "HIGH")
        if profile_amount_ratio >= 3.0 and amount_ratio >= max(4.0, profile_amount_ratio * 0.9):
            risk = _max_risk_level(risk, "HIGH")
        if profile_projected_ratio >= 4.0 and projected_ratio >= max(6.0, profile_projected_ratio * 0.9):
            risk = _max_risk_level(risk, "HIGH")

    return risk


def build_tx_reasons(
    event: TransactionEvent,
    features: np.ndarray,
    feature_mean: np.ndarray,
    feature_std: np.ndarray,
    countries: set[str],
    payment_methods: set[str],
    merchant_categories: set[str],
    feedback_profile: dict | None = None,
) -> list[str]:
    reasons: list[str] = []
    feature_names = list(TX_FEATURE_NAMES[: len(features)])
    feature_positions = {name: index for index, name in enumerate(feature_names)}

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
        amount_ratio = event.amount / max(event.daily_spend_avg_30d, 1.0)
        if amount_ratio >= 10:
            reasons.append("Transaction amount is far above the user's usual daily spend")
        elif amount_ratio >= 4:
            reasons.append("Transaction amount is well above the user's usual daily spend")
    if event.balance_before > 0 and _is_material_balance_drain(event):
        drain_ratio = event.amount / max(event.balance_before, 1.0)
        if drain_ratio >= 0.95:
            reasons.append("Transfer would use almost all available wallet balance")
        elif drain_ratio >= 0.85:
            reasons.append("Transfer would use most of the available wallet balance")
    if _is_material_balance_drain(event) and event.remaining_balance <= 5:
        reasons.append("Transfer would leave the wallet nearly empty")
    elif _is_material_balance_drain(event) and event.remaining_balance <= 25:
        reasons.append("Transfer would leave only a very small remaining balance")

    z_scores = (features - feature_mean) / feature_std
    if feature_positions.get("hour_of_day") is not None and z_scores[feature_positions["hour_of_day"]] > 2.0:
        reasons.append("Unusual transaction hour")
    if feature_positions.get("amount_log10") is not None and z_scores[feature_positions["amount_log10"]] > 2.0:
        reasons.append("Amount significantly above normal behavior")
    if feature_positions.get("velocity_1h") is not None and z_scores[feature_positions["velocity_1h"]] > 2.0:
        reasons.append("Abnormally high transaction velocity")
    if (
        feature_positions.get("projected_spend_ratio_log10") is not None
        and z_scores[feature_positions["projected_spend_ratio_log10"]] > 2.0
    ):
        reasons.append("Projected daily spend deviates sharply from normal behavior")
    if (
        feature_positions.get("projected_spend_delta_log10") is not None
        and z_scores[feature_positions["projected_spend_delta_log10"]] > 2.0
    ):
        reasons.append("Projected daily spend increase is unusually large")
    if (
        feature_positions.get("balance_drain_ratio") is not None
        and _is_material_balance_drain(event)
        and z_scores[feature_positions["balance_drain_ratio"]] > 2.0
    ):
        reasons.append("This transfer would drain much more balance than normal behavior")
    if (
        feature_positions.get("low_remaining_balance_flag") is not None
        and _is_material_balance_drain(event)
        and z_scores[feature_positions["low_remaining_balance_flag"]] > 1.5
    ):
        reasons.append("Remaining balance after transfer is unusually low")

    if feedback_profile:
        profile_drain = float(feedback_profile.get("median_balance_drain_ratio") or 0.0)
        profile_amount_ratio = float(feedback_profile.get("median_amount_to_daily_avg_ratio") or 0.0)
        profile_projected_ratio = float(feedback_profile.get("median_projected_spend_ratio") or 0.0)
        if (
            event.balance_before > 0
            and profile_drain >= 0.8
            and _is_material_balance_drain(event)
        ):
            drain_ratio = event.amount / max(event.balance_before, 1.0)
            if drain_ratio >= max(0.85, profile_drain * 0.95):
                reasons.append("This matches recent user-aborted or user-flagged drain-transfer patterns")
        if event.daily_spend_avg_30d > 0 and profile_amount_ratio >= 3.0:
            amount_ratio = event.amount / max(event.daily_spend_avg_30d, 1.0)
            if amount_ratio >= max(4.0, profile_amount_ratio * 0.9):
                reasons.append("This amount is close to previously flagged scam-like transfer attempts")
        if event.daily_spend_avg_30d > 0 and profile_projected_ratio >= 4.0:
            projected_ratio = event.projected_daily_spend / max(event.daily_spend_avg_30d, 1.0)
            if projected_ratio >= max(6.0, profile_projected_ratio * 0.9):
                reasons.append("This spend spike resembles recent transfers users hesitated on")

    if not reasons:
        reasons.append("No clear anomaly signals detected")

    deduped: list[str] = []
    seen: set[str] = set()
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            deduped.append(reason)
    return deduped
