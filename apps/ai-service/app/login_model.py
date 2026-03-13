import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Any

import numpy as np
from pydantic import AliasChoices, BaseModel, Field

FEATURE_NAMES = ["hour_of_day", "day_of_week", "failed_10m", "device_length", "bot_score"]


class LoginEvent(BaseModel):
    login_event_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("login_event_id", "loginEventId"),
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
    ip: str = Field(validation_alias=AliasChoices("ip", "ipAddress"))
    country: str = Field(validation_alias=AliasChoices("country", "location"))
    device: str = Field(validation_alias=AliasChoices("device", "userAgent"))
    success: int
    failed_10m: int = Field(validation_alias=AliasChoices("failed_10m", "failed10m"))
    bot_score: float = Field(validation_alias=AliasChoices("bot_score", "botScore"))
    email: str | None = None
    region: str | None = None
    city: str | None = None


class TrainRequest(BaseModel):
    events: list[LoginEvent]


def _as_utc(dt: datetime | None) -> datetime | None:
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalize_device(device: str) -> str:
    return (device or "").strip().lower()


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


def _normalize_ip(ip: str) -> str:
    cleaned = (ip or "").strip()
    try:
        return str(ipaddress.ip_address(cleaned))
    except Exception:
        return cleaned


def normalize_login_event(event: LoginEvent) -> LoginEvent:
    event.timestamp = _as_utc(event.timestamp) or event.timestamp
    event.ip = _normalize_ip(event.ip)
    event.country = _normalize_country(event.country)
    event.region = _normalize_region_city(event.region)
    event.city = _normalize_region_city(event.city)
    event.device = (event.device or "").strip()
    return event


def build_request_fingerprint(event: LoginEvent) -> str:
    payload = "|".join(
        [
            str(event.user_id),
            str(event.timestamp.isoformat()),
            str(event.ip),
            str(event.country),
            str(event.device),
            str(int(event.success)),
            str(int(event.failed_10m)),
            f"{float(event.bot_score):.6f}",
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def resolve_request_key(event: LoginEvent, header_key: str | None) -> str:
    for candidate in [header_key, event.idempotency_key, event.request_id]:
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    return build_request_fingerprint(event)


def build_features(event: LoginEvent) -> np.ndarray:
    return np.array(
        [
            float(event.timestamp.hour),
            float(event.timestamp.weekday()),
            float(event.failed_10m),
            float(len(event.device or "")),
            float(event.bot_score),
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


def adjust_risk_level(base_risk: str, event: LoginEvent, history_signals: dict[str, Any]) -> str:
    risk = base_risk

    if history_signals.get("require_otp_sms"):
        risk = _max_risk_level(risk, "HIGH")

    if history_signals.get("recent_attempts_10m", 0) >= 10:
        risk = _max_risk_level(risk, "HIGH")
    elif history_signals.get("recent_attempts_10m", 0) >= 5:
        risk = _max_risk_level(risk, "MEDIUM")

    if history_signals.get("country_changed_recently"):
        risk = _max_risk_level(risk, "HIGH")

    if history_signals.get("is_new_country") and history_signals.get("is_new_ip"):
        risk = _max_risk_level(risk, "MEDIUM")

    if event.bot_score >= 0.9 and (event.failed_10m >= 5 or history_signals.get("recent_attempts_10m", 0) >= 5):
        risk = _max_risk_level(risk, "HIGH")

    return risk


def build_reasons(
    event: LoginEvent,
    features: np.ndarray,
    feature_mean: np.ndarray,
    feature_std: np.ndarray,
    countries: set[str],
    devices: set[str],
    history_signals: dict[str, Any] | None = None,
) -> list[str]:
    reasons: list[str] = []
    history_signals = history_signals or {}

    if countries and event.country.strip().lower() not in countries:
        reasons.append("New country compared to login history")
    if devices and _normalize_device(event.device) not in devices:
        reasons.append("New device not seen before")
    if history_signals.get("is_new_ip"):
        reasons.append("New IP not seen before")
    if history_signals.get("require_otp_sms"):
        reasons.append("Different device and IP from the last successful login; require OTP via SMS")
    if history_signals.get("private_ip"):
        reasons.append("Private/loopback IP detected (verify request source)")
    if history_signals.get("country_changed_recently"):
        last_country = history_signals.get("last_country") or "unknown"
        reasons.append(f"Rapid login country change ({last_country} -> {event.country})")
    if history_signals.get("off_hour_for_user"):
        reasons.append("Uncommon login hour for this user")
    if history_signals.get("recent_attempts_10m", 0) >= 5:
        reasons.append("High login attempt frequency in the last 10 minutes")

    z_scores = (features - feature_mean) / feature_std
    if z_scores[0] > 2.0:
        reasons.append("Unusual login hour")
    if z_scores[1] > 2.0:
        reasons.append("Unusual day of week")
    if z_scores[2] > 2.0:
        reasons.append("High failed attempts in 10 minutes")
    if z_scores[3] > 2.0:
        reasons.append("Unusual device string length")
    if event.bot_score >= 0.8:
        reasons.append("High bot score")
    if history_signals.get("recent_failed_10m_db", 0) >= 3:
        reasons.append("Many recent failed logins based on DB history")

    if not reasons:
        reasons.append("No clear anomaly signals detected")

    deduped: list[str] = []
    seen: set[str] = set()
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            deduped.append(reason)
    return deduped
