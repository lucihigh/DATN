import hashlib
import ipaddress
from collections import deque
from datetime import datetime, timezone
from typing import Any

import numpy as np
from pydantic import AliasChoices, BaseModel, Field

FEATURE_NAMES = [
    "hour_of_day",
    "day_of_week",
    "failed_10m",
    "device_length",
    "bot_score",
    "recent_attempts_1h",
    "is_new_country",
    "is_new_device",
    "off_hour_for_user",
    "private_ip",
]
OFF_HOURS = {0, 1, 2, 3, 4, 5}


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


def _is_private_or_loopback_ip(ip: str | None) -> bool:
    cleaned = (ip or "").strip()
    if not cleaned:
        return False
    try:
        parsed = ipaddress.ip_address(cleaned)
        return parsed.is_private or parsed.is_loopback
    except Exception:
        return False


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


def _history_flag(history_signals: dict[str, Any], key: str) -> float:
    return 1.0 if history_signals.get(key) else 0.0


def _history_count(history_signals: dict[str, Any], key: str) -> float:
    try:
        return float(history_signals.get(key) or 0.0)
    except Exception:
        return 0.0


def build_feature_map(event: LoginEvent, history_signals: dict[str, Any] | None = None) -> dict[str, float]:
    history_signals = history_signals or {}
    return {
        "hour_of_day": float(event.timestamp.hour),
        "day_of_week": float(event.timestamp.weekday()),
        "failed_10m": float(event.failed_10m),
        "device_length": float(len(event.device or "")),
        "bot_score": float(event.bot_score),
        "recent_attempts_1h": _history_count(history_signals, "recent_attempts_1h"),
        "is_new_country": _history_flag(history_signals, "is_new_country"),
        "is_new_device": _history_flag(history_signals, "is_new_device"),
        "off_hour_for_user": _history_flag(history_signals, "off_hour_for_user"),
        "private_ip": _history_flag(history_signals, "private_ip"),
    }


def build_features(
    event: LoginEvent,
    history_signals: dict[str, Any] | None = None,
    feature_names: list[str] | None = None,
) -> np.ndarray:
    feature_map = build_feature_map(event, history_signals)
    ordered_names = feature_names or FEATURE_NAMES
    return np.array([float(feature_map.get(name, 0.0)) for name in ordered_names], dtype=float)


def build_training_feature_rows(
    events: list[LoginEvent],
    feature_names: list[str] | None = None,
) -> list[tuple[LoginEvent, np.ndarray, dict[str, Any]]]:
    ordered_names = feature_names or FEATURE_NAMES
    rows: list[tuple[LoginEvent, np.ndarray, dict[str, Any]]] = []

    recent_1h_by_user: dict[str, deque[datetime]] = {}
    seen_countries_by_user: dict[str, set[str]] = {}
    seen_devices_by_user: dict[str, set[str]] = {}
    hour_history_by_user: dict[str, deque[int]] = {}

    indexed_events = list(enumerate(events))
    indexed_events.sort(key=lambda item: ((_as_utc(item[1].timestamp) or item[1].timestamp), item[0]))

    for _, event in indexed_events:
        event_ts = _as_utc(event.timestamp) or event.timestamp
        user_key = str(event.user_id)
        normalized_country = event.country.strip().lower()
        normalized_device = _normalize_device(event.device)

        recent_attempts = recent_1h_by_user.setdefault(user_key, deque())
        cutoff_1h = event_ts.timestamp() - 3600
        while recent_attempts and recent_attempts[0].timestamp() < cutoff_1h:
            recent_attempts.popleft()

        seen_countries = seen_countries_by_user.setdefault(user_key, set())
        seen_devices = seen_devices_by_user.setdefault(user_key, set())
        hour_history = hour_history_by_user.setdefault(user_key, deque(maxlen=50))
        off_hour_baseline = sum(1 for hour in hour_history if hour in OFF_HOURS)
        off_hour_for_user = (
            event_ts.hour in OFF_HOURS
            and len(hour_history) >= 5
            and off_hour_baseline <= max(1, len(hour_history) // 5)
        )

        history_signals = {
            "recent_attempts_1h": len(recent_attempts),
            "is_new_country": bool(seen_countries and normalized_country not in seen_countries),
            "is_new_device": bool(seen_devices and normalized_device not in seen_devices),
            "off_hour_for_user": off_hour_for_user,
            "private_ip": _is_private_or_loopback_ip(event.ip),
        }
        rows.append((event, build_features(event, history_signals, ordered_names), history_signals))

        recent_attempts.append(event_ts)
        if normalized_country:
            seen_countries.add(normalized_country)
        if normalized_device:
            seen_devices.add(normalized_device)
        hour_history.append(event_ts.hour)

    return rows


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

    if history_signals.get("is_new_country") and history_signals.get("is_new_device"):
        risk = _max_risk_level(risk, "HIGH")

    if history_signals.get("recent_attempts_1h", 0) >= 12:
        risk = _max_risk_level(risk, "HIGH")
    elif history_signals.get("recent_attempts_1h", 0) >= 6:
        risk = _max_risk_level(risk, "MEDIUM")

    if history_signals.get("off_hour_for_user") and history_signals.get("is_new_device"):
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
    feature_names = list(FEATURE_NAMES[: len(features)])
    feature_positions = {name: index for index, name in enumerate(feature_names)}

    if countries and event.country.strip().lower() not in countries:
        reasons.append("New country compared to login history")
    if devices and _normalize_device(event.device) not in devices:
        reasons.append("New device not seen before")
    if history_signals.get("is_new_ip"):
        reasons.append("New IP not seen before")
    if history_signals.get("is_new_country") and history_signals.get("is_new_device"):
        reasons.append("New country and device combination")
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
    if history_signals.get("recent_attempts_1h", 0) >= 6:
        reasons.append("Sustained login burst in the last hour")

    z_scores = (features - feature_mean) / feature_std
    if feature_positions.get("hour_of_day") is not None and z_scores[feature_positions["hour_of_day"]] > 2.0:
        reasons.append("Unusual login hour")
    if feature_positions.get("day_of_week") is not None and z_scores[feature_positions["day_of_week"]] > 2.0:
        reasons.append("Unusual day of week")
    if feature_positions.get("failed_10m") is not None and z_scores[feature_positions["failed_10m"]] > 2.0:
        reasons.append("High failed attempts in 10 minutes")
    if feature_positions.get("device_length") is not None and z_scores[feature_positions["device_length"]] > 2.0:
        reasons.append("Unusual device string length")
    if (
        feature_positions.get("recent_attempts_1h") is not None
        and z_scores[feature_positions["recent_attempts_1h"]] > 2.0
    ):
        reasons.append("Login activity is faster than normal behavior")
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
