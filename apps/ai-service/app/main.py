import json
import os
import ipaddress
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import joblib
import numpy as np
from bson import ObjectId
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError
from pyod.models.iforest import IForest

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
except Exception:  # pragma: no cover - optional dependency at import time
    psycopg = None
    dict_row = None
    Jsonb = None

try:
    import jwt
    from jwt import InvalidTokenError
except Exception:  # pragma: no cover - optional dependency at import time
    jwt = None

    class InvalidTokenError(Exception):
        pass
from app.login_model import (
    FEATURE_NAMES,
    LoginEvent,
    TrainRequest,
    adjust_risk_level as login_adjust_risk_level,
    build_features as build_login_features,
    build_training_feature_rows as build_login_training_feature_rows,
    build_reasons as build_login_reasons,
    normalize_login_event as normalize_login_event_payload,
    resolve_request_key as resolve_login_request_key,
)
from app.transaction_model import (
    TX_FEATURE_NAMES,
    TrainTransactionRequest,
    TransactionEvent,
    adjust_tx_risk_level as transaction_adjust_risk_level,
    build_tx_features as build_transaction_features,
    build_tx_reasons as build_transaction_reasons,
    normalize_transaction_event as normalize_transaction_event_payload,
    resolve_tx_request_key as resolve_transaction_request_key,
)
from app.test_ui import TEST_UI_HTML

app = FastAPI(title="AI Anomaly Scorer")

DEFAULT_CONTAMINATION = 0.02
LOGIN_EVENTS_COLLECTION = "LOGIN_EVENTS"
AI_LOGIN_SCORES_COLLECTION = "AI_LOGIN_SCORES"
TRANSACTION_EVENTS_COLLECTION = "TRANSACTION_EVENTS"
AI_TRANSACTION_SCORES_COLLECTION = "AI_TRANSACTION_SCORES"
AUDIT_LOGS_COLLECTION = "AUDIT_LOGS"
AI_ACTION = "NOTIFY_ADMIN_ONLY"
AI_TX_ACTION = "REVIEW_TRANSACTION_ONLY"
METRICS_KEYS = (
    "score_requests_total",
    "score_success_total",
    "score_errors_total",
    "tx_score_requests_total",
    "tx_score_success_total",
    "tx_score_errors_total",
    "mongo_write_success_total",
    "mongo_write_error_total",
    "admin_alerts_sent_total",
    "admin_alerts_error_total",
    "risk_low_total",
    "risk_medium_total",
    "risk_high_total",
    "score_latency_ms_total",
    "tx_risk_low_total",
    "tx_risk_medium_total",
    "tx_risk_high_total",
    "tx_score_latency_ms_total",
)


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_dt().isoformat()


def _metric_inc(key: str, amount: float = 1.0) -> None:
    if key not in app.state.metrics:
        app.state.metrics[key] = 0.0
    app.state.metrics[key] += amount


def _auth_enabled() -> bool:
    return not bool(str(os.getenv("AI_DISABLE_AUTH", "0")).strip().lower() in {"1", "true", "yes"})


def _auth_mode() -> str:
    mode = str(os.getenv("AI_AUTH_MODE", "api_key")).strip().lower()
    if mode in {"api_key", "jwt", "both"}:
        return mode
    return "api_key"


def _verify_api_key(x_ai_api_key: str | None) -> bool:
    expected = os.getenv("AI_API_KEY", "local-dev-key")
    return bool(x_ai_api_key and x_ai_api_key == expected)


def _verify_jwt(authorization: str | None) -> bool:
    if not authorization:
        return False
    parts = str(authorization).strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return False

    if jwt is None:
        raise HTTPException(status_code=500, detail="JWT library is not available. Install PyJWT.")

    secret = str(os.getenv("AI_JWT_SECRET", "")).strip()
    if not secret:
        raise HTTPException(status_code=500, detail="JWT auth is enabled but AI_JWT_SECRET is missing.")
    algorithm = str(os.getenv("AI_JWT_ALGORITHM", "HS256")).strip() or "HS256"
    audience = str(os.getenv("AI_JWT_AUDIENCE", "")).strip() or None
    issuer = str(os.getenv("AI_JWT_ISSUER", "")).strip() or None

    try:
        jwt.decode(
            parts[1].strip(),
            secret,
            algorithms=[algorithm],
            audience=audience,
            issuer=issuer,
            options={"verify_aud": audience is not None},
        )
        return True
    except InvalidTokenError:
        return False


def _require_api_key(
    x_ai_api_key: str | None = Header(default=None, alias="X-AI-API-KEY"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> None:
    if not _auth_enabled():
        return

    mode = _auth_mode()
    if mode == "api_key":
        if _verify_api_key(x_ai_api_key):
            return
        raise HTTPException(status_code=401, detail="Unauthorized: invalid API key")

    if mode == "jwt":
        if _verify_jwt(authorization):
            return
        raise HTTPException(status_code=401, detail="Unauthorized: invalid JWT")

    if _verify_api_key(x_ai_api_key) or _verify_jwt(authorization):
        return
    raise HTTPException(status_code=401, detail="Unauthorized: invalid API key or JWT")


def _normalize_device(device: str) -> str:
    return (device or "").strip().lower()


def _normalize_login_event(event: LoginEvent) -> LoginEvent:
    return normalize_login_event_payload(event)


def _normalize_transaction_event(event: TransactionEvent) -> TransactionEvent:
    return normalize_transaction_event_payload(event)


def _resolve_request_key(event: LoginEvent, header_key: str | None) -> str:
    return resolve_login_request_key(event, header_key)


def _resolve_tx_request_key(event: TransactionEvent, header_key: str | None) -> str:
    return resolve_transaction_request_key(event, header_key)


def _active_feature_names() -> list[str]:
    names = getattr(app.state, "feature_names", None)
    if isinstance(names, list) and names:
        return [str(name) for name in names]
    return list(FEATURE_NAMES)


def _active_tx_feature_names() -> list[str]:
    names = getattr(app.state, "tx_feature_names", None)
    if isinstance(names, list) and names:
        return [str(name) for name in names]
    return list(TX_FEATURE_NAMES)


def _build_features(event: LoginEvent, history_signals: dict[str, Any] | None = None) -> np.ndarray:
    return build_login_features(event, history_signals=history_signals, feature_names=_active_feature_names())


def _build_tx_features(event: TransactionEvent) -> np.ndarray:
    return build_transaction_features(event, feature_names=_active_tx_feature_names())


def _camel_case_feature_name(name: str) -> str:
    parts = [part for part in str(name).split("_") if part]
    if not parts:
        return "unknownFeature"
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def _feature_vector_to_dict(feature_names: list[str], features: np.ndarray) -> dict[str, float]:
    limit = min(len(feature_names), len(features))
    return {
        _camel_case_feature_name(feature_names[index]): float(features[index])
        for index in range(limit)
    }


def _state_ready() -> bool:
    return getattr(app.state, "model", None) is not None


def _tx_state_ready() -> bool:
    return getattr(app.state, "tx_model", None) is not None


def _mongo_ready() -> bool:
    return getattr(app.state, "mongo_db", None) is not None


def _postgres_ready() -> bool:
    return getattr(app.state, "postgres_conn", None) is not None


def _storage_backend() -> str:
    if _postgres_ready():
        return "postgres"
    if _mongo_ready():
        return "mongo"
    return "none"


def _to_json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    return value


def _normalize_json_field(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _pg_jsonb(value: dict[str, Any]) -> Any:
    normalized = json.loads(json.dumps(value, default=_to_json_value))
    return Jsonb(normalized) if Jsonb is not None else normalized


def _pg_fetchone(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    if not _postgres_ready():
        return None
    with app.state.postgres_conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, params)
        row = cur.fetchone()
    return dict(row) if row else None


def _pg_fetchall(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    if not _postgres_ready():
        return []
    with app.state.postgres_conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
    return [dict(row) for row in rows]


def _pg_execute(query: str, params: tuple[Any, ...] = ()) -> None:
    if not _postgres_ready():
        raise RuntimeError("PostgreSQL not connected")
    with app.state.postgres_conn.cursor() as cur:
        cur.execute(query, params)


def _build_login_score_details(
    *,
    event: LoginEvent,
    features: np.ndarray,
    anomaly_score: float,
    raw_score: float,
    risk_level_base: str,
    risk_level_final: str,
    reasons: list[str],
    history_signals: dict[str, Any],
    request_key: str,
    login_event_id: str,
) -> dict[str, Any]:
    model_version = str(getattr(app.state, "model_version", None) or "unknown")
    feature_names = _active_feature_names()
    return {
        "requestKey": request_key,
        "requestId": event.request_id,
        "loginEventId": login_event_id,
        "userId": event.user_id,
        "inputSnapshot": {
            "timestamp": event.timestamp,
            "ipAddress": event.ip,
            "country": event.country,
            "region": event.region,
            "city": event.city,
            "device": event.device,
            "success": bool(event.success),
            "failed10m": int(event.failed_10m),
            "botScore": float(event.bot_score),
        },
        "features": _feature_vector_to_dict(feature_names, features),
        "result": {
            "anomalyScore": float(anomaly_score),
            "rawScore": float(raw_score),
            "riskLevel": risk_level_final,
            "riskLevelBase": risk_level_base,
            "riskLevelFinal": risk_level_final,
            "reasons": reasons,
            "monitoringOnly": True,
            "action": AI_ACTION,
            "requireOtpSms": bool(history_signals.get("require_otp_sms")),
            "otpChannel": "sms" if history_signals.get("require_otp_sms") else None,
            "otpReason": history_signals.get("otp_reason"),
        },
        "analysis": {
            "ip": {
                "value": event.ip,
                "isNewIpForUser": bool(history_signals.get("is_new_ip")),
                "isPrivateOrLoopback": bool(history_signals.get("private_ip")),
            },
            "device": {
                "value": event.device,
                "isNewDeviceForUser": bool(history_signals.get("is_new_device")),
            },
            "location": {
                "country": event.country,
                "region": event.region,
                "city": event.city,
                "isNewCountryForUser": bool(history_signals.get("is_new_country")),
                "countryChangedRecently": bool(history_signals.get("country_changed_recently")),
                "lastCountry": history_signals.get("last_country"),
            },
            "time": {
                "hourOfDay": int(event.timestamp.hour),
                "dayOfWeek": int(event.timestamp.weekday()),
                "offHourForUser": bool(history_signals.get("off_hour_for_user")),
                "lastLoginAt": history_signals.get("last_timestamp"),
            },
            "session": {
                "hasSuccessHistory": bool(history_signals.get("has_success_history")),
                "lastSuccessIp": history_signals.get("last_success_ip"),
                "lastSuccessDevice": history_signals.get("last_success_device"),
                "lastSuccessTimestamp": history_signals.get("last_success_timestamp"),
                "differentIpFromLastSuccess": bool(history_signals.get("different_ip_from_last_success")),
                "differentDeviceFromLastSuccess": bool(history_signals.get("different_device_from_last_success")),
                "requireOtpSms": bool(history_signals.get("require_otp_sms")),
            },
            "frequency": {
                "failed10mInput": int(event.failed_10m),
                "recentAttempts10m": int(history_signals.get("recent_attempts_10m", 0)),
                "recentAttempts1h": int(history_signals.get("recent_attempts_1h", 0)),
                "recentFailed10mDb": int(history_signals.get("recent_failed_10m_db", 0)),
            },
        },
        "model": {
            "name": "pyod_iforest",
            "version": model_version,
            "source": app.state.model_source,
            "trainedAt": getattr(app.state, "model_trained_at_dt", None),
        },
        "scoreStatus": "SUCCESS",
        "error": None,
        "scoredAt": _now_dt(),
    }


def _build_tx_score_details(
    *,
    event: TransactionEvent,
    features: np.ndarray,
    anomaly_score: float,
    raw_score: float,
    risk_level_base: str,
    risk_level_final: str,
    reasons: list[str],
    request_key: str,
    transaction_event_id: str,
) -> dict[str, Any]:
    model_version = str(getattr(app.state, "tx_model_version", None) or "unknown")
    feature_names = _active_tx_feature_names()
    return {
        "requestKey": request_key,
        "requestId": event.request_id,
        "transactionEventId": transaction_event_id,
        "transactionId": event.transaction_id,
        "userId": event.user_id,
        "inputSnapshot": {
            "timestamp": event.timestamp,
            "amount": float(event.amount),
            "currency": event.currency,
            "country": event.country,
            "paymentMethod": event.payment_method,
            "merchantCategory": event.merchant_category,
            "device": event.device,
            "channel": event.channel,
            "failedTx24h": int(event.failed_tx_24h),
            "velocity1h": int(event.velocity_1h),
            "dailySpendAvg30d": float(event.daily_spend_avg_30d),
            "todaySpendBefore": float(event.today_spend_before),
            "projectedDailySpend": float(event.projected_daily_spend),
            "balanceBefore": float(event.balance_before),
            "remainingBalance": float(event.remaining_balance),
        },
        "features": _feature_vector_to_dict(feature_names, features),
        "result": {
            "anomalyScore": float(anomaly_score),
            "rawScore": float(raw_score),
            "riskLevel": risk_level_final,
            "riskLevelBase": risk_level_base,
            "riskLevelFinal": risk_level_final,
            "reasons": reasons,
            "monitoringOnly": True,
            "action": AI_TX_ACTION,
        },
        "model": {
            "name": "pyod_iforest",
            "version": model_version,
            "source": app.state.tx_model_source,
            "trainedAt": getattr(app.state, "tx_model_trained_at_dt", None),
        },
        "scoreStatus": "SUCCESS",
        "error": None,
        "scoredAt": _now_dt(),
    }


def _score_to_level(score: float, thresholds: dict[str, float]) -> str:
    if score <= thresholds["p90"]:
        return "LOW"
    if score <= thresholds["p97"]:
        return "MEDIUM"
    return "HIGH"


def _scaled_score(score: float, score_min: float, score_max: float) -> float:
    if score_max <= score_min:
        return 0.0
    scaled = (score - score_min) / (score_max - score_min)
    return float(max(0.0, min(1.0, scaled)))


def _fit_iforest(feature_matrix: np.ndarray) -> tuple[IForest, dict[str, float], np.ndarray, np.ndarray]:
    model = IForest(contamination=DEFAULT_CONTAMINATION, random_state=42)
    model.fit(feature_matrix)

    scores = model.decision_scores_
    if len(scores) >= 20:
        p90 = float(np.percentile(scores, 90))
        p97 = float(np.percentile(scores, 97))
    else:
        p90 = float(scores.mean() + scores.std())
        p97 = float(scores.mean() + 2 * scores.std())

    thresholds = {
        "p90": p90,
        "p97": p97,
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
    }
    feature_mean = feature_matrix.mean(axis=0)
    feature_std = feature_matrix.std(axis=0)
    return model, thresholds, feature_mean, feature_std


def _set_model_state(
    *,
    model: Any,
    thresholds: dict[str, float],
    feature_mean: np.ndarray,
    feature_std: np.ndarray,
    countries: set[str],
    devices: set[str],
    trained_at: str,
    train_size: int,
    source: str,
    model_version: str | None = None,
    model_path: str | None = None,
    metadata_path: str | None = None,
    feature_names: list[str] | None = None,
) -> None:
    safe_std = np.asarray(feature_std, dtype=float).copy()
    safe_std[safe_std == 0] = 1.0
    app.state.model = model
    app.state.thresholds = thresholds
    app.state.feature_mean = np.asarray(feature_mean, dtype=float)
    app.state.feature_std = safe_std
    app.state.countries = countries
    app.state.devices = devices
    app.state.trained_at = trained_at
    app.state.train_size = train_size
    app.state.model_source = source
    app.state.model_version = model_version or str(trained_at)
    app.state.model_path = model_path
    app.state.metadata_path = metadata_path
    app.state.feature_names = list(feature_names or FEATURE_NAMES)


def _set_tx_model_state(
    *,
    model: Any,
    thresholds: dict[str, float],
    feature_mean: np.ndarray,
    feature_std: np.ndarray,
    countries: set[str],
    payment_methods: set[str],
    merchant_categories: set[str],
    trained_at: str,
    train_size: int,
    source: str,
    model_version: str | None = None,
    model_path: str | None = None,
    metadata_path: str | None = None,
    feature_names: list[str] | None = None,
    feedback_profile: dict[str, Any] | None = None,
) -> None:
    safe_std = np.asarray(feature_std, dtype=float).copy()
    safe_std[safe_std == 0] = 1.0
    app.state.tx_model = model
    app.state.tx_thresholds = thresholds
    app.state.tx_feature_mean = np.asarray(feature_mean, dtype=float)
    app.state.tx_feature_std = safe_std
    app.state.tx_countries = countries
    app.state.tx_payment_methods = payment_methods
    app.state.tx_merchant_categories = merchant_categories
    app.state.tx_trained_at = trained_at
    app.state.tx_train_size = train_size
    app.state.tx_model_source = source
    app.state.tx_model_version = model_version or str(trained_at)
    app.state.tx_model_path = model_path
    app.state.tx_metadata_path = metadata_path
    app.state.tx_feature_names = list(feature_names or TX_FEATURE_NAMES)
    app.state.tx_feedback_profile = dict(feedback_profile or {})


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _as_utc(dt: datetime | None) -> datetime | None:
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe_object_id(value: str | None) -> ObjectId | None:
    if not value:
        return None
    try:
        return ObjectId(str(value))
    except Exception:
        return None


def _safe_uuid_str(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(UUID(str(value)))
    except Exception:
        return None


def _resolve_existing_postgres_user_id(value: str | None) -> str | None:
    candidate = _safe_uuid_str(value)
    if not candidate or not _postgres_ready():
        return None
    try:
        row = _pg_fetchone('SELECT "id" FROM "User" WHERE "id" = %s LIMIT 1', (candidate,))
        return candidate if row else None
    except Exception:
        return None


def _is_private_or_loopback_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return parsed.is_private or parsed.is_loopback
    except Exception:
        return False


def _get_history_signals(event: LoginEvent) -> dict[str, Any]:
    if _postgres_ready():
        return _get_history_signals_from_postgres(event)

    event_ts = _as_utc(event.timestamp) or event.timestamp
    signals: dict[str, Any] = {
        "available": False,
        "history_count": 0,
        "has_success_history": False,
        "is_new_ip": False,
        "is_new_country": False,
        "is_new_device": False,
        "recent_attempts_10m": 0,
        "recent_attempts_1h": 0,
        "recent_failed_10m_db": 0,
        "last_country": None,
        "last_region": None,
        "last_city": None,
        "last_ip": None,
        "last_timestamp": None,
        "last_success_ip": None,
        "last_success_device": None,
        "last_success_timestamp": None,
        "different_ip_from_last_success": False,
        "different_device_from_last_success": False,
        "require_otp_sms": False,
        "otp_reason": None,
        "country_changed_recently": False,
        "off_hour_for_user": False,
        "private_ip": _is_private_or_loopback_ip(event.ip),
    }

    if not _mongo_ready():
        return signals

    mongo_db = app.state.mongo_db
    user_oid = _safe_object_id(event.user_id)
    query: dict[str, Any] = {}
    if user_oid is not None:
        query["$or"] = [{"userId": user_oid}, {"userIdRaw": event.user_id}]
    else:
        query["userIdRaw"] = event.user_id

    query["createdAt"] = {"$lt": event_ts}

    projection = {
        "ipAddress": 1,
        "country": 1,
        "region": 1,
        "city": 1,
        "device": 1,
        "userAgent": 1,
        "success": 1,
        "createdAt": 1,
        "failed10m": 1,
    }

    try:
        history_docs = list(
            mongo_db[LOGIN_EVENTS_COLLECTION]
            .find(query, projection=projection)
            .sort("createdAt", -1)
            .limit(300)
        )
    except PyMongoError:
        return signals

    if not history_docs:
        return signals

    signals["available"] = True
    signals["history_count"] = len(history_docs)

    seen_ips = {str(doc.get("ipAddress") or "").strip() for doc in history_docs if doc.get("ipAddress")}
    seen_countries = {
        str(doc.get("country") or doc.get("location") or "").strip().lower()
        for doc in history_docs
        if (doc.get("country") or doc.get("location"))
    }
    seen_devices = {
        _normalize_device(str(doc.get("device") or doc.get("userAgent") or ""))
        for doc in history_docs
        if (doc.get("device") or doc.get("userAgent"))
    }

    signals["is_new_ip"] = event.ip not in seen_ips if seen_ips else False
    signals["is_new_country"] = event.country.strip().lower() not in seen_countries if seen_countries else False
    signals["is_new_device"] = _normalize_device(event.device) not in seen_devices if seen_devices else False

    latest = history_docs[0]
    signals["last_country"] = latest.get("country") or latest.get("location")
    signals["last_region"] = latest.get("region")
    signals["last_city"] = latest.get("city")
    signals["last_ip"] = latest.get("ipAddress")
    signals["last_timestamp"] = latest.get("createdAt")

    successful_docs = [doc for doc in history_docs if doc.get("success") is True]
    if successful_docs:
        last_success = successful_docs[0]
        last_success_ip = str(last_success.get("ipAddress") or "").strip() or None
        last_success_device = _normalize_device(str(last_success.get("device") or last_success.get("userAgent") or ""))

        signals["has_success_history"] = True
        signals["last_success_ip"] = last_success_ip
        signals["last_success_device"] = last_success_device or None
        signals["last_success_timestamp"] = last_success.get("createdAt")
        signals["different_ip_from_last_success"] = bool(last_success_ip and last_success_ip != event.ip)
        signals["different_device_from_last_success"] = bool(
            last_success_device and last_success_device != _normalize_device(event.device)
        )

        if signals["different_ip_from_last_success"] and signals["different_device_from_last_success"]:
            signals["require_otp_sms"] = True
            signals["otp_reason"] = "Existing successful login detected from another device and IP"

    recent_10m_cutoff = event_ts.timestamp() - 600
    recent_1h_cutoff = event_ts.timestamp() - 3600
    hour_buckets: dict[int, int] = {}

    for doc in history_docs:
        created_at = doc.get("createdAt")
        created_at = _as_utc(created_at)
        if not isinstance(created_at, datetime):
            continue
        ts = created_at.timestamp()
        if ts >= recent_10m_cutoff:
            signals["recent_attempts_10m"] += 1
            if doc.get("success") is False:
                signals["recent_failed_10m_db"] += 1
        if ts >= recent_1h_cutoff:
            signals["recent_attempts_1h"] += 1
        hour_buckets[created_at.hour] = hour_buckets.get(created_at.hour, 0) + 1

    current_hour_count = hour_buckets.get(event_ts.hour, 0)
    if len(history_docs) >= 20 and current_hour_count <= 1:
        signals["off_hour_for_user"] = True

    latest_time = _as_utc(latest.get("createdAt"))
    latest_country = str(latest.get("country") or latest.get("location") or "").strip().lower()
    if isinstance(latest_time, datetime) and latest_country:
        delta_minutes = (event_ts - latest_time).total_seconds() / 60.0
        signals["country_changed_recently"] = (
            delta_minutes <= 180
            and latest_country != event.country.strip().lower()
        )

    return signals


def _adjust_risk_level(base_risk: str, event: LoginEvent, history_signals: dict[str, Any]) -> str:
    return login_adjust_risk_level(base_risk, event, history_signals)


def _adjust_tx_risk_level(base_risk: str, event: TransactionEvent) -> str:
    return transaction_adjust_risk_level(
        base_risk,
        event,
        feedback_profile=getattr(app.state, "tx_feedback_profile", {}) or {},
    )


def _build_reasons(event: LoginEvent, features: np.ndarray, history_signals: dict[str, Any] | None = None) -> list[str]:
    return build_login_reasons(
        event=event,
        features=features,
        feature_mean=app.state.feature_mean,
        feature_std=app.state.feature_std,
        countries=app.state.countries,
        devices=app.state.devices,
        history_signals=history_signals,
    )


def _build_tx_reasons(event: TransactionEvent, features: np.ndarray) -> list[str]:
    return build_transaction_reasons(
        event=event,
        features=features,
        feature_mean=app.state.tx_feature_mean,
        feature_std=app.state.tx_feature_std,
        countries=app.state.tx_countries,
        payment_methods=app.state.tx_payment_methods,
        merchant_categories=app.state.tx_merchant_categories,
        feedback_profile=getattr(app.state, "tx_feedback_profile", {}) or {},
    )


def _resolve_artifact_paths() -> tuple[Path, Path]:
    base_dir = Path(__file__).resolve().parents[1]
    env_model = os.getenv("AI_MODEL_PATH")
    env_meta = os.getenv("AI_METADATA_PATH")
    if env_model and env_meta:
        return Path(env_model), Path(env_meta)

    active_file = Path(os.getenv("AI_ACTIVE_MODEL_FILE", str(base_dir / "models" / "active_model.json")))
    if active_file.exists():
        try:
            active_cfg = json.loads(active_file.read_text(encoding="utf-8"))
            return Path(active_cfg["model_path"]), Path(active_cfg["metadata_path"])
        except Exception:
            pass

    model_path = Path(base_dir / "models" / "iforest_rba.joblib")
    metadata_path = Path(base_dir / "models" / "iforest_rba_metadata.json")
    return model_path, metadata_path


def _resolve_tx_artifact_paths() -> tuple[Path, Path]:
    base_dir = Path(__file__).resolve().parents[1]
    env_model = os.getenv("AI_TX_MODEL_PATH")
    env_meta = os.getenv("AI_TX_METADATA_PATH")
    if env_model and env_meta:
        return Path(env_model), Path(env_meta)

    active_file = Path(os.getenv("AI_TX_ACTIVE_MODEL_FILE", str(base_dir / "models" / "active_tx_model.json")))
    if active_file.exists():
        try:
            active_cfg = json.loads(active_file.read_text(encoding="utf-8"))
            return Path(active_cfg["model_path"]), Path(active_cfg["metadata_path"])
        except Exception:
            pass

    model_path = Path(base_dir / "models" / "iforest_tx.joblib")
    metadata_path = Path(base_dir / "models" / "iforest_tx_metadata.json")
    return model_path, metadata_path


def _resolve_model_version(
    *, metadata: dict[str, Any] | None = None, model_path: Path | None = None, trained_at: str | None = None
) -> str:
    env_version = os.getenv("AI_MODEL_VERSION")
    if env_version:
        return env_version
    if metadata and metadata.get("model_version"):
        return str(metadata["model_version"])
    if model_path is not None:
        return model_path.stem
    if trained_at:
        return trained_at
    return "unknown"


def _try_load_persisted_model() -> None:
    model_path, metadata_path = _resolve_artifact_paths()
    if not model_path.exists() or not metadata_path.exists():
        app.state.load_error = None
        return

    try:
        model = joblib.load(model_path)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        feature_names = [str(name) for name in metadata.get("feature_names", FEATURE_NAMES)]
        thresholds = {
            "p90": float(metadata["thresholds"]["p90"]),
            "p97": float(metadata["thresholds"]["p97"]),
            "score_min": float(metadata["thresholds"]["score_min"]),
            "score_max": float(metadata["thresholds"]["score_max"]),
        }
        feature_mean = np.asarray(metadata["feature_mean"], dtype=float)
        feature_std = np.asarray(metadata["feature_std"], dtype=float)
        countries = {str(country).lower() for country in metadata.get("countries", [])}
        devices = {str(device).lower() for device in metadata.get("devices", [])}
        _set_model_state(
            model=model,
            thresholds=thresholds,
            feature_mean=feature_mean,
            feature_std=feature_std,
            countries=countries,
            devices=devices,
            trained_at=str(metadata.get("trained_at") or _now_iso()),
            train_size=int(metadata.get("train_size", 0)),
            source=f"artifact:{model_path.name}",
            model_version=_resolve_model_version(
                metadata=metadata,
                model_path=model_path,
                trained_at=str(metadata.get("trained_at") or None),
            ),
            model_path=str(model_path),
            metadata_path=str(metadata_path),
            feature_names=feature_names,
        )
        app.state.model_trained_at_dt = _parse_iso_datetime(str(metadata.get("trained_at")))
        app.state.load_error = None
    except Exception as exc:
        app.state.load_error = str(exc)


def _try_load_persisted_tx_model() -> None:
    model_path, metadata_path = _resolve_tx_artifact_paths()
    if not model_path.exists() or not metadata_path.exists():
        app.state.tx_load_error = None
        return

    try:
        model = joblib.load(model_path)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        feature_names = [str(name) for name in metadata.get("feature_names", TX_FEATURE_NAMES)]
        thresholds = {
            "p90": float(metadata["thresholds"]["p90"]),
            "p97": float(metadata["thresholds"]["p97"]),
            "score_min": float(metadata["thresholds"]["score_min"]),
            "score_max": float(metadata["thresholds"]["score_max"]),
        }
        feature_mean = np.asarray(metadata["feature_mean"], dtype=float)
        feature_std = np.asarray(metadata["feature_std"], dtype=float)
        countries = {str(country).lower() for country in metadata.get("countries", [])}
        payment_methods = {str(method).lower() for method in metadata.get("payment_methods", [])}
        merchant_categories = {str(category).lower() for category in metadata.get("merchant_categories", [])}
        feedback_profile = metadata.get("feedback_profile", {})
        trained_at = str(metadata.get("trained_at") or _now_iso())
        _set_tx_model_state(
            model=model,
            thresholds=thresholds,
            feature_mean=feature_mean,
            feature_std=feature_std,
            countries=countries,
            payment_methods=payment_methods,
            merchant_categories=merchant_categories,
            trained_at=trained_at,
            train_size=int(metadata.get("train_size", 0)),
            source=f"artifact:{model_path.name}",
            model_version=_resolve_model_version(
                metadata=metadata,
                model_path=model_path,
                trained_at=trained_at,
            ),
            model_path=str(model_path),
            metadata_path=str(metadata_path),
            feature_names=feature_names,
            feedback_profile=feedback_profile if isinstance(feedback_profile, dict) else {},
        )
        app.state.tx_model_trained_at_dt = _parse_iso_datetime(trained_at)
        app.state.tx_load_error = None
    except Exception as exc:
        app.state.tx_load_error = str(exc)


def _persist_login_model_artifacts(*, promote: bool = False) -> dict[str, Any]:
    if not _state_ready():
        return {"saved": False, "reason": "model_not_ready"}

    model_path, metadata_path = _resolve_artifact_paths()
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    metadata = {
        "artifact_version": 1,
        "model_type": "pyod.IForest",
        "model_version": getattr(app.state, "model_version", "unknown"),
        "trained_at": app.state.trained_at,
        "contamination": DEFAULT_CONTAMINATION,
        "feature_names": _active_feature_names(),
        "train_size": int(app.state.train_size or 0),
        "thresholds": {
            "p90": float(app.state.thresholds["p90"]),
            "p97": float(app.state.thresholds["p97"]),
            "score_min": float(app.state.thresholds["score_min"]),
            "score_max": float(app.state.thresholds["score_max"]),
        },
        "feature_mean": [float(x) for x in np.asarray(app.state.feature_mean, dtype=float).tolist()],
        "feature_std": [float(x) for x in np.asarray(app.state.feature_std, dtype=float).tolist()],
        "countries": sorted(app.state.countries),
        "devices": sorted(app.state.devices),
        "source": app.state.model_source,
    }

    joblib.dump(app.state.model, model_path)
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=True), encoding="utf-8")

    if promote:
        base_dir = Path(__file__).resolve().parents[1]
        active_file = Path(os.getenv("AI_ACTIVE_MODEL_FILE", str(base_dir / "models" / "active_model.json")))
        active_file.parent.mkdir(parents=True, exist_ok=True)
        active_cfg = {
            "model_version": getattr(app.state, "model_version", "unknown"),
            "model_path": str(model_path),
            "metadata_path": str(metadata_path),
            "promoted_at": _now_iso(),
        }
        active_file.write_text(json.dumps(active_cfg, ensure_ascii=True), encoding="utf-8")
    else:
        active_file = None

    app.state.model_path = str(model_path)
    app.state.metadata_path = str(metadata_path)
    return {
        "saved": True,
        "model_path": str(model_path),
        "metadata_path": str(metadata_path),
        "active_model_file": str(active_file) if active_file is not None else None,
    }


def _persist_tx_model_artifacts(*, promote: bool = False) -> dict[str, Any]:
    if not _tx_state_ready():
        return {"saved": False, "reason": "tx_model_not_ready"}

    model_path, metadata_path = _resolve_tx_artifact_paths()
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    metadata = {
        "artifact_version": 1,
        "model_type": "pyod.IForest",
        "model_version": getattr(app.state, "tx_model_version", "unknown"),
        "trained_at": app.state.tx_trained_at,
        "contamination": DEFAULT_CONTAMINATION,
        "feature_names": _active_tx_feature_names(),
        "train_size": int(app.state.tx_train_size or 0),
        "thresholds": {
            "p90": float(app.state.tx_thresholds["p90"]),
            "p97": float(app.state.tx_thresholds["p97"]),
            "score_min": float(app.state.tx_thresholds["score_min"]),
            "score_max": float(app.state.tx_thresholds["score_max"]),
        },
        "feature_mean": [float(x) for x in np.asarray(app.state.tx_feature_mean, dtype=float).tolist()],
        "feature_std": [float(x) for x in np.asarray(app.state.tx_feature_std, dtype=float).tolist()],
        "countries": sorted(app.state.tx_countries),
        "payment_methods": sorted(app.state.tx_payment_methods),
        "merchant_categories": sorted(app.state.tx_merchant_categories),
        "feedback_profile": getattr(app.state, "tx_feedback_profile", {}) or {},
        "source": app.state.tx_model_source,
    }

    joblib.dump(app.state.tx_model, model_path)
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=True), encoding="utf-8")

    if promote:
        base_dir = Path(__file__).resolve().parents[1]
        active_file = Path(os.getenv("AI_TX_ACTIVE_MODEL_FILE", str(base_dir / "models" / "active_tx_model.json")))
        active_file.parent.mkdir(parents=True, exist_ok=True)
        active_cfg = {
            "model_version": getattr(app.state, "tx_model_version", "unknown"),
            "model_path": str(model_path),
            "metadata_path": str(metadata_path),
            "promoted_at": _now_iso(),
        }
        active_file.write_text(json.dumps(active_cfg, ensure_ascii=True), encoding="utf-8")
    else:
        active_file = None

    app.state.tx_model_path = str(model_path)
    app.state.tx_metadata_path = str(metadata_path)
    return {
        "saved": True,
        "model_path": str(model_path),
        "metadata_path": str(metadata_path),
        "active_model_file": str(active_file) if active_file is not None else None,
    }


def _aggregate_risk_counts(db: Any, collection_name: str, cutoff_dt: datetime) -> dict[str, int]:
    pipeline = [
        {"$match": {"scoredAt": {"$gte": cutoff_dt}}},
        {"$group": {"_id": "$result.riskLevel", "count": {"$sum": 1}}},
    ]
    grouped = list(db[collection_name].aggregate(pipeline))
    risk = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for row in grouped:
        key = str(row.get("_id") or "").upper()
        if key in risk:
            risk[key] = int(row.get("count", 0))
    return risk


def _init_mongo() -> None:
    uri = os.getenv("MONGODB_URI")
    db_name = os.getenv("MONGODB_DB")
    app.state.mongo_client = None
    app.state.mongo_db = None
    app.state.mongo_db_name = db_name
    app.state.mongo_error = None

    if not uri or not db_name:
        app.state.mongo_error = "Missing MONGODB_URI or MONGODB_DB"
        return

    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        app.state.mongo_client = client
        app.state.mongo_db = client[db_name]
        app.state.mongo_error = None
        _ensure_mongo_indexes()
    except Exception as exc:
        app.state.mongo_client = None
        app.state.mongo_db = None
        app.state.mongo_error = str(exc)


def _init_postgres() -> None:
    db_url = os.getenv("DATABASE_URL")
    app.state.postgres_conn = None
    app.state.postgres_error = None
    app.state.postgres_db = db_url

    if not db_url:
        app.state.postgres_error = "Missing DATABASE_URL"
        return

    if psycopg is None:
        app.state.postgres_error = "psycopg is not installed"
        return

    try:
        conn = psycopg.connect(db_url, autocommit=True)
        app.state.postgres_conn = conn
        app.state.postgres_error = None
    except Exception as exc:
        app.state.postgres_conn = None
        app.state.postgres_error = str(exc)


def _ensure_mongo_indexes() -> None:
    if not _mongo_ready():
        return
    db = app.state.mongo_db
    try:
        db[LOGIN_EVENTS_COLLECTION].create_index([("createdAt", -1)])
        db[LOGIN_EVENTS_COLLECTION].create_index([("userId", 1), ("createdAt", -1)])
        db[LOGIN_EVENTS_COLLECTION].create_index([("userIdRaw", 1), ("createdAt", -1)])
        db[LOGIN_EVENTS_COLLECTION].create_index([("country", 1), ("createdAt", -1)])
        db[LOGIN_EVENTS_COLLECTION].create_index([("ipAddress", 1), ("createdAt", -1)])
        db[LOGIN_EVENTS_COLLECTION].create_index([("requestKey", 1), ("createdAt", -1)])

        db[AI_LOGIN_SCORES_COLLECTION].create_index([("scoredAt", -1)])
        db[AI_LOGIN_SCORES_COLLECTION].create_index([("userId", 1), ("scoredAt", -1)])
        db[AI_LOGIN_SCORES_COLLECTION].create_index([("result.riskLevel", 1), ("scoredAt", -1)])
        db[AI_LOGIN_SCORES_COLLECTION].create_index(
            [("requestKey", 1), ("model.version", 1)],
            unique=True,
            name="uniq_requestKey_modelVersion",
            partialFilterExpression={"requestKey": {"$type": "string"}},
        )

        db[TRANSACTION_EVENTS_COLLECTION].create_index([("createdAt", -1)])
        db[TRANSACTION_EVENTS_COLLECTION].create_index([("userId", 1), ("createdAt", -1)])
        db[TRANSACTION_EVENTS_COLLECTION].create_index([("userIdRaw", 1), ("createdAt", -1)])
        db[TRANSACTION_EVENTS_COLLECTION].create_index([("country", 1), ("createdAt", -1)])
        db[TRANSACTION_EVENTS_COLLECTION].create_index([("paymentMethod", 1), ("createdAt", -1)])
        db[TRANSACTION_EVENTS_COLLECTION].create_index([("requestKey", 1), ("createdAt", -1)])

        db[AI_TRANSACTION_SCORES_COLLECTION].create_index([("scoredAt", -1)])
        db[AI_TRANSACTION_SCORES_COLLECTION].create_index([("userId", 1), ("scoredAt", -1)])
        db[AI_TRANSACTION_SCORES_COLLECTION].create_index([("result.riskLevel", 1), ("scoredAt", -1)])
        db[AI_TRANSACTION_SCORES_COLLECTION].create_index(
            [("requestKey", 1), ("model.version", 1)],
            unique=True,
            name="uniq_tx_requestKey_modelVersion",
            partialFilterExpression={"requestKey": {"$type": "string"}},
        )

        db[AUDIT_LOGS_COLLECTION].create_index([("action", 1), ("createdAt", -1)])
        db[AUDIT_LOGS_COLLECTION].create_index([("userId", 1), ("createdAt", -1)])
        db[AUDIT_LOGS_COLLECTION].create_index([("ipAddress", 1), ("createdAt", -1)])
    except Exception as exc:
        app.state.mongo_error = f"{app.state.mongo_error}; index_error={exc}" if app.state.mongo_error else f"index_error={exc}"


def _close_mongo() -> None:
    client = getattr(app.state, "mongo_client", None)
    if client is not None:
        try:
            client.close()
        except Exception:
            pass
    app.state.mongo_client = None
    app.state.mongo_db = None


def _close_postgres() -> None:
    conn = getattr(app.state, "postgres_conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    app.state.postgres_conn = None


def _get_history_signals_from_postgres(event: LoginEvent) -> dict[str, Any]:
    event_ts = _as_utc(event.timestamp) or event.timestamp
    signals: dict[str, Any] = {
        "available": False,
        "history_count": 0,
        "has_success_history": False,
        "is_new_ip": False,
        "is_new_country": False,
        "is_new_device": False,
        "recent_attempts_10m": 0,
        "recent_attempts_1h": 0,
        "recent_failed_10m_db": 0,
        "last_country": None,
        "last_region": None,
        "last_city": None,
        "last_ip": None,
        "last_timestamp": None,
        "last_success_ip": None,
        "last_success_device": None,
        "last_success_timestamp": None,
        "different_ip_from_last_success": False,
        "different_device_from_last_success": False,
        "require_otp_sms": False,
        "otp_reason": None,
        "country_changed_recently": False,
        "off_hour_for_user": False,
        "private_ip": _is_private_or_loopback_ip(event.ip),
    }
    if not _postgres_ready():
        return signals

    try:
        history_rows = _pg_fetchall(
            """
            SELECT
              "ipAddress",
              "location",
              "userAgent",
              "success",
              "createdAt",
              "metadata"
            FROM "LoginEvent"
            WHERE "userId" = %s
              AND "createdAt" < %s
            ORDER BY "createdAt" DESC
            LIMIT 300
            """,
            (event.user_id, event_ts),
        )
    except Exception:
        return signals

    if not history_rows:
        return signals

    signals["available"] = True
    signals["history_count"] = len(history_rows)

    seen_ips: set[str] = set()
    seen_countries: set[str] = set()
    seen_devices: set[str] = set()
    successful_rows: list[dict[str, Any]] = []

    for row in history_rows:
        metadata = _normalize_json_field(row.get("metadata"))
        ip_value = str(row.get("ipAddress") or "").strip()
        country_value = str(metadata.get("country") or row.get("location") or "").strip().lower()
        device_value = _normalize_device(str(metadata.get("device") or row.get("userAgent") or ""))
        if ip_value:
            seen_ips.add(ip_value)
        if country_value:
            seen_countries.add(country_value)
        if device_value:
            seen_devices.add(device_value)
        if row.get("success"):
            successful_rows.append({"row": row, "metadata": metadata})

    signals["is_new_ip"] = event.ip not in seen_ips if seen_ips else False
    signals["is_new_country"] = event.country.strip().lower() not in seen_countries if seen_countries else False
    signals["is_new_device"] = _normalize_device(event.device) not in seen_devices if seen_devices else False

    latest = history_rows[0]
    latest_meta = _normalize_json_field(latest.get("metadata"))
    signals["last_country"] = latest_meta.get("country") or latest.get("location")
    signals["last_region"] = latest_meta.get("region")
    signals["last_city"] = latest_meta.get("city")
    signals["last_ip"] = latest.get("ipAddress")
    signals["last_timestamp"] = latest.get("createdAt")

    if successful_rows:
        last_success = successful_rows[0]
        row = last_success["row"]
        metadata = last_success["metadata"]
        last_success_ip = str(row.get("ipAddress") or "").strip() or None
        last_success_device = _normalize_device(
            str(metadata.get("device") or row.get("userAgent") or "")
        )
        signals["has_success_history"] = True
        signals["last_success_ip"] = last_success_ip
        signals["last_success_device"] = last_success_device or None
        signals["last_success_timestamp"] = row.get("createdAt")
        signals["different_ip_from_last_success"] = bool(last_success_ip and last_success_ip != event.ip)
        signals["different_device_from_last_success"] = bool(
            last_success_device and last_success_device != _normalize_device(event.device)
        )
        if signals["different_ip_from_last_success"] and signals["different_device_from_last_success"]:
            signals["require_otp_sms"] = True
            signals["otp_reason"] = "Different device and IP from the last successful login"

    recent_country_cutoff = event_ts.timestamp() - 24 * 3600
    ten_minutes_cutoff = event_ts.timestamp() - 10 * 60
    one_hour_cutoff = event_ts.timestamp() - 3600
    off_hours = {0, 1, 2, 3, 4, 5}

    for row in history_rows:
        created_at = _as_utc(row.get("createdAt"))
        if created_at is None:
            continue
        created_ts = created_at.timestamp()
        if created_ts >= ten_minutes_cutoff:
            signals["recent_attempts_10m"] += 1
            if not row.get("success"):
                signals["recent_failed_10m_db"] += 1
        if created_ts >= one_hour_cutoff:
            signals["recent_attempts_1h"] += 1
        if created_ts >= recent_country_cutoff:
            metadata = _normalize_json_field(row.get("metadata"))
            country_value = str(metadata.get("country") or row.get("location") or "").strip().upper()
            if country_value and country_value != event.country:
                signals["country_changed_recently"] = True
                break

    if event_ts.hour in off_hours and signals["history_count"] >= 5:
        usual_hours = [
            (_as_utc(row.get("createdAt")) or event_ts).hour
            for row in history_rows[:50]
            if row.get("createdAt") is not None
        ]
        off_hour_baseline = sum(1 for hour in usual_hours if hour in off_hours)
        signals["off_hour_for_user"] = off_hour_baseline <= max(1, len(usual_hours) // 5)

    return signals


def _persist_score_to_postgres(
    *,
    event: LoginEvent,
    features: np.ndarray,
    anomaly_score: float,
    raw_score: float,
    risk_level_base: str,
    risk_level_final: str,
    reasons: list[str],
    history_signals: dict[str, Any] | None = None,
    request_key: str,
) -> dict[str, Any]:
    if not _postgres_ready():
        return {"saved": False, "reason": "postgres_not_connected"}

    history_signals = history_signals or {}
    model_version = str(getattr(app.state, "model_version", None) or "unknown")
    existing = _pg_fetchone(
        """
        SELECT "id", "metadata"
        FROM "AuditLog"
        WHERE "actor" = 'ai-service'
          AND "action" = 'AI_LOGIN_SCORE'
          AND COALESCE("metadata"->>'requestKey', '') = %s
          AND COALESCE("metadata"->>'modelVersion', '') = %s
        ORDER BY "createdAt" DESC
        LIMIT 1
        """,
        (request_key, model_version),
    )
    if existing:
        metadata = _normalize_json_field(existing.get("metadata"))
        return {
            "saved": True,
            "reused": True,
            "login_event_id": metadata.get("loginEventId"),
            "ai_score_id": existing.get("id"),
        }

    login_event_id = event.login_event_id or f"ai-login-{request_key}"
    now_dt = _now_dt()
    login_metadata = {
        "country": event.country,
        "region": event.region,
        "city": event.city,
        "device": event.device,
        "failed10m": int(event.failed_10m),
        "botScore": float(event.bot_score),
        "requestId": event.request_id,
        "requestKey": request_key,
    }
    _pg_execute(
        """
        INSERT INTO "LoginEvent"
          ("id", "userId", "email", "ipAddress", "userAgent", "success", "anomaly", "location", "createdAt", "metadata")
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT ("id") DO UPDATE
        SET "anomaly" = EXCLUDED."anomaly",
            "metadata" = EXCLUDED."metadata"
        """,
        (
            login_event_id,
            event.user_id,
            event.email,
            event.ip,
            event.device,
            bool(event.success),
            float(anomaly_score),
            event.country,
            event.timestamp,
            _pg_jsonb(login_metadata),
        ),
    )

    details = _build_login_score_details(
        event=event,
        features=features,
        anomaly_score=anomaly_score,
        raw_score=raw_score,
        risk_level_base=risk_level_base,
        risk_level_final=risk_level_final,
        reasons=reasons,
        history_signals=history_signals,
        request_key=request_key,
        login_event_id=login_event_id,
    )
    metadata = {
        "recordType": "ai_login_score",
        "requestKey": request_key,
        "modelVersion": model_version,
        "modelSource": app.state.model_source,
        "riskLevel": risk_level_final,
        "monitoringOnly": True,
        "loginEventId": login_event_id,
    }
    audit_id = str(uuid4())
    _pg_execute(
        """
        INSERT INTO "AuditLog"
          ("id", "userId", "actor", "action", "details", "ipAddress", "createdAt", "metadata")
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            audit_id,
            event.user_id,
            "ai-service",
            "AI_LOGIN_SCORE",
            _pg_jsonb(details),
            event.ip,
            now_dt,
            _pg_jsonb(metadata),
        ),
    )
    _metric_inc("mongo_write_success_total")
    return {
        "saved": True,
        "reused": False,
        "login_event_id": login_event_id,
        "ai_score_id": audit_id,
    }


def _write_admin_alert_postgres(
    *,
    event: LoginEvent,
    risk_level: str,
    anomaly_score: float,
    reasons: list[str],
    login_event_id: str | None,
) -> dict[str, Any]:
    if not _postgres_ready():
        return {"sent": False, "reason": "postgres_not_connected"}
    if risk_level not in {"MEDIUM", "HIGH"}:
        return {"sent": False, "reason": "risk_below_alert_threshold"}

    details = {
        "riskLevel": risk_level,
        "anomalyScore": float(anomaly_score),
        "reasons": reasons,
        "loginEventId": login_event_id,
        "userIdRaw": event.user_id,
        "country": event.country,
        "region": event.region,
        "city": event.city,
        "ipAddress": event.ip,
        "modelVersion": getattr(app.state, "model_version", "unknown"),
        "modelSource": app.state.model_source,
        "monitoringOnly": True,
        "adminStatus": "PENDING_REVIEW",
        "aiDecision": AI_ACTION,
    }
    metadata = {
        "recordType": "ai_login_alert",
        "riskLevel": risk_level,
        "monitoringOnly": True,
        "loginEventId": login_event_id,
    }
    _pg_execute(
        """
        INSERT INTO "AuditLog"
          ("id", "userId", "actor", "action", "details", "ipAddress", "createdAt", "metadata")
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            str(uuid4()),
            event.user_id,
            "ai-service",
            "AI_LOGIN_ALERT",
            _pg_jsonb(details),
            event.ip,
            _now_dt(),
            _pg_jsonb(metadata),
        ),
    )
    _metric_inc("admin_alerts_sent_total")
    return {"sent": True}


def _persist_tx_score_to_postgres(
    *,
    event: TransactionEvent,
    features: np.ndarray,
    anomaly_score: float,
    raw_score: float,
    risk_level_base: str,
    risk_level_final: str,
    reasons: list[str],
    request_key: str,
) -> dict[str, Any]:
    if not _postgres_ready():
        return {"saved": False, "reason": "postgres_not_connected"}

    model_version = str(getattr(app.state, "tx_model_version", None) or "unknown")
    existing = _pg_fetchone(
        """
        SELECT "id", "metadata"
        FROM "AuditLog"
        WHERE "actor" = 'ai-service'
          AND "action" = 'AI_TRANSACTION_SCORE'
          AND COALESCE("metadata"->>'requestKey', '') = %s
          AND COALESCE("metadata"->>'modelVersion', '') = %s
        ORDER BY "createdAt" DESC
        LIMIT 1
        """,
        (request_key, model_version),
    )
    if existing:
        metadata = _normalize_json_field(existing.get("metadata"))
        return {
            "saved": True,
            "reused": True,
            "transaction_event_id": metadata.get("transactionEventId"),
            "ai_score_id": existing.get("id"),
        }

    transaction_event_id = event.transaction_event_id or event.transaction_id or f"ai-tx-{request_key}"
    details = _build_tx_score_details(
        event=event,
        features=features,
        anomaly_score=anomaly_score,
        raw_score=raw_score,
        risk_level_base=risk_level_base,
        risk_level_final=risk_level_final,
        reasons=reasons,
        request_key=request_key,
        transaction_event_id=transaction_event_id,
    )
    metadata = {
        "recordType": "ai_transaction_score",
        "requestKey": request_key,
        "modelVersion": model_version,
        "modelSource": app.state.tx_model_source,
        "riskLevel": risk_level_final,
        "monitoringOnly": True,
        "transactionEventId": transaction_event_id,
        "transactionId": event.transaction_id,
    }
    audit_id = str(uuid4())
    _pg_execute(
        """
        INSERT INTO "AuditLog"
          ("id", "userId", "actor", "action", "details", "ipAddress", "createdAt", "metadata")
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            audit_id,
            event.user_id,
            "ai-service",
            "AI_TRANSACTION_SCORE",
            _pg_jsonb(details),
            None,
            _now_dt(),
            _pg_jsonb(metadata),
        ),
    )
    _metric_inc("mongo_write_success_total")
    return {
        "saved": True,
        "reused": False,
        "transaction_event_id": transaction_event_id,
        "ai_score_id": audit_id,
    }


def _write_transaction_alert_postgres(
    *,
    event: TransactionEvent,
    risk_level: str,
    anomaly_score: float,
    reasons: list[str],
    transaction_event_id: str | None,
) -> dict[str, Any]:
    if not _postgres_ready():
        return {"sent": False, "reason": "postgres_not_connected"}
    if risk_level not in {"MEDIUM", "HIGH"}:
        return {"sent": False, "reason": "risk_below_alert_threshold"}

    details = {
        "riskLevel": risk_level,
        "anomalyScore": float(anomaly_score),
        "reasons": reasons,
        "transactionEventId": transaction_event_id,
        "transactionId": event.transaction_id,
        "userIdRaw": event.user_id,
        "country": event.country,
        "currency": event.currency,
        "amount": float(event.amount),
        "paymentMethod": event.payment_method,
        "merchantCategory": event.merchant_category,
        "modelVersion": getattr(app.state, "tx_model_version", "unknown"),
        "modelSource": app.state.tx_model_source,
        "monitoringOnly": True,
        "adminStatus": "PENDING_REVIEW",
        "aiDecision": AI_TX_ACTION,
    }
    metadata = {
        "recordType": "ai_transaction_alert",
        "riskLevel": risk_level,
        "monitoringOnly": True,
        "transactionEventId": transaction_event_id,
        "transactionId": event.transaction_id,
    }
    _pg_execute(
        """
        INSERT INTO "AuditLog"
          ("id", "userId", "actor", "action", "details", "ipAddress", "createdAt", "metadata")
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            str(uuid4()),
            event.user_id,
            "ai-service",
            "AI_TRANSACTION_ALERT",
            _pg_jsonb(details),
            None,
            _now_dt(),
            _pg_jsonb(metadata),
        ),
    )
    _metric_inc("admin_alerts_sent_total")
    return {"sent": True}


def _write_admin_alert(
    *,
    event: LoginEvent,
    risk_level: str,
    anomaly_score: float,
    reasons: list[str],
    login_event_id: str | None,
) -> dict[str, Any]:
    if _postgres_ready():
        return _write_admin_alert_postgres(
            event=event,
            risk_level=risk_level,
            anomaly_score=anomaly_score,
            reasons=reasons,
            login_event_id=login_event_id,
        )
    if not _mongo_ready():
        return {"sent": False, "reason": "storage_not_connected"}
    if risk_level not in {"MEDIUM", "HIGH"}:
        return {"sent": False, "reason": "risk_below_alert_threshold"}

    mongo_db = app.state.mongo_db
    user_oid = _safe_object_id(event.user_id)
    try:
        alert_doc = {
            "userId": user_oid,
            "actor": "ai-service",
            "action": "AI_LOGIN_ALERT",
            "details": {
                "riskLevel": risk_level,
                "anomalyScore": float(anomaly_score),
                "reasons": reasons,
                "loginEventId": _safe_object_id(login_event_id) if login_event_id else None,
                "userIdRaw": event.user_id,
                "country": event.country,
                "region": event.region,
                "city": event.city,
                "ipAddress": event.ip,
                "modelVersion": getattr(app.state, "model_version", "unknown"),
                "modelSource": app.state.model_source,
                "monitoringOnly": True,
                "adminStatus": "PENDING_REVIEW",
                "aiDecision": AI_ACTION,
            },
            "ipAddress": event.ip,
            "createdAt": _now_dt(),
        }
        mongo_db[AUDIT_LOGS_COLLECTION].insert_one(alert_doc)
        _metric_inc("admin_alerts_sent_total")
        return {"sent": True}
    except PyMongoError as exc:
        _metric_inc("admin_alerts_error_total")
        return {"sent": False, "reason": str(exc)}


def _persist_score_to_mongo(
    *,
    event: LoginEvent,
    features: np.ndarray,
    anomaly_score: float,
    raw_score: float,
    risk_level_base: str,
    risk_level_final: str,
    reasons: list[str],
    history_signals: dict[str, Any] | None = None,
    request_key: str,
) -> dict[str, Any]:
    if _postgres_ready():
        return _persist_score_to_postgres(
            event=event,
            features=features,
            anomaly_score=anomaly_score,
            raw_score=raw_score,
            risk_level_base=risk_level_base,
            risk_level_final=risk_level_final,
            reasons=reasons,
            history_signals=history_signals,
            request_key=request_key,
        )
    if not _mongo_ready():
        return {"saved": False, "reason": "storage_not_connected"}

    mongo_db = app.state.mongo_db
    now_dt = _now_dt()
    user_oid = _safe_object_id(event.user_id)
    login_event_oid = _safe_object_id(event.login_event_id)
    history_signals = history_signals or {}
    model_version = str(getattr(app.state, "model_version", None) or "unknown")

    ai_query = {"requestKey": request_key, "model.version": model_version}
    existing = mongo_db[AI_LOGIN_SCORES_COLLECTION].find_one(ai_query, {"_id": 1, "loginEventId": 1})
    if existing:
        return {
            "saved": True,
            "reused": True,
            "login_event_id": str(existing.get("loginEventId")) if existing.get("loginEventId") else None,
            "ai_score_id": str(existing.get("_id")),
        }

    try:
        if login_event_oid is None:
            login_doc = {
                "userId": user_oid,
                "userIdRaw": event.user_id,
                "email": event.email,
                "ipAddress": event.ip,
                "userAgent": event.device,
                "success": bool(event.success),
                "anomaly": float(anomaly_score),
                "location": event.country,
                "country": event.country,
                "region": event.region,
                "city": event.city,
                "device": event.device,
                "failed10m": int(event.failed_10m),
                "botScore": float(event.bot_score),
                "requestId": event.request_id,
                "requestKey": request_key,
                "createdAt": event.timestamp,
                "updatedAt": now_dt,
            }
            login_insert = mongo_db[LOGIN_EVENTS_COLLECTION].insert_one(login_doc)
            login_event_oid = login_insert.inserted_id

        ai_doc = {
            "requestKey": request_key,
            "requestId": event.request_id,
            "loginEventId": login_event_oid,
            "userId": user_oid,
            "inputSnapshot": {
                "timestamp": event.timestamp,
                "ipAddress": event.ip,
                "country": event.country,
                "region": event.region,
                "city": event.city,
                "device": event.device,
                "success": bool(event.success),
                "failed10m": int(event.failed_10m),
                "botScore": float(event.bot_score),
            },
            "features": _feature_vector_to_dict(_active_feature_names(), features),
            "result": {
                "anomalyScore": float(anomaly_score),
                "rawScore": float(raw_score),
                "riskLevel": risk_level_final,
                "riskLevelBase": risk_level_base,
                "riskLevelFinal": risk_level_final,
                "reasons": reasons,
                "monitoringOnly": True,
                "action": AI_ACTION,
                "requireOtpSms": bool(history_signals.get("require_otp_sms")),
                "otpChannel": "sms" if history_signals.get("require_otp_sms") else None,
                "otpReason": history_signals.get("otp_reason"),
            },
            "analysis": {
                "ip": {
                    "value": event.ip,
                    "isNewIpForUser": bool(history_signals.get("is_new_ip")),
                    "isPrivateOrLoopback": bool(history_signals.get("private_ip")),
                },
                "device": {
                    "value": event.device,
                    "isNewDeviceForUser": bool(history_signals.get("is_new_device")),
                },
                "location": {
                    "country": event.country,
                    "region": event.region,
                    "city": event.city,
                    "isNewCountryForUser": bool(history_signals.get("is_new_country")),
                    "countryChangedRecently": bool(history_signals.get("country_changed_recently")),
                    "lastCountry": history_signals.get("last_country"),
                },
                "time": {
                    "hourOfDay": int(event.timestamp.hour),
                    "dayOfWeek": int(event.timestamp.weekday()),
                    "offHourForUser": bool(history_signals.get("off_hour_for_user")),
                    "lastLoginAt": history_signals.get("last_timestamp"),
                },
                "session": {
                    "hasSuccessHistory": bool(history_signals.get("has_success_history")),
                    "lastSuccessIp": history_signals.get("last_success_ip"),
                    "lastSuccessDevice": history_signals.get("last_success_device"),
                    "lastSuccessTimestamp": history_signals.get("last_success_timestamp"),
                    "differentIpFromLastSuccess": bool(history_signals.get("different_ip_from_last_success")),
                    "differentDeviceFromLastSuccess": bool(history_signals.get("different_device_from_last_success")),
                    "requireOtpSms": bool(history_signals.get("require_otp_sms")),
                },
                "frequency": {
                    "failed10mInput": int(event.failed_10m),
                    "recentAttempts10m": int(history_signals.get("recent_attempts_10m", 0)),
                    "recentAttempts1h": int(history_signals.get("recent_attempts_1h", 0)),
                    "recentFailed10mDb": int(history_signals.get("recent_failed_10m_db", 0)),
                },
            },
            "model": {
                "name": "pyod_iforest",
                "version": model_version,
                "source": app.state.model_source,
                "trainedAt": getattr(app.state, "model_trained_at_dt", None),
            },
            "scoreStatus": "SUCCESS",
            "error": None,
            "scoredAt": now_dt,
            "createdAt": now_dt,
        }
        ai_insert = mongo_db[AI_LOGIN_SCORES_COLLECTION].insert_one(ai_doc)
        _metric_inc("mongo_write_success_total")
        return {
            "saved": True,
            "reused": False,
            "login_event_id": str(login_event_oid),
            "ai_score_id": str(ai_insert.inserted_id),
        }
    except DuplicateKeyError:
        existing = mongo_db[AI_LOGIN_SCORES_COLLECTION].find_one(ai_query, {"_id": 1, "loginEventId": 1})
        return {
            "saved": True,
            "reused": True,
            "login_event_id": str(existing.get("loginEventId")) if existing and existing.get("loginEventId") else None,
            "ai_score_id": str(existing.get("_id")) if existing and existing.get("_id") else None,
        }
    except PyMongoError as exc:
        _metric_inc("mongo_write_error_total")
        return {"saved": False, "reason": str(exc)}


def _write_transaction_alert(
    *,
    event: TransactionEvent,
    risk_level: str,
    anomaly_score: float,
    reasons: list[str],
    transaction_event_id: str | None,
) -> dict[str, Any]:
    if _postgres_ready():
        return _write_transaction_alert_postgres(
            event=event,
            risk_level=risk_level,
            anomaly_score=anomaly_score,
            reasons=reasons,
            transaction_event_id=transaction_event_id,
        )
    if not _mongo_ready():
        return {"sent": False, "reason": "storage_not_connected"}
    if risk_level not in {"MEDIUM", "HIGH"}:
        return {"sent": False, "reason": "risk_below_alert_threshold"}

    mongo_db = app.state.mongo_db
    user_oid = _safe_object_id(event.user_id)
    try:
        alert_doc = {
            "userId": user_oid,
            "actor": "ai-service",
            "action": "AI_TRANSACTION_ALERT",
            "details": {
                "riskLevel": risk_level,
                "anomalyScore": float(anomaly_score),
                "reasons": reasons,
                "transactionEventId": _safe_object_id(transaction_event_id) if transaction_event_id else None,
                "transactionId": event.transaction_id,
                "userIdRaw": event.user_id,
                "country": event.country,
                "currency": event.currency,
                "amount": float(event.amount),
                "paymentMethod": event.payment_method,
                "merchantCategory": event.merchant_category,
                "modelVersion": getattr(app.state, "tx_model_version", "unknown"),
                "modelSource": app.state.tx_model_source,
                "monitoringOnly": True,
                "adminStatus": "PENDING_REVIEW",
                "aiDecision": AI_TX_ACTION,
            },
            "ipAddress": None,
            "createdAt": _now_dt(),
        }
        mongo_db[AUDIT_LOGS_COLLECTION].insert_one(alert_doc)
        _metric_inc("admin_alerts_sent_total")
        return {"sent": True}
    except PyMongoError as exc:
        _metric_inc("admin_alerts_error_total")
        return {"sent": False, "reason": str(exc)}


def _persist_tx_score_to_mongo(
    *,
    event: TransactionEvent,
    features: np.ndarray,
    anomaly_score: float,
    raw_score: float,
    risk_level_base: str,
    risk_level_final: str,
    reasons: list[str],
    request_key: str,
) -> dict[str, Any]:
    if _postgres_ready():
        return _persist_tx_score_to_postgres(
            event=event,
            features=features,
            anomaly_score=anomaly_score,
            raw_score=raw_score,
            risk_level_base=risk_level_base,
            risk_level_final=risk_level_final,
            reasons=reasons,
            request_key=request_key,
        )
    if not _mongo_ready():
        return {"saved": False, "reason": "storage_not_connected"}

    mongo_db = app.state.mongo_db
    now_dt = _now_dt()
    user_oid = _safe_object_id(event.user_id)
    transaction_event_oid = _safe_object_id(event.transaction_event_id)
    model_version = str(getattr(app.state, "tx_model_version", None) or "unknown")

    ai_query = {"requestKey": request_key, "model.version": model_version}
    existing = mongo_db[AI_TRANSACTION_SCORES_COLLECTION].find_one(ai_query, {"_id": 1, "transactionEventId": 1})
    if existing:
        return {
            "saved": True,
            "reused": True,
            "transaction_event_id": str(existing.get("transactionEventId")) if existing.get("transactionEventId") else None,
            "ai_score_id": str(existing.get("_id")),
        }

    try:
        if transaction_event_oid is None:
            tx_doc = {
                "userId": user_oid,
                "userIdRaw": event.user_id,
                "transactionId": event.transaction_id,
                "amount": float(event.amount),
                "currency": event.currency,
                "country": event.country,
                "paymentMethod": event.payment_method,
                "merchantCategory": event.merchant_category,
                "device": event.device,
                "channel": event.channel,
                "failedTx24h": int(event.failed_tx_24h),
                "velocity1h": int(event.velocity_1h),
                "requestId": event.request_id,
                "requestKey": request_key,
                "createdAt": event.timestamp,
                "updatedAt": now_dt,
            }
            tx_insert = mongo_db[TRANSACTION_EVENTS_COLLECTION].insert_one(tx_doc)
            transaction_event_oid = tx_insert.inserted_id

        ai_doc = {
            "requestKey": request_key,
            "requestId": event.request_id,
            "transactionEventId": transaction_event_oid,
            "transactionId": event.transaction_id,
            "userId": user_oid,
            "inputSnapshot": {
                "timestamp": event.timestamp,
                "amount": float(event.amount),
                "currency": event.currency,
                "country": event.country,
                "paymentMethod": event.payment_method,
                "merchantCategory": event.merchant_category,
                "device": event.device,
                "channel": event.channel,
                "failedTx24h": int(event.failed_tx_24h),
                "velocity1h": int(event.velocity_1h),
            },
            "features": _feature_vector_to_dict(_active_tx_feature_names(), features),
            "result": {
                "anomalyScore": float(anomaly_score),
                "rawScore": float(raw_score),
                "riskLevel": risk_level_final,
                "riskLevelBase": risk_level_base,
                "riskLevelFinal": risk_level_final,
                "reasons": reasons,
                "monitoringOnly": True,
                "action": AI_TX_ACTION,
            },
            "model": {
                "name": "pyod_iforest",
                "version": model_version,
                "source": app.state.tx_model_source,
                "trainedAt": getattr(app.state, "tx_model_trained_at_dt", None),
            },
            "scoreStatus": "SUCCESS",
            "error": None,
            "scoredAt": now_dt,
            "createdAt": now_dt,
        }
        ai_insert = mongo_db[AI_TRANSACTION_SCORES_COLLECTION].insert_one(ai_doc)
        _metric_inc("mongo_write_success_total")
        return {
            "saved": True,
            "reused": False,
            "transaction_event_id": str(transaction_event_oid),
            "ai_score_id": str(ai_insert.inserted_id),
        }
    except DuplicateKeyError:
        existing = mongo_db[AI_TRANSACTION_SCORES_COLLECTION].find_one(ai_query, {"_id": 1, "transactionEventId": 1})
        return {
            "saved": True,
            "reused": True,
            "transaction_event_id": (
                str(existing.get("transactionEventId")) if existing and existing.get("transactionEventId") else None
            ),
            "ai_score_id": str(existing.get("_id")) if existing and existing.get("_id") else None,
        }
    except PyMongoError as exc:
        _metric_inc("mongo_write_error_total")
        return {"saved": False, "reason": str(exc)}


def _startup_app() -> None:
    app.state.model = None
    app.state.thresholds = None
    app.state.feature_mean = None
    app.state.feature_std = None
    app.state.countries = set()
    app.state.devices = set()
    app.state.trained_at = None
    app.state.model_trained_at_dt = None
    app.state.train_size = 0
    app.state.model_source = "none"
    app.state.model_version = "unknown"
    app.state.model_path = None
    app.state.metadata_path = None
    app.state.feature_names = list(FEATURE_NAMES)
    app.state.load_error = None
    app.state.tx_model = None
    app.state.tx_thresholds = None
    app.state.tx_feature_mean = None
    app.state.tx_feature_std = None
    app.state.tx_countries = set()
    app.state.tx_payment_methods = set()
    app.state.tx_merchant_categories = set()
    app.state.tx_trained_at = None
    app.state.tx_model_trained_at_dt = None
    app.state.tx_train_size = 0
    app.state.tx_model_source = "none"
    app.state.tx_model_version = "unknown"
    app.state.tx_model_path = None
    app.state.tx_metadata_path = None
    app.state.tx_feature_names = list(TX_FEATURE_NAMES)
    app.state.tx_feedback_profile = {}
    app.state.tx_load_error = None
    app.state.mongo_client = None
    app.state.mongo_db = None
    app.state.mongo_db_name = os.getenv("MONGODB_DB")
    app.state.mongo_error = None
    app.state.postgres_conn = None
    app.state.postgres_db = os.getenv("DATABASE_URL")
    app.state.postgres_error = None
    app.state.metrics = {key: 0.0 for key in METRICS_KEYS}
    _try_load_persisted_model()
    _try_load_persisted_tx_model()
    _init_postgres()
    _init_mongo()


def _shutdown_app() -> None:
    _close_postgres()
    _close_mongo()


@asynccontextmanager
async def _app_lifespan(_: FastAPI):
    _startup_app()
    try:
        yield
    finally:
        _shutdown_app()


app.router.lifespan_context = _app_lifespan


@app.get("/ui", response_class=HTMLResponse)
def test_ui():
    return TEST_UI_HTML


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ai",
        "timestamp": _now_iso(),
        "auth_enabled": _auth_enabled(),
        "auth_mode": _auth_mode(),
        "model_loaded": _state_ready(),
        "model_source": app.state.model_source,
        "model_version": getattr(app.state, "model_version", "unknown"),
        "tx_model_loaded": _tx_state_ready(),
        "tx_model_source": app.state.tx_model_source,
        "tx_model_version": getattr(app.state, "tx_model_version", "unknown"),
        "postgres_connected": _postgres_ready(),
        "postgres_db": bool(getattr(app.state, "postgres_db", None)),
        "storage_backend": _storage_backend(),
        "mongo_connected": _mongo_ready(),
        "mongo_db": getattr(app.state, "mongo_db_name", None),
    }


@app.get("/ai/status")
def status(_: None = Depends(_require_api_key)):
    return {
        "model_loaded": _state_ready(),
        "model_source": app.state.model_source,
        "model_version": getattr(app.state, "model_version", "unknown"),
        "model_path": getattr(app.state, "model_path", None),
        "metadata_path": getattr(app.state, "metadata_path", None),
        "trained_at": app.state.trained_at,
        "train_size": app.state.train_size,
        "features": _active_feature_names(),
        "load_error": app.state.load_error,
        "tx_model_loaded": _tx_state_ready(),
        "tx_model_source": app.state.tx_model_source,
        "tx_model_version": getattr(app.state, "tx_model_version", "unknown"),
        "tx_model_path": getattr(app.state, "tx_model_path", None),
        "tx_metadata_path": getattr(app.state, "tx_metadata_path", None),
        "tx_trained_at": app.state.tx_trained_at,
        "tx_train_size": app.state.tx_train_size,
        "tx_features": _active_tx_feature_names(),
        "tx_feedback_profile": getattr(app.state, "tx_feedback_profile", {}) or {},
        "tx_load_error": app.state.tx_load_error,
        "postgres_connected": _postgres_ready(),
        "postgres_db": bool(getattr(app.state, "postgres_db", None)),
        "postgres_error": getattr(app.state, "postgres_error", None),
        "storage_backend": _storage_backend(),
        "mongo_connected": _mongo_ready(),
        "mongo_db": getattr(app.state, "mongo_db_name", None),
        "mongo_error": getattr(app.state, "mongo_error", None),
        "auth_enabled": _auth_enabled(),
        "auth_mode": _auth_mode(),
    }


@app.get("/ai/metrics")
def metrics(_: None = Depends(_require_api_key)):
    requests = app.state.metrics["score_requests_total"]
    tx_requests = app.state.metrics["tx_score_requests_total"]
    avg_latency = (app.state.metrics["score_latency_ms_total"] / requests) if requests > 0 else 0.0
    avg_tx_latency = (app.state.metrics["tx_score_latency_ms_total"] / tx_requests) if tx_requests > 0 else 0.0
    return {
        "metrics": app.state.metrics,
        "avg_score_latency_ms": round(avg_latency, 3),
        "avg_tx_score_latency_ms": round(avg_tx_latency, 3),
        "generated_at": _now_iso(),
    }


@app.get("/ai/admin/alerts")
def admin_alerts(limit: int = 50, _: None = Depends(_require_api_key)):
    if _postgres_ready():
        capped = max(1, min(limit, 200))
        rows = _pg_fetchall(
            """
            SELECT "id", "userId", "actor", "action", "details", "ipAddress", "createdAt"
            FROM "AuditLog"
            WHERE "action" IN ('AI_LOGIN_ALERT', 'AI_TRANSACTION_ALERT')
            ORDER BY "createdAt" DESC
            LIMIT %s
            """,
            (capped,),
        )
        alerts: list[dict[str, Any]] = []
        for item in rows:
            alerts.append(
                {
                    "_id": item.get("id"),
                    "userId": item.get("userId"),
                    "actor": item.get("actor"),
                    "action": item.get("action"),
                    "details": _normalize_json_field(item.get("details")),
                    "ipAddress": item.get("ipAddress"),
                    "createdAt": _to_json_value(item.get("createdAt")),
                }
            )
        return {"alerts": alerts, "count": len(alerts)}
    if not _mongo_ready():
        return {"alerts": [], "reason": "storage_not_connected"}
    capped = max(1, min(limit, 200))
    db = app.state.mongo_db
    try:
        cursor = (
            db[AUDIT_LOGS_COLLECTION]
            .find({"action": {"$in": ["AI_LOGIN_ALERT", "AI_TRANSACTION_ALERT"]}})
            .sort("createdAt", -1)
            .limit(capped)
        )
        alerts: list[dict[str, Any]] = []
        for item in cursor:
            item["_id"] = str(item["_id"])
            if item.get("userId") is not None:
                item["userId"] = str(item["userId"])
            details = item.get("details")
            if isinstance(details, dict) and details.get("loginEventId") is not None:
                details["loginEventId"] = str(details["loginEventId"])
            if isinstance(details, dict) and details.get("transactionEventId") is not None:
                details["transactionEventId"] = str(details["transactionEventId"])
            alerts.append(item)
        return {"alerts": alerts, "count": len(alerts)}
    except PyMongoError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load alerts: {exc}")


@app.get("/ai/admin/stats")
def admin_stats(hours: int = 24, _: None = Depends(_require_api_key)):
    if _postgres_ready():
        safe_hours = max(1, min(hours, 24 * 30))
        cutoff = _now_dt().timestamp() - safe_hours * 3600
        cutoff_dt = datetime.fromtimestamp(cutoff, tz=timezone.utc)
        rows = _pg_fetchall(
            """
            SELECT
              "action",
              UPPER(COALESCE("metadata"->>'riskLevel', 'LOW')) AS "riskLevel",
              COUNT(*)::int AS "count"
            FROM "AuditLog"
            WHERE "actor" = 'ai-service'
              AND "action" IN ('AI_LOGIN_SCORE', 'AI_TRANSACTION_SCORE')
              AND "createdAt" >= %s
            GROUP BY "action", UPPER(COALESCE("metadata"->>'riskLevel', 'LOW'))
            """,
            (cutoff_dt,),
        )
        login_risk = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        tx_risk = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for row in rows:
            target = login_risk if row.get("action") == "AI_LOGIN_SCORE" else tx_risk
            risk = str(row.get("riskLevel") or "LOW").upper()
            if risk in target:
                target[risk] = int(row.get("count") or 0)
        combined_risk = {
            "LOW": int(login_risk["LOW"] + tx_risk["LOW"]),
            "MEDIUM": int(login_risk["MEDIUM"] + tx_risk["MEDIUM"]),
            "HIGH": int(login_risk["HIGH"] + tx_risk["HIGH"]),
        }
        return {
            "window_hours": safe_hours,
            "risk_counts": login_risk,
            "tx_risk_counts": tx_risk,
            "combined_risk_counts": combined_risk,
        }
    if not _mongo_ready():
        return {"stats": {}, "reason": "storage_not_connected"}
    safe_hours = max(1, min(hours, 24 * 30))
    cutoff = _now_dt().timestamp() - safe_hours * 3600
    cutoff_dt = datetime.fromtimestamp(cutoff, tz=timezone.utc)
    db = app.state.mongo_db
    try:
        login_risk = _aggregate_risk_counts(db, AI_LOGIN_SCORES_COLLECTION, cutoff_dt)
        tx_risk = _aggregate_risk_counts(db, AI_TRANSACTION_SCORES_COLLECTION, cutoff_dt)
        combined_risk = {
            "LOW": int(login_risk["LOW"] + tx_risk["LOW"]),
            "MEDIUM": int(login_risk["MEDIUM"] + tx_risk["MEDIUM"]),
            "HIGH": int(login_risk["HIGH"] + tx_risk["HIGH"]),
        }
        return {
            "window_hours": safe_hours,
            "risk_counts": login_risk,
            "tx_risk_counts": tx_risk,
            "combined_risk_counts": combined_risk,
        }
    except PyMongoError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load stats: {exc}")


@app.post("/ai/reload-model")
def reload_model(_: None = Depends(_require_api_key)):
    _try_load_persisted_model()
    _try_load_persisted_tx_model()
    return {
        "status": "reloaded",
        "model_loaded": _state_ready(),
        "model_source": app.state.model_source,
        "model_version": app.state.model_version,
        "model_path": app.state.model_path,
        "metadata_path": app.state.metadata_path,
        "load_error": app.state.load_error,
        "tx_model_loaded": _tx_state_ready(),
        "tx_model_source": app.state.tx_model_source,
        "tx_model_version": app.state.tx_model_version,
        "tx_model_path": app.state.tx_model_path,
        "tx_metadata_path": app.state.tx_metadata_path,
        "tx_load_error": app.state.tx_load_error,
    }


@app.post("/ai/train")
def train(
    payload: TrainRequest,
    persist: bool = False,
    promote: bool = False,
    model_version: str | None = None,
    _: None = Depends(_require_api_key),
):
    normalized_events = [_normalize_login_event(event) for event in payload.events]
    training_rows = build_login_training_feature_rows(normalized_events, FEATURE_NAMES)
    normal_events = [event for event, _, _ in training_rows if int(event.success) == 1]
    if len(normal_events) < 10:
        raise HTTPException(
            status_code=400,
            detail="At least 10 normal login events (success=1) are required for training.",
        )

    feature_matrix = np.vstack([features for event, features, _ in training_rows if int(event.success) == 1])
    model, thresholds, feature_mean, feature_std = _fit_iforest(feature_matrix)
    countries = {event.country.strip().lower() for event in normal_events}
    devices = {_normalize_device(event.device) for event in normal_events}

    _set_model_state(
        model=model,
        thresholds=thresholds,
        feature_mean=feature_mean,
        feature_std=feature_std,
        countries=countries,
        devices=devices,
        trained_at=_now_iso(),
        train_size=len(normal_events),
        source="runtime:/ai/train",
        model_version=model_version or f"runtime_iforest_{_now_dt().strftime('%Y%m%d_%H%M%S')}",
        model_path=None,
        metadata_path=None,
        feature_names=FEATURE_NAMES,
    )
    app.state.model_trained_at_dt = _parse_iso_datetime(app.state.trained_at)
    artifact = _persist_login_model_artifacts(promote=promote) if persist else {"saved": False}

    return {
        "status": "trained",
        "trained_at": app.state.trained_at,
        "model_version": app.state.model_version,
        "train_size": app.state.train_size,
        "features": _active_feature_names(),
        "model_source": app.state.model_source,
        "artifact": artifact,
    }


@app.post("/ai/score")
def score(
    event: LoginEvent,
    _: None = Depends(_require_api_key),
    x_idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
):
    start = time.perf_counter()
    _metric_inc("score_requests_total")

    if not _state_ready():
        _metric_inc("score_errors_total")
        raise HTTPException(
            status_code=503,
            detail="Login model is not trained yet. Train via /ai/train or load an artifact first.",
        )

    event = _normalize_login_event(event)
    request_key = _resolve_request_key(event, x_idempotency_key)
    history_signals = _get_history_signals(event)
    features = _build_features(event, history_signals)
    score_value = float(app.state.model.decision_function(features.reshape(1, -1))[0])
    anomaly_score = _scaled_score(
        score_value,
        float(app.state.thresholds["score_min"]),
        float(app.state.thresholds["score_max"]),
    )
    risk_level_base = _score_to_level(score_value, app.state.thresholds)
    risk_level = risk_level_base
    risk_level = _adjust_risk_level(risk_level, event, history_signals)
    reasons = _build_reasons(event, features, history_signals)
    try:
        mongo_persist = _persist_score_to_mongo(
            event=event,
            features=features,
            anomaly_score=anomaly_score,
            raw_score=score_value,
            risk_level_base=risk_level_base,
            risk_level_final=risk_level,
            reasons=reasons,
            history_signals=history_signals,
            request_key=request_key,
        )
    except Exception as exc:
        _metric_inc("mongo_write_error_total")
        mongo_persist = {"saved": False, "reason": f"persist_error:{exc}"}

    try:
        admin_alert = _write_admin_alert(
            event=event,
            risk_level=risk_level,
            anomaly_score=anomaly_score,
            reasons=reasons,
            login_event_id=mongo_persist.get("login_event_id"),
        )
    except Exception as exc:
        _metric_inc("admin_alerts_error_total")
        admin_alert = {"sent": False, "reason": f"alert_error:{exc}"}
    if risk_level == "LOW":
        _metric_inc("risk_low_total")
    elif risk_level == "MEDIUM":
        _metric_inc("risk_medium_total")
    else:
        _metric_inc("risk_high_total")
    _metric_inc("score_success_total")
    _metric_inc("score_latency_ms_total", (time.perf_counter() - start) * 1000.0)

    return {
        "anomaly_score": anomaly_score,
        "raw_score": score_value,
        "risk_level_base": risk_level_base,
        "risk_level": risk_level,
        "reasons": reasons,
        "monitoring_only": True,
        "action": AI_ACTION,
        "require_otp_sms": bool(history_signals.get("require_otp_sms")),
        "otp_channel": "sms" if history_signals.get("require_otp_sms") else None,
        "otp_reason": history_signals.get("otp_reason"),
        "model_source": app.state.model_source,
        "model_version": getattr(app.state, "model_version", "unknown"),
        "request_key": request_key,
        "analysis_signals": {
            "ip": {
                "is_new_ip": bool(history_signals.get("is_new_ip")),
                "private_or_loopback": bool(history_signals.get("private_ip")),
            },
            "device": {"is_new_device": bool(history_signals.get("is_new_device"))},
            "location": {
                "is_new_country": bool(history_signals.get("is_new_country")),
                "country_changed_recently": bool(history_signals.get("country_changed_recently")),
                "last_country": history_signals.get("last_country"),
            },
            "session": {
                "has_success_history": bool(history_signals.get("has_success_history")),
                "last_success_ip": history_signals.get("last_success_ip"),
                "last_success_device": history_signals.get("last_success_device"),
                "last_success_timestamp": history_signals.get("last_success_timestamp"),
                "different_ip_from_last_success": bool(history_signals.get("different_ip_from_last_success")),
                "different_device_from_last_success": bool(history_signals.get("different_device_from_last_success")),
                "require_otp_sms": bool(history_signals.get("require_otp_sms")),
            },
            "time": {"off_hour_for_user": bool(history_signals.get("off_hour_for_user"))},
            "frequency": {
                "recent_attempts_10m": int(history_signals.get("recent_attempts_10m", 0)),
                "recent_attempts_1h": int(history_signals.get("recent_attempts_1h", 0)),
                "recent_failed_10m_db": int(history_signals.get("recent_failed_10m_db", 0)),
            },
        },
        "mongo_persist": mongo_persist,
        "admin_alert": admin_alert,
    }


@app.post("/ai/tx/train")
def train_transaction(
    payload: TrainTransactionRequest,
    persist: bool = False,
    promote: bool = False,
    model_version: str | None = None,
    _: None = Depends(_require_api_key),
):
    normalized_events = [_normalize_transaction_event(event) for event in payload.events]
    if len(normalized_events) < 10:
        raise HTTPException(
            status_code=400,
            detail="At least 10 transactions are required for transaction model training.",
        )

    feature_matrix = np.vstack([build_transaction_features(event, feature_names=TX_FEATURE_NAMES) for event in normalized_events])
    model, thresholds, feature_mean, feature_std = _fit_iforest(feature_matrix)
    countries = {event.country.strip().lower() for event in normalized_events if event.country}
    payment_methods = {event.payment_method for event in normalized_events if event.payment_method}
    merchant_categories = {event.merchant_category for event in normalized_events if event.merchant_category}

    _set_tx_model_state(
        model=model,
        thresholds=thresholds,
        feature_mean=feature_mean,
        feature_std=feature_std,
        countries=countries,
        payment_methods=payment_methods,
        merchant_categories=merchant_categories,
        trained_at=_now_iso(),
        train_size=len(normalized_events),
        source="runtime:/ai/tx/train",
        model_version=model_version or f"runtime_tx_iforest_{_now_dt().strftime('%Y%m%d_%H%M%S')}",
        model_path=None,
        metadata_path=None,
        feature_names=TX_FEATURE_NAMES,
    )
    app.state.tx_model_trained_at_dt = _parse_iso_datetime(app.state.tx_trained_at)
    artifact = _persist_tx_model_artifacts(promote=promote) if persist else {"saved": False}

    return {
        "status": "trained",
        "trained_at": app.state.tx_trained_at,
        "model_version": app.state.tx_model_version,
        "train_size": app.state.tx_train_size,
        "features": _active_tx_feature_names(),
        "model_source": app.state.tx_model_source,
        "artifact": artifact,
    }


@app.post("/ai/tx/score")
def score_transaction(
    event: TransactionEvent,
    _: None = Depends(_require_api_key),
    x_idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
):
    start = time.perf_counter()
    _metric_inc("tx_score_requests_total")

    if not _tx_state_ready():
        _metric_inc("tx_score_errors_total")
        raise HTTPException(
            status_code=503,
            detail="Transaction model is not trained yet. Train via /ai/tx/train or load an artifact first.",
        )

    event = _normalize_transaction_event(event)
    request_key = _resolve_tx_request_key(event, x_idempotency_key)
    features = _build_tx_features(event)
    score_value = float(app.state.tx_model.decision_function(features.reshape(1, -1))[0])
    anomaly_score = _scaled_score(
        score_value,
        float(app.state.tx_thresholds["score_min"]),
        float(app.state.tx_thresholds["score_max"]),
    )
    risk_level_base = _score_to_level(score_value, app.state.tx_thresholds)
    risk_level = _adjust_tx_risk_level(risk_level_base, event)
    reasons = _build_tx_reasons(event, features)
    try:
        mongo_persist = _persist_tx_score_to_mongo(
            event=event,
            features=features,
            anomaly_score=anomaly_score,
            raw_score=score_value,
            risk_level_base=risk_level_base,
            risk_level_final=risk_level,
            reasons=reasons,
            request_key=request_key,
        )
    except Exception as exc:
        _metric_inc("mongo_write_error_total")
        mongo_persist = {"saved": False, "reason": f"persist_error:{exc}"}

    try:
        admin_alert = _write_transaction_alert(
            event=event,
            risk_level=risk_level,
            anomaly_score=anomaly_score,
            reasons=reasons,
            transaction_event_id=mongo_persist.get("transaction_event_id"),
        )
    except Exception as exc:
        _metric_inc("admin_alerts_error_total")
        admin_alert = {"sent": False, "reason": f"alert_error:{exc}"}

    if risk_level == "LOW":
        _metric_inc("tx_risk_low_total")
    elif risk_level == "MEDIUM":
        _metric_inc("tx_risk_medium_total")
    else:
        _metric_inc("tx_risk_high_total")
    _metric_inc("tx_score_success_total")
    _metric_inc("tx_score_latency_ms_total", (time.perf_counter() - start) * 1000.0)

    return {
        "anomaly_score": anomaly_score,
        "raw_score": score_value,
        "risk_level_base": risk_level_base,
        "risk_level": risk_level,
        "reasons": reasons,
        "monitoring_only": True,
        "action": AI_TX_ACTION,
        "model_source": app.state.tx_model_source,
        "model_version": getattr(app.state, "tx_model_version", "unknown"),
        "request_key": request_key,
        "analysis_signals": {
            "amount": float(event.amount),
            "currency": event.currency,
            "country": event.country,
            "payment_method": event.payment_method,
            "merchant_category": event.merchant_category,
            "failed_tx_24h": int(event.failed_tx_24h),
            "velocity_1h": int(event.velocity_1h),
            "daily_spend_avg_30d": float(event.daily_spend_avg_30d),
            "today_spend_before": float(event.today_spend_before),
            "projected_daily_spend": float(event.projected_daily_spend),
            "balance_before": float(event.balance_before),
            "remaining_balance": float(event.remaining_balance),
        },
        "mongo_persist": mongo_persist,
        "admin_alert": admin_alert,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
