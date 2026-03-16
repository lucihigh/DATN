import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
import psycopg

AI_SERVICE_ROOT = Path(__file__).resolve().parents[1]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from app.login_model import LoginEvent, TrainRequest
from app.main import app, _set_tx_model_state, _shutdown_app, _startup_app, _persist_tx_model_artifacts, train, train_transaction
from app.transaction_model import TrainTransactionRequest, TransactionEvent


def _load_env_file() -> dict[str, str]:
    env_path = Path(__file__).resolve().parents[3] / ".env"
    loaded: dict[str, str] = {}
    if not env_path.exists():
        return loaded
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        loaded[key.strip()] = value.strip()
    return loaded


def _read_json_field(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _build_login_events_from_postgres(database_url: str, max_rows: int = 1000) -> list[dict[str, Any]]:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT "userId", "email", "ipAddress", "location", "userAgent", "success", "createdAt", "metadata"
                FROM "LoginEvent"
                WHERE "userId" IS NOT NULL
                ORDER BY "createdAt" ASC
                LIMIT %s
                """,
                (max_rows,),
            )
            rows = cur.fetchall()

    events: list[dict[str, Any]] = []
    for user_id, email, ip_address, location, user_agent, success, created_at, metadata_raw in rows:
        metadata = _read_json_field(metadata_raw)
        country = str(metadata.get("country") or location or "UNK").strip() or "UNK"
        device = str(metadata.get("device") or user_agent or "unknown").strip() or "unknown"
        event = {
            "user_id": str(user_id),
            "timestamp": created_at.astimezone(timezone.utc).isoformat(),
            "ip": str(ip_address or "127.0.0.1"),
            "country": country,
            "device": device,
            "success": 1 if bool(success) else 0,
            "failed_10m": int(metadata.get("failed10m") or 0),
            "bot_score": float(metadata.get("botScore") or 0.05),
            "email": str(email or ""),
            "region": metadata.get("region"),
            "city": metadata.get("city"),
        }
        events.append(event)
    return events


def _augment_login_events(events: list[dict[str, Any]], target_rows: int = 180) -> list[dict[str, Any]]:
    if len(events) >= target_rows:
        return events

    base_now = datetime.now(timezone.utc)
    augmented = list(events)
    user_ids = [event["user_id"] for event in events if event.get("user_id")] or ["demo-user"]
    devices = [event["device"] for event in events if event.get("device")] or ["Mozilla/5.0 Chrome"]
    countries = [event["country"] for event in events if event.get("country")] or ["VN"]

    for index in range(target_rows - len(events)):
        ts = base_now - timedelta(minutes=7 * index)
        augmented.append(
            {
                "user_id": user_ids[index % len(user_ids)],
                "timestamp": ts.isoformat(),
                "ip": f"10.0.0.{(index % 50) + 10}",
                "country": countries[index % len(countries)],
                "device": devices[index % len(devices)],
                "success": 1,
                "failed_10m": 0,
                "bot_score": 0.04 + ((index % 5) * 0.01),
            }
        )
    augmented.sort(key=lambda item: item["timestamp"])
    return augmented


def _generate_benign_tx_events(rows: int = 180) -> list[dict[str, Any]]:
    random.seed(42)
    base_now = datetime.now(timezone.utc)
    users = [
        {"user_id": "wallet-user-1", "country": "US", "avg_daily": 180.0},
        {"user_id": "wallet-user-2", "country": "VN", "avg_daily": 220.0},
        {"user_id": "wallet-user-3", "country": "SG", "avg_daily": 140.0},
        {"user_id": "wallet-user-4", "country": "US", "avg_daily": 260.0},
    ]
    events: list[dict[str, Any]] = []
    for index in range(rows):
        user = users[index % len(users)]
        timestamp = base_now - timedelta(minutes=18 * index)
        avg_daily = user["avg_daily"] + float((index % 6) * 15)
        today_spend_before = max(0.0, avg_daily * random.uniform(0.05, 0.7))
        amount = max(15.0, avg_daily * random.uniform(0.12, 0.45))
        projected_daily_spend = today_spend_before + amount
        events.append(
            {
                "user_id": user["user_id"],
                "transaction_id": f"bootstrap-tx-{index}",
                "timestamp": timestamp.isoformat(),
                "amount": round(amount, 2),
                "currency": "USD",
                "country": user["country"],
                "payment_method": "wallet_balance",
                "merchant_category": "p2p_transfer",
                "device": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36",
                "channel": "web",
                "failed_tx_24h": 0 if index % 11 else 1,
                "velocity_1h": 1 if index % 5 else 2,
                "daily_spend_avg_30d": round(avg_daily, 2),
                "today_spend_before": round(today_spend_before, 2),
                "projected_daily_spend": round(projected_daily_spend, 2),
                "balance_before": round(max(projected_daily_spend * random.uniform(1.2, 2.0), amount + 150.0), 2),
                "remaining_balance": round(
                    max(projected_daily_spend * random.uniform(0.4, 1.2), 75.0),
                    2,
                ),
            }
        )
    events.sort(key=lambda item: item["timestamp"])
    return events


def _safe_number(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
        return parsed if parsed == parsed else default
    except Exception:
        return default


def _extract_request_key(details: dict[str, Any], metadata: dict[str, Any]) -> str:
    for candidate in [
        details.get("requestKey"),
        metadata.get("requestKey"),
        _read_json_field(metadata.get("transferAdvisory")).get("requestKey"),
    ]:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def _build_tx_events_from_audit_scores(database_url: str, max_rows: int = 2000) -> list[dict[str, Any]]:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT "userId", "createdAt", "details", "metadata"
                FROM "AuditLog"
                WHERE "actor" = 'ai-service'
                  AND "action" = 'AI_TRANSACTION_SCORE'
                ORDER BY "createdAt" ASC
                LIMIT %s
                """,
                (max_rows,),
            )
            rows = cur.fetchall()

    events: list[dict[str, Any]] = []
    for user_id, created_at, details_raw, metadata_raw in rows:
        details = _read_json_field(details_raw)
        metadata = _read_json_field(metadata_raw)
        input_snapshot = _read_json_field(details.get("inputSnapshot"))
        result = _read_json_field(details.get("result"))
        request_key = _extract_request_key(details, metadata)
        timestamp = input_snapshot.get("timestamp") or created_at
        event = {
            "request_key": request_key,
            "user_id": str(input_snapshot.get("userId") or user_id or ""),
            "transaction_id": str(
                details.get("transactionId")
                or metadata.get("transactionId")
                or request_key
                or f"audit-tx-{len(events)}"
            ),
            "timestamp": timestamp.astimezone(timezone.utc).isoformat()
            if isinstance(timestamp, datetime)
            else str(timestamp),
            "amount": round(_safe_number(input_snapshot.get("amount")), 2),
            "currency": str(input_snapshot.get("currency") or "USD"),
            "country": str(input_snapshot.get("country") or "UNK"),
            "payment_method": str(input_snapshot.get("paymentMethod") or "wallet_balance"),
            "merchant_category": str(input_snapshot.get("merchantCategory") or "p2p_transfer"),
            "device": str(input_snapshot.get("device") or ""),
            "channel": input_snapshot.get("channel") or "web",
            "failed_tx_24h": int(_safe_number(input_snapshot.get("failedTx24h"))),
            "velocity_1h": int(_safe_number(input_snapshot.get("velocity1h"))),
            "daily_spend_avg_30d": round(_safe_number(input_snapshot.get("dailySpendAvg30d")), 2),
            "today_spend_before": round(_safe_number(input_snapshot.get("todaySpendBefore")), 2),
            "projected_daily_spend": round(_safe_number(input_snapshot.get("projectedDailySpend")), 2),
            "balance_before": round(_safe_number(input_snapshot.get("balanceBefore")), 2),
            "remaining_balance": round(_safe_number(input_snapshot.get("remainingBalance")), 2),
            "risk_level": str(result.get("riskLevel") or "low").lower(),
        }
        if event["user_id"] and event["amount"] > 0:
            events.append(event)
    return events


def _load_transfer_feedback(database_url: str, max_rows: int = 5000) -> dict[str, dict[str, Any]]:
    actions = (
        "TRANSFER_ADVISORY_PRESENTED",
        "TRANSFER_ADVISORY_ACKNOWLEDGED",
        "TRANSFER_ADVISORY_DISMISSED",
        "TRANSFER_OTP_VERIFIED",
    )
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT "action", "details", "metadata", "createdAt"
                FROM "AuditLog"
                WHERE "action" = ANY(%s)
                ORDER BY "createdAt" ASC
                LIMIT %s
                """,
                (list(actions), max_rows),
            )
            rows = cur.fetchall()

    feedback: dict[str, dict[str, Any]] = {}
    for action, details_raw, metadata_raw, created_at in rows:
        details = _read_json_field(details_raw)
        metadata = _read_json_field(metadata_raw)
        transfer_advisory = _read_json_field(metadata.get("transferAdvisory"))
        request_key = (
            str(metadata.get("requestKey") or transfer_advisory.get("requestKey") or "").strip()
        )
        if not request_key:
            continue
        item = feedback.setdefault(
            request_key,
            {
                "presented": False,
                "acknowledged": False,
                "dismissed": False,
                "verified": False,
                "lastActionAt": created_at,
                "advisory": transfer_advisory,
            },
        )
        item["lastActionAt"] = created_at
        if transfer_advisory:
            item["advisory"] = transfer_advisory
        if action == "TRANSFER_ADVISORY_PRESENTED":
            item["presented"] = True
        elif action == "TRANSFER_ADVISORY_ACKNOWLEDGED":
            item["acknowledged"] = True
        elif action == "TRANSFER_ADVISORY_DISMISSED":
            item["dismissed"] = True
        elif action == "TRANSFER_OTP_VERIFIED":
            item["verified"] = True
    return feedback


def _build_tx_feedback_profile(
    scored_events: list[dict[str, Any]],
    feedback: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    risky_rows: list[dict[str, Any]] = []
    dismissed_count = 0
    acknowledged_count = 0

    for event in scored_events:
        request_key = str(event.get("request_key") or "")
        if not request_key:
            continue
        item = feedback.get(request_key) or {}
        if not item.get("presented"):
            continue
        if item.get("dismissed"):
            dismissed_count += 1
        if item.get("acknowledged"):
            acknowledged_count += 1
        if item.get("dismissed") or item.get("acknowledged"):
            risky_rows.append(event)

    if not risky_rows:
        return {
            "advisory_event_count": 0,
            "dismissed_count": dismissed_count,
            "acknowledged_count": acknowledged_count,
        }

    drain_ratios = []
    amount_ratios = []
    projected_ratios = []
    remaining_balances = []
    for event in risky_rows:
        balance_before = max(_safe_number(event.get("balance_before")), 0.0)
        amount = max(_safe_number(event.get("amount")), 0.0)
        daily_avg = max(_safe_number(event.get("daily_spend_avg_30d")), 0.0)
        projected = max(_safe_number(event.get("projected_daily_spend")), 0.0)
        remaining = max(_safe_number(event.get("remaining_balance")), 0.0)
        if balance_before > 0:
            drain_ratios.append(amount / balance_before)
        if daily_avg > 0:
            amount_ratios.append(amount / daily_avg)
            projected_ratios.append(projected / daily_avg)
        remaining_balances.append(remaining)

    return {
        "advisory_event_count": len(risky_rows),
        "dismissed_count": dismissed_count,
        "acknowledged_count": acknowledged_count,
        "median_balance_drain_ratio": round(float(np.median(drain_ratios)), 4) if drain_ratios else 0.0,
        "median_amount_to_daily_avg_ratio": round(float(np.median(amount_ratios)), 4) if amount_ratios else 0.0,
        "median_projected_spend_ratio": round(float(np.median(projected_ratios)), 4) if projected_ratios else 0.0,
        "median_remaining_balance": round(float(np.median(remaining_balances)), 2) if remaining_balances else 0.0,
    }


def _build_training_tx_dataset(
    database_url: str,
    target_rows: int = 180,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    scored_events = _build_tx_events_from_audit_scores(database_url)
    feedback = _load_transfer_feedback(database_url)
    feedback_profile = _build_tx_feedback_profile(scored_events, feedback)

    benign_events: list[dict[str, Any]] = []
    for event in scored_events:
        request_key = str(event.get("request_key") or "")
        item = feedback.get(request_key) or {}
        if item.get("dismissed") or item.get("acknowledged"):
            continue
        if item.get("presented"):
            continue
        if str(event.get("risk_level") or "low").lower() != "low":
            continue
        benign_events.append({key: value for key, value in event.items() if key not in {"request_key", "risk_level"}})

    if len(benign_events) < target_rows:
        synthetic = _generate_benign_tx_events(rows=target_rows - len(benign_events))
        benign_events.extend(synthetic)

    benign_events.sort(key=lambda item: item["timestamp"])
    return benign_events[: max(target_rows, len(benign_events))], feedback_profile


def main() -> None:
    env_values = _load_env_file()
    database_url = os.getenv("DATABASE_URL") or env_values.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required to bootstrap login model")

    login_events = _augment_login_events(_build_login_events_from_postgres(database_url))
    tx_events, tx_feedback_profile = _build_training_tx_dataset(database_url)

    login_version = f"local_login_protect_v2_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    tx_version = f"local_tx_protect_v3_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    _startup_app()
    try:
        login_result = train(
            TrainRequest(events=[LoginEvent(**event) for event in login_events]),
            persist=True,
            promote=True,
            model_version=login_version,
            _=None,
        )
        tx_result = train_transaction(
            TrainTransactionRequest(events=[TransactionEvent(**event) for event in tx_events]),
            persist=True,
            promote=False,
            model_version=tx_version,
            _=None,
        )
        _set_tx_model_state(
            model=app.state.tx_model,
            thresholds=app.state.tx_thresholds,
            feature_mean=app.state.tx_feature_mean,
            feature_std=app.state.tx_feature_std,
            countries=app.state.tx_countries,
            payment_methods=app.state.tx_payment_methods,
            merchant_categories=app.state.tx_merchant_categories,
            trained_at=app.state.tx_trained_at,
            train_size=app.state.tx_train_size,
            source=app.state.tx_model_source,
            model_version=app.state.tx_model_version,
            model_path=app.state.tx_model_path,
            metadata_path=app.state.tx_metadata_path,
            feature_names=list(app.state.tx_feature_names),
            feedback_profile=tx_feedback_profile,
        )
        tx_artifact = _persist_tx_model_artifacts(promote=True)
        tx_result["artifact"] = tx_artifact
        tx_result["feedback_profile"] = tx_feedback_profile
        print(
            json.dumps(
                {
                    "login": login_result,
                    "transaction": tx_result,
                },
                ensure_ascii=True,
                indent=2,
                default=str,
            )
        )
    finally:
        _shutdown_app()


if __name__ == "__main__":
    main()
