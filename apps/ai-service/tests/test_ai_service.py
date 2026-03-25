import json
from datetime import datetime, timedelta, timezone

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from pyod.models.iforest import IForest

from app.main import app
from app.fraud_rules import evaluate_transaction_rules
from app.transaction_model import TransactionEvent, adjust_tx_risk_level

JWT_TEST_SECRET = "jwt-test-secret-32-characters-long!"


def _build_iforest_artifacts(
    *,
    model_path,
    metadata_path,
    feature_names: list[str],
    rows: list[list[float]],
    model_version: str,
    extra_metadata: dict,
) -> None:
    matrix = np.asarray(rows, dtype=float)
    model = IForest(contamination=0.1, random_state=42)
    model.fit(matrix)
    scores = model.decision_scores_
    feature_std = matrix.std(axis=0)
    feature_std[feature_std == 0] = 1.0

    metadata = {
        "artifact_version": 1,
        "model_type": "pyod.IForest",
        "model_version": model_version,
        "trained_at": "2026-03-09T00:00:00+00:00",
        "feature_names": feature_names,
        "train_size": int(matrix.shape[0]),
        "thresholds": {
            "p90": float(np.percentile(scores, 90)),
            "p97": float(np.percentile(scores, 97)),
            "score_min": float(np.min(scores)),
            "score_max": float(np.max(scores)),
        },
        "feature_mean": [float(x) for x in matrix.mean(axis=0).tolist()],
        "feature_std": [float(x) for x in feature_std.tolist()],
    }
    metadata.update(extra_metadata)
    joblib.dump(model, model_path)
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=True), encoding="utf-8")


def _auth_headers() -> dict[str, str]:
    return {"X-AI-API-KEY": "local-dev-key"}


def _jwt_headers(secret: str) -> dict[str, str]:
    jwt_lib = pytest.importorskip("jwt")
    token = jwt_lib.encode(
        {"sub": "postman-user", "exp": datetime.now(timezone.utc) + timedelta(hours=2)},
        secret,
        algorithm="HS256",
    )
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return {"Authorization": f"Bearer {token}"}


def test_score_requires_api_key_when_auth_enabled():
    with TestClient(app) as client:
        payload = {
            "user_id": "u-test",
            "timestamp": "2026-03-05T10:00:00Z",
            "ip": "1.1.1.1",
            "country": "VN",
            "device": "Chrome",
            "success": 1,
            "failed_10m": 0,
            "bot_score": 0.1,
        }
        res = client.post("/ai/score", json=payload)
        assert res.status_code == 401


def test_ui_page_is_available():
    with TestClient(app) as client:
        res = client.get("/ui")
        assert res.status_code == 200
        assert "AI Service Test UI" in res.text


def test_tx_score_requires_api_key_when_auth_enabled():
    with TestClient(app) as client:
        payload = {
            "user_id": "u-test",
            "timestamp": "2026-03-05T10:00:00Z",
            "amount": 59.9,
            "currency": "USD",
            "country": "US",
            "payment_method": "card",
            "merchant_category": "retail",
            "device": "Chrome",
            "failed_tx_24h": 0,
            "velocity_1h": 1,
        }
        res = client.post("/ai/tx/score", json=payload)
        assert res.status_code == 401


def test_jwt_auth_mode_train_and_score(monkeypatch):
    monkeypatch.setenv("AI_AUTH_MODE", "jwt")
    monkeypatch.setenv("AI_JWT_SECRET", JWT_TEST_SECRET)
    monkeypatch.setenv("AI_JWT_ALGORITHM", "HS256")

    train_events = []
    for i in range(12):
        train_events.append(
            {
                "user_id": f"u-{i%3}",
                "timestamp": f"2026-03-0{1 + (i % 3)}T10:{i:02d}:00Z",
                "ip": "1.1.1.1",
                "country": "VN",
                "device": "Mozilla/5.0 Chrome",
                "success": 1,
                "failed_10m": 0,
                "bot_score": 0.1,
            }
        )

    with TestClient(app) as client:
        unauthorized = client.post("/ai/train", json={"events": train_events})
        assert unauthorized.status_code == 401

        train_res = client.post("/ai/train", json={"events": train_events}, headers=_jwt_headers(JWT_TEST_SECRET))
        assert train_res.status_code == 200

        score_payload = {
            "user_id": "u-x",
            "timestamp": "2026-03-05T03:12:00Z",
            "ip": "88.88.88.88",
            "country": "RU",
            "device": "VeryStrangeBot/9.9",
            "success": 0,
            "failed_10m": 8,
            "bot_score": 0.96,
        }
        score_res = client.post("/ai/score", json=score_payload, headers=_jwt_headers(JWT_TEST_SECRET))
        assert score_res.status_code == 200


def test_train_and_score_monitoring_only():
    train_events = []
    for i in range(12):
        train_events.append(
            {
                "user_id": f"u-{i%3}",
                "timestamp": f"2026-03-0{1 + (i % 3)}T10:{i:02d}:00Z",
                "ip": "1.1.1.1",
                "country": "VN",
                "device": "Mozilla/5.0 Chrome",
                "success": 1,
                "failed_10m": 0,
                "bot_score": 0.1,
            }
        )

    with TestClient(app) as client:
        train_res = client.post("/ai/train", json={"events": train_events}, headers=_auth_headers())
        assert train_res.status_code == 200
        score_payload = {
            "user_id": "u-x",
            "timestamp": "2026-03-05T03:12:00Z",
            "ip": "88.88.88.88",
            "country": "RU",
            "device": "VeryStrangeBot/9.9",
            "success": 0,
            "failed_10m": 8,
            "bot_score": 0.96,
            "idempotency_key": "idem-test-1",
        }
        score_res = client.post(
            "/ai/score",
            json=score_payload,
            headers={**_auth_headers(), "X-Idempotency-Key": "idem-test-1"},
        )
        assert score_res.status_code == 200
        body = score_res.json()
        assert body["monitoring_only"] is True
        assert body["action"] == "NOTIFY_ADMIN_ONLY"
        assert body["request_key"] == "idem-test-1"
        assert body["risk_level"] in {"LOW", "MEDIUM", "HIGH"}


def test_train_and_score_transaction_monitoring_only():
    tx_events = []
    for i in range(12):
        tx_events.append(
            {
                "user_id": f"u-{i%3}",
                "transaction_id": f"tx-{i}",
                "timestamp": f"2026-03-0{1 + (i % 3)}T12:{i:02d}:00Z",
                "amount": 50 + i * 3,
                "currency": "USD",
                "country": "US",
                "payment_method": "card",
                "merchant_category": "retail",
                "device": "Mozilla/5.0 Chrome",
                "failed_tx_24h": 0,
                "velocity_1h": 1,
            }
        )

    with TestClient(app) as client:
        train_res = client.post("/ai/tx/train", json={"events": tx_events}, headers=_auth_headers())
        assert train_res.status_code == 200

        score_payload = {
            "user_id": "u-z",
            "transaction_id": "tx-risk-1",
            "timestamp": "2026-03-05T03:12:00Z",
            "amount": 12500,
            "currency": "USD",
            "country": "RU",
            "payment_method": "crypto",
            "merchant_category": "gambling",
            "device": "VeryStrangeBot/9.9",
            "failed_tx_24h": 3,
            "velocity_1h": 7,
            "idempotency_key": "idem-tx-1",
        }
        score_res = client.post(
            "/ai/tx/score",
            json=score_payload,
            headers={**_auth_headers(), "X-Idempotency-Key": "idem-tx-1"},
        )
        assert score_res.status_code == 200
        body = score_res.json()
        assert body["monitoring_only"] is True
        assert body["action"] == "REVIEW_TRANSACTION_ONLY"
        assert body["request_key"] == "idem-tx-1"
        assert body["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
        assert body["rule_risk_level"] in {"LOW", "MEDIUM", "HIGH"}
        assert isinstance(body["rule_hit_count"], int)
        assert isinstance(body["rule_hits"], list)
        assert "warning_vi" in body
        assert "title" in body["warning_vi"]


def test_rule_engine_returns_high_risk_for_crypto_burst_drain():
    event = TransactionEvent(
        user_id="u-aml-1",
        transaction_id="tx-aml-1",
        timestamp=datetime(2026, 3, 5, 2, 20, tzinfo=timezone.utc),
        amount=12000,
        currency="USD",
        country="IR",
        payment_method="crypto",
        merchant_category="crypto_exchange",
        device="Mozilla/5.0 Chrome",
        failed_tx_24h=4,
        velocity_1h=7,
        daily_spend_avg_30d=120,
        projected_daily_spend=22000,
        balance_before=12500,
        remaining_balance=50,
    )

    rule_eval = evaluate_transaction_rules(event, learned_countries={"us", "vn"})
    assert rule_eval.rule_risk_level == "HIGH"
    assert rule_eval.rule_score >= 60
    assert len(rule_eval.hits) >= 4


def test_small_full_balance_transfer_does_not_raise_drain_risk():
    event = TransactionEvent(
        user_id="u-low-drain",
        transaction_id="tx-low-drain",
        timestamp=datetime(2026, 3, 5, 3, 12, tzinfo=timezone.utc),
        amount=443,
        currency="USD",
        country="US",
        payment_method="wallet_balance",
        merchant_category="p2p_transfer",
        device="Mozilla/5.0 Chrome",
        failed_tx_24h=0,
        velocity_1h=1,
        balance_before=443,
        remaining_balance=0,
    )

    assert adjust_tx_risk_level("LOW", event) == "LOW"


def test_large_full_balance_transfer_still_raises_drain_risk():
    event = TransactionEvent(
        user_id="u-high-drain",
        transaction_id="tx-high-drain",
        timestamp=datetime(2026, 3, 5, 3, 12, tzinfo=timezone.utc),
        amount=1500,
        currency="USD",
        country="US",
        payment_method="wallet_balance",
        merchant_category="p2p_transfer",
        device="Mozilla/5.0 Chrome",
        failed_tx_24h=0,
        velocity_1h=1,
        balance_before=1500,
        remaining_balance=0,
    )

    assert adjust_tx_risk_level("LOW", event) == "HIGH"


def test_train_login_can_persist_artifact(tmp_path, monkeypatch):
    model_path = tmp_path / "iforest_rba.joblib"
    metadata_path = tmp_path / "iforest_rba_metadata.json"
    active_path = tmp_path / "active_model.json"
    monkeypatch.setenv("AI_MODEL_PATH", str(model_path))
    monkeypatch.setenv("AI_METADATA_PATH", str(metadata_path))
    monkeypatch.setenv("AI_ACTIVE_MODEL_FILE", str(active_path))

    train_events = []
    for i in range(12):
        train_events.append(
            {
                "user_id": f"u-{i%2}",
                "timestamp": f"2026-03-0{1 + (i % 3)}T11:{i:02d}:00Z",
                "ip": "1.1.1.1",
                "country": "VN",
                "device": "Mozilla/5.0 Chrome",
                "success": 1,
                "failed_10m": 0,
                "bot_score": 0.1,
            }
        )

    with TestClient(app) as client:
        train_res = client.post(
            "/ai/train?persist=true&promote=true&model_version=test_login_persist_v1",
            json={"events": train_events},
            headers=_auth_headers(),
        )
        assert train_res.status_code == 200
        body = train_res.json()
        assert body["artifact"]["saved"] is True
        assert model_path.exists()
        assert metadata_path.exists()
        assert active_path.exists()


def test_startup_loads_login_and_tx_artifacts_from_env_paths(tmp_path, monkeypatch):
    login_model = tmp_path / "iforest_rba.joblib"
    login_meta = tmp_path / "iforest_rba_metadata.json"
    tx_model = tmp_path / "iforest_tx.joblib"
    tx_meta = tmp_path / "iforest_tx_metadata.json"

    _build_iforest_artifacts(
        model_path=login_model,
        metadata_path=login_meta,
        feature_names=["hour_of_day", "day_of_week", "failed_10m", "device_length", "bot_score"],
        rows=[
            [9, 0, 0, 30, 0.1],
            [10, 1, 0, 28, 0.1],
            [11, 2, 1, 31, 0.2],
            [12, 3, 0, 32, 0.1],
            [13, 4, 0, 29, 0.1],
            [14, 5, 0, 30, 0.1],
            [15, 6, 0, 33, 0.1],
            [16, 0, 1, 35, 0.2],
            [17, 1, 0, 30, 0.1],
            [18, 2, 0, 30, 0.1],
        ],
        model_version="test_login_artifact_v1",
        extra_metadata={"countries": ["vn"], "devices": ["mozilla/5.0 chrome"]},
    )
    _build_iforest_artifacts(
        model_path=tx_model,
        metadata_path=tx_meta,
        feature_names=["hour_of_day", "day_of_week", "amount_log10", "failed_tx_24h", "velocity_1h", "device_length"],
        rows=[
            [9, 0, 2.0, 0, 0, 6],
            [10, 1, 2.2, 0, 1, 7],
            [11, 2, 2.4, 0, 1, 8],
            [12, 3, 2.1, 0, 1, 7],
            [13, 4, 2.3, 0, 0, 6],
            [14, 5, 2.5, 0, 1, 8],
            [15, 6, 2.2, 0, 0, 6],
            [16, 0, 2.3, 0, 2, 7],
            [17, 1, 2.1, 0, 1, 7],
            [18, 2, 2.4, 0, 1, 8],
        ],
        model_version="test_tx_artifact_v1",
        extra_metadata={
            "countries": ["us"],
            "payment_methods": ["card"],
            "merchant_categories": ["retail"],
        },
    )

    monkeypatch.setenv("AI_MODEL_PATH", str(login_model))
    monkeypatch.setenv("AI_METADATA_PATH", str(login_meta))
    monkeypatch.setenv("AI_TX_MODEL_PATH", str(tx_model))
    monkeypatch.setenv("AI_TX_METADATA_PATH", str(tx_meta))

    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        health_body = health.json()
        assert health_body["model_loaded"] is True
        assert health_body["tx_model_loaded"] is True

        status = client.get("/ai/status", headers=_auth_headers())
        assert status.status_code == 200
        status_body = status.json()
        assert status_body["model_loaded"] is True
        assert status_body["tx_model_loaded"] is True
        assert status_body["model_path"] == str(login_model)
        assert status_body["tx_model_path"] == str(tx_model)


def test_reload_uses_tx_active_model_file(tmp_path, monkeypatch):
    tx_model = tmp_path / "iforest_tx_active.joblib"
    tx_meta = tmp_path / "iforest_tx_active_metadata.json"
    active_tx_file = tmp_path / "active_tx_model.json"

    _build_iforest_artifacts(
        model_path=tx_model,
        metadata_path=tx_meta,
        feature_names=["hour_of_day", "day_of_week", "amount_log10", "failed_tx_24h", "velocity_1h", "device_length"],
        rows=[
            [9, 0, 2.0, 0, 0, 6],
            [10, 1, 2.2, 0, 1, 7],
            [11, 2, 2.4, 0, 1, 8],
            [12, 3, 2.1, 0, 1, 7],
            [13, 4, 2.3, 0, 0, 6],
            [14, 5, 2.5, 0, 1, 8],
            [15, 6, 2.2, 0, 0, 6],
            [16, 0, 2.3, 0, 2, 7],
            [17, 1, 2.1, 0, 1, 7],
            [18, 2, 2.4, 0, 1, 8],
        ],
        model_version="test_tx_pointer_v1",
        extra_metadata={
            "countries": ["us"],
            "payment_methods": ["card"],
            "merchant_categories": ["retail"],
        },
    )
    active_tx_file.write_text(
        json.dumps(
            {
                "model_version": "test_tx_pointer_v1",
                "model_path": str(tx_model),
                "metadata_path": str(tx_meta),
            },
            ensure_ascii=True,
        ),
        encoding="utf-8",
    )

    monkeypatch.delenv("AI_TX_MODEL_PATH", raising=False)
    monkeypatch.delenv("AI_TX_METADATA_PATH", raising=False)
    monkeypatch.setenv("AI_TX_ACTIVE_MODEL_FILE", str(active_tx_file))

    with TestClient(app) as client:
        reload_res = client.post("/ai/reload-model", headers=_auth_headers())
        assert reload_res.status_code == 200
        body = reload_res.json()
        assert body["tx_model_loaded"] is True
        assert body["tx_model_path"] == str(tx_model)
