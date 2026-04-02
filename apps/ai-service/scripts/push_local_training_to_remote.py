import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

AI_SERVICE_ROOT = Path(__file__).resolve().parents[1]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build local AI training datasets and push them to a remote ai-service for train/persist/promote.",
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL"),
        help="Local PostgreSQL DATABASE_URL. Falls back to repo .env if omitted.",
    )
    parser.add_argument(
        "--remote-url",
        default=os.getenv("REMOTE_AI_URL") or os.getenv("AI_REMOTE_URL") or os.getenv("AI_SERVICE_URL"),
        help="Remote ai-service base URL, for example https://your-ai-service.onrender.com",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("REMOTE_AI_API_KEY") or os.getenv("AI_REMOTE_API_KEY") or os.getenv("AI_API_KEY"),
        help="Remote ai-service API key for X-AI-API-KEY auth.",
    )
    parser.add_argument(
        "--jwt",
        default=os.getenv("REMOTE_AI_JWT") or os.getenv("AI_REMOTE_JWT"),
        help="Optional Bearer JWT for remote ai-service auth.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="HTTP timeout in seconds for remote train calls.",
    )
    parser.add_argument(
        "--login-only",
        action="store_true",
        help="Push only login training data.",
    )
    parser.add_argument(
        "--tx-only",
        action="store_true",
        help="Push only transaction training data.",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Do not ask remote ai-service to persist model artifacts.",
    )
    parser.add_argument(
        "--no-promote",
        action="store_true",
        help="Do not ask remote ai-service to promote the newly trained model.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build local datasets and print counts only, without sending to remote.",
    )
    return parser.parse_args()


def _resolve_database_url(cli_value: str | None) -> str:
    if cli_value:
        return cli_value
    _, _, _, load_env_file = _load_local_dataset_builders()
    env_values = load_env_file()
    database_url = env_values.get("DATABASE_URL")
    if database_url:
        return database_url
    raise RuntimeError("DATABASE_URL is required. Pass --database-url or define it in .env.")


def _resolve_remote_url(cli_value: str | None) -> str:
    if not cli_value or not str(cli_value).strip():
        raise RuntimeError("Remote ai-service URL is required. Pass --remote-url or set REMOTE_AI_URL.")
    return str(cli_value).rstrip("/")


def _build_headers(api_key: str | None, jwt_token: str | None) -> dict[str, str]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key and str(api_key).strip():
        headers["X-AI-API-KEY"] = str(api_key).strip()
    if jwt_token and str(jwt_token).strip():
        headers["Authorization"] = f"Bearer {str(jwt_token).strip()}"
    return headers


def _build_query(persist: bool, promote: bool, model_version: str) -> dict[str, str]:
    return {
        "persist": "true" if persist else "false",
        "promote": "true" if promote else "false",
        "model_version": model_version,
    }


def _post_json(
    client: httpx.Client,
    *,
    url: str,
    headers: dict[str, str],
    params: dict[str, str],
    payload: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(url, headers=headers, params=params, json=payload)
    response.raise_for_status()
    return response.json()


def _load_local_dataset_builders():
    try:
        from scripts.bootstrap_local_models import (
            _augment_login_events,
            _build_login_events_from_postgres,
            _build_training_tx_dataset,
            _load_env_file,
        )
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing ai-service Python dependencies. Install apps/ai-service/requirements.txt before running this script.",
        ) from exc
    return (
        _augment_login_events,
        _build_login_events_from_postgres,
        _build_training_tx_dataset,
        _load_env_file,
    )


def main() -> None:
    args = _parse_args()
    if args.login_only and args.tx_only:
        raise RuntimeError("Choose only one of --login-only or --tx-only.")

    augment_login_events, build_login_events_from_postgres, build_training_tx_dataset, _ = _load_local_dataset_builders()
    database_url = _resolve_database_url(args.database_url)
    remote_url = _resolve_remote_url(args.remote_url)
    persist = not args.no_persist
    promote = not args.no_promote

    login_events = augment_login_events(build_login_events_from_postgres(database_url))
    tx_events, tx_feedback_profile = build_training_tx_dataset(database_url)

    summary: dict[str, Any] = {
        "remote_url": remote_url,
        "persist": persist,
        "promote": promote,
        "datasets": {
            "login_events": len(login_events),
            "tx_events": len(tx_events),
            "tx_feedback_profile": tx_feedback_profile,
        },
    }

    if args.dry_run:
        print(json.dumps(summary, ensure_ascii=True, indent=2, default=str))
        return

    headers = _build_headers(args.api_key, args.jwt)
    if "X-AI-API-KEY" not in headers and "Authorization" not in headers:
        raise RuntimeError(
            "Remote auth is missing. Provide --api-key, --jwt, REMOTE_AI_API_KEY, or REMOTE_AI_JWT.",
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results: dict[str, Any] = {}
    with httpx.Client(timeout=args.timeout) as client:
        status_response = client.get(f"{remote_url}/ai/status", headers=headers)
        status_response.raise_for_status()
        summary["remote_status_before"] = status_response.json()

        if not args.tx_only:
            login_version = f"remote_login_push_{timestamp}"
            results["login"] = _post_json(
                client,
                url=f"{remote_url}/ai/train",
                headers=headers,
                params=_build_query(persist=persist, promote=promote, model_version=login_version),
                payload={"events": login_events},
            )

        if not args.login_only:
            tx_version = f"remote_tx_push_{timestamp}"
            results["transaction"] = _post_json(
                client,
                url=f"{remote_url}/ai/tx/train",
                headers=headers,
                params=_build_query(persist=persist, promote=promote, model_version=tx_version),
                payload={"events": tx_events},
            )

        status_after = client.get(f"{remote_url}/ai/status", headers=headers)
        status_after.raise_for_status()
        summary["remote_status_after"] = status_after.json()

    summary["results"] = results
    print(json.dumps(summary, ensure_ascii=True, indent=2, default=str))


if __name__ == "__main__":
    main()
