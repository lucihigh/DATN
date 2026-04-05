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
    "new_recipient_flag",
    "suspicious_note_count",
    "session_transfer_limit_flag",
    "rolling_outflow_amount_log10",
    "face_id_required_flag",
    "recent_review_count_30d",
    "recent_blocked_count_30d",
    "recent_pending_otp_count_7d",
    "llm_note_medium_flag",
    "llm_note_high_flag",
    "llm_signal_count",
]
BALANCE_DRAIN_RISK_MIN_AMOUNT = 1000.0
DEFAULT_ACCOUNT_SEGMENT = "PERSONAL"
DEFAULT_ACCOUNT_CATEGORY = "PERSONAL"
DEFAULT_PERSONAL_TIER = "STANDARD"
DEFAULT_BUSINESS_TIER = "SMALL_BUSINESS"
PERSONAL_ACCOUNT_TIERS = {"BASIC", "STANDARD", "PREMIUM"}
BUSINESS_ACCOUNT_TIERS = {"SMALL_BUSINESS", "MEDIUM_BUSINESS", "ENTERPRISE"}
ACCOUNT_PROFILE_THRESHOLDS = {
    "PERSONAL_BASIC": {
        "medium_amount": 1500.0,
        "high_amount": 5000.0,
        "projected_medium_ratio": 16.0,
        "projected_high_ratio": 45.0,
        "projected_medium_delta": 1500.0,
        "projected_high_delta": 6000.0,
        "amount_ratio_medium": 2.8,
        "amount_ratio_high": 6.0,
        "amount_ratio_medium_min": 300.0,
        "amount_ratio_high_min": 1200.0,
        "rolling_outflow_medium": 1500.0,
        "rolling_outflow_high": 5000.0,
        "new_recipient_amount": 1000.0,
        "high_drain_ratio": 0.92,
        "medium_drain_ratio": 0.78,
        "critical_remaining_balance": 5.0,
        "low_remaining_balance": 25.0,
        "label": "personal basic",
        "review_bias": 1.18,
    },
    "PERSONAL_STANDARD": {
        "medium_amount": 3000.0,
        "high_amount": 10000.0,
        "projected_medium_ratio": 30.0,
        "projected_high_ratio": 100.0,
        "projected_medium_delta": 5000.0,
        "projected_high_delta": 20000.0,
        "amount_ratio_medium": 4.0,
        "amount_ratio_high": 10.0,
        "amount_ratio_medium_min": 500.0,
        "amount_ratio_high_min": 2000.0,
        "rolling_outflow_medium": 3000.0,
        "rolling_outflow_high": 10000.0,
        "new_recipient_amount": 2000.0,
        "high_drain_ratio": 0.95,
        "medium_drain_ratio": 0.85,
        "critical_remaining_balance": 5.0,
        "low_remaining_balance": 25.0,
        "label": "personal standard",
        "review_bias": 1.0,
    },
    "PERSONAL_PREMIUM": {
        "medium_amount": 7000.0,
        "high_amount": 25000.0,
        "projected_medium_ratio": 42.0,
        "projected_high_ratio": 120.0,
        "projected_medium_delta": 10000.0,
        "projected_high_delta": 35000.0,
        "amount_ratio_medium": 5.5,
        "amount_ratio_high": 12.0,
        "amount_ratio_medium_min": 1000.0,
        "amount_ratio_high_min": 4000.0,
        "rolling_outflow_medium": 8000.0,
        "rolling_outflow_high": 25000.0,
        "new_recipient_amount": 5000.0,
        "high_drain_ratio": 0.97,
        "medium_drain_ratio": 0.88,
        "critical_remaining_balance": 10.0,
        "low_remaining_balance": 50.0,
        "label": "personal premium",
        "review_bias": 0.92,
    },
    "BUSINESS_SMALL_BUSINESS": {
        "medium_amount": 10000.0,
        "high_amount": 35000.0,
        "projected_medium_ratio": 40.0,
        "projected_high_ratio": 120.0,
        "projected_medium_delta": 10000.0,
        "projected_high_delta": 40000.0,
        "amount_ratio_medium": 6.0,
        "amount_ratio_high": 14.0,
        "amount_ratio_medium_min": 1500.0,
        "amount_ratio_high_min": 7000.0,
        "rolling_outflow_medium": 10000.0,
        "rolling_outflow_high": 25000.0,
        "new_recipient_amount": 7000.0,
        "high_drain_ratio": 0.98,
        "medium_drain_ratio": 0.9,
        "critical_remaining_balance": 50.0,
        "low_remaining_balance": 250.0,
        "label": "business small",
        "review_bias": 0.88,
    },
    "BUSINESS_MEDIUM_BUSINESS": {
        "medium_amount": 25000.0,
        "high_amount": 100000.0,
        "projected_medium_ratio": 65.0,
        "projected_high_ratio": 180.0,
        "projected_medium_delta": 25000.0,
        "projected_high_delta": 120000.0,
        "amount_ratio_medium": 8.5,
        "amount_ratio_high": 18.0,
        "amount_ratio_medium_min": 4000.0,
        "amount_ratio_high_min": 18000.0,
        "rolling_outflow_medium": 25000.0,
        "rolling_outflow_high": 90000.0,
        "new_recipient_amount": 15000.0,
        "high_drain_ratio": 0.985,
        "medium_drain_ratio": 0.9,
        "critical_remaining_balance": 150.0,
        "low_remaining_balance": 700.0,
        "label": "business medium",
        "review_bias": 0.82,
    },
    "BUSINESS_ENTERPRISE": {
        "medium_amount": 50000.0,
        "high_amount": 250000.0,
        "projected_medium_ratio": 90.0,
        "projected_high_ratio": 240.0,
        "projected_medium_delta": 50000.0,
        "projected_high_delta": 250000.0,
        "amount_ratio_medium": 12.0,
        "amount_ratio_high": 26.0,
        "amount_ratio_medium_min": 15000.0,
        "amount_ratio_high_min": 60000.0,
        "rolling_outflow_medium": 60000.0,
        "rolling_outflow_high": 250000.0,
        "new_recipient_amount": 30000.0,
        "high_drain_ratio": 0.99,
        "medium_drain_ratio": 0.92,
        "critical_remaining_balance": 250.0,
        "low_remaining_balance": 1000.0,
        "label": "business enterprise",
        "review_bias": 0.78,
    },
}
ACCOUNT_SEGMENT_THRESHOLDS = {
    "PERSONAL": ACCOUNT_PROFILE_THRESHOLDS["PERSONAL_STANDARD"],
    "SME": ACCOUNT_PROFILE_THRESHOLDS["BUSINESS_MEDIUM_BUSINESS"],
    "ENTERPRISE": ACCOUNT_PROFILE_THRESHOLDS["BUSINESS_ENTERPRISE"],
}
ACCOUNT_PROFILE_THRESHOLDS["PERSONAL_PRIVATE"] = ACCOUNT_PROFILE_THRESHOLDS["PERSONAL_PREMIUM"]
ACCOUNT_PROFILE_THRESHOLDS["BUSINESS_SME"] = ACCOUNT_PROFILE_THRESHOLDS["BUSINESS_SMALL_BUSINESS"]


class TransactionAccountProfile(BaseModel):
    segment: str | None = None
    category: str | None = None
    tier: str | None = None
    status: str | None = None
    confidence: float | None = None


class TransactionTransferContext(BaseModel):
    channel: str | None = None
    balance_before: float | None = Field(
        default=None,
        validation_alias=AliasChoices("balance_before", "balanceBefore"),
    )
    remaining_balance: float | None = Field(
        default=None,
        validation_alias=AliasChoices("remaining_balance", "remainingBalance"),
    )
    recipient_known: bool | None = Field(
        default=None,
        validation_alias=AliasChoices("recipient_known", "recipientKnown"),
    )
    rolling_outflow_amount: float | None = Field(
        default=None,
        validation_alias=AliasChoices("rolling_outflow_amount", "rollingOutflowAmount"),
    )
    face_id_required: bool | None = Field(
        default=None,
        validation_alias=AliasChoices("face_id_required", "faceIdRequired"),
    )
    session_risk_level: str | None = Field(
        default=None,
        validation_alias=AliasChoices("session_risk_level", "sessionRiskLevel"),
    )
    session_restrict_large_transfers: bool | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "session_restrict_large_transfers",
            "sessionRestrictLargeTransfers",
        ),
    )


class TransactionBehaviorSnapshot(BaseModel):
    failed_tx_24h: int | None = Field(
        default=None,
        validation_alias=AliasChoices("failed_tx_24h", "failedTx24h"),
    )
    velocity_1h: int | None = Field(
        default=None,
        validation_alias=AliasChoices("velocity_1h", "velocity1h"),
    )
    daily_spend_avg_30d: float | None = Field(
        default=None,
        validation_alias=AliasChoices("daily_spend_avg_30d", "dailySpendAvg30d"),
    )
    today_spend_before: float | None = Field(
        default=None,
        validation_alias=AliasChoices("today_spend_before", "todaySpendBefore"),
    )
    projected_daily_spend: float | None = Field(
        default=None,
        validation_alias=AliasChoices("projected_daily_spend", "projectedDailySpend"),
    )
    recent_review_count_30d: int | None = Field(
        default=None,
        validation_alias=AliasChoices("recent_review_count_30d", "recentReviewCount30d"),
    )
    recent_blocked_count_30d: int | None = Field(
        default=None,
        validation_alias=AliasChoices("recent_blocked_count_30d", "recentBlockedCount30d"),
    )
    recent_pending_otp_count_7d: int | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "recent_pending_otp_count_7d",
            "recentPendingOtpCount7d",
        ),
    )
    recent_inbound_amount_24h: float | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "recent_inbound_amount_24h",
            "recentInboundAmount24h",
        ),
    )
    recent_admin_topup_amount_24h: float | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "recent_admin_topup_amount_24h",
            "recentAdminTopUpAmount24h",
        ),
    )
    recent_self_deposit_amount_24h: float | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "recent_self_deposit_amount_24h",
            "recentSelfDepositAmount24h",
        ),
    )
    small_probe_count_24h: int | None = Field(
        default=None,
        validation_alias=AliasChoices("small_probe_count_24h", "smallProbeCount24h"),
    )
    small_probe_total_24h: float | None = Field(
        default=None,
        validation_alias=AliasChoices("small_probe_total_24h", "smallProbeTotal24h"),
    )
    distinct_small_probe_recipients_24h: int | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "distinct_small_probe_recipients_24h",
            "distinctSmallProbeRecipients24h",
        ),
    )
    same_recipient_small_probe_count_24h: int | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "same_recipient_small_probe_count_24h",
            "sameRecipientSmallProbeCount24h",
        ),
    )
    new_recipient_small_probe_count_24h: int | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "new_recipient_small_probe_count_24h",
            "newRecipientSmallProbeCount24h",
        ),
    )
    probe_then_large_risk_score: float | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "probe_then_large_risk_score",
            "probeThenLargeRiskScore",
        ),
    )
    rapid_cash_out_risk_score: float | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "rapid_cash_out_risk_score",
            "rapidCashOutRiskScore",
        ),
    )


class TransactionLlmContext(BaseModel):
    risk_level: str | None = Field(
        default=None,
        validation_alias=AliasChoices("risk_level", "riskLevel"),
    )
    signal_count: int | None = Field(
        default=None,
        validation_alias=AliasChoices("signal_count", "signalCount"),
    )
    signals: list[str] = Field(default_factory=list)
    rule_tags: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("rule_tags", "ruleTags"),
    )
    summary: str | None = None
    source: str | None = None
    model: str | None = None


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
    account_segment: str = Field(
        default=DEFAULT_ACCOUNT_SEGMENT,
        validation_alias=AliasChoices(
            "account_segment",
            "accountSegment",
            "account_type",
            "accountType",
        ),
    )
    account_category: str = Field(
        default=DEFAULT_ACCOUNT_CATEGORY,
        validation_alias=AliasChoices(
            "account_category",
            "accountCategory",
            "category",
        ),
    )
    account_tier: str = Field(
        default=DEFAULT_PERSONAL_TIER,
        validation_alias=AliasChoices(
            "account_tier",
            "accountTier",
            "tier",
        ),
    )
    account_profile_status: str = Field(
        default="SYSTEM_ASSIGNED",
        validation_alias=AliasChoices(
            "account_profile_status",
            "accountProfileStatus",
            "profileStatus",
        ),
    )
    account_profile_confidence: float = Field(
        default=0.6,
        validation_alias=AliasChoices(
            "account_profile_confidence",
            "accountProfileConfidence",
            "profileConfidence",
        ),
    )
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
    recipient_known: bool = Field(
        default=False,
        validation_alias=AliasChoices("recipient_known", "recipientKnown"),
    )
    suspicious_note_count: int = Field(
        default=0,
        validation_alias=AliasChoices("suspicious_note_count", "suspiciousNoteCount"),
    )
    rolling_outflow_amount: float = Field(
        default=0.0,
        validation_alias=AliasChoices("rolling_outflow_amount", "rollingOutflowAmount"),
    )
    face_id_required: bool = Field(
        default=False,
        validation_alias=AliasChoices("face_id_required", "faceIdRequired"),
    )
    session_restrict_large_transfers: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "session_restrict_large_transfers",
            "sessionRestrictLargeTransfers",
        ),
    )
    recent_review_count_30d: int = Field(
        default=0,
        validation_alias=AliasChoices("recent_review_count_30d", "recentReviewCount30d"),
    )
    recent_blocked_count_30d: int = Field(
        default=0,
        validation_alias=AliasChoices("recent_blocked_count_30d", "recentBlockedCount30d"),
    )
    recent_pending_otp_count_7d: int = Field(
        default=0,
        validation_alias=AliasChoices(
            "recent_pending_otp_count_7d",
            "recentPendingOtpCount7d",
        ),
    )
    recent_inbound_amount_24h: float = Field(
        default=0.0,
        validation_alias=AliasChoices(
            "recent_inbound_amount_24h",
            "recentInboundAmount24h",
        ),
    )
    recent_admin_topup_amount_24h: float = Field(
        default=0.0,
        validation_alias=AliasChoices(
            "recent_admin_topup_amount_24h",
            "recentAdminTopUpAmount24h",
        ),
    )
    recent_self_deposit_amount_24h: float = Field(
        default=0.0,
        validation_alias=AliasChoices(
            "recent_self_deposit_amount_24h",
            "recentSelfDepositAmount24h",
        ),
    )
    small_probe_count_24h: int = Field(
        default=0,
        validation_alias=AliasChoices("small_probe_count_24h", "smallProbeCount24h"),
    )
    small_probe_total_24h: float = Field(
        default=0.0,
        validation_alias=AliasChoices("small_probe_total_24h", "smallProbeTotal24h"),
    )
    distinct_small_probe_recipients_24h: int = Field(
        default=0,
        validation_alias=AliasChoices(
            "distinct_small_probe_recipients_24h",
            "distinctSmallProbeRecipients24h",
        ),
    )
    same_recipient_small_probe_count_24h: int = Field(
        default=0,
        validation_alias=AliasChoices(
            "same_recipient_small_probe_count_24h",
            "sameRecipientSmallProbeCount24h",
        ),
    )
    new_recipient_small_probe_count_24h: int = Field(
        default=0,
        validation_alias=AliasChoices(
            "new_recipient_small_probe_count_24h",
            "newRecipientSmallProbeCount24h",
        ),
    )
    probe_then_large_risk_score: float = Field(
        default=0.0,
        validation_alias=AliasChoices(
            "probe_then_large_risk_score",
            "probeThenLargeRiskScore",
        ),
    )
    rapid_cash_out_risk_score: float = Field(
        default=0.0,
        validation_alias=AliasChoices(
            "rapid_cash_out_risk_score",
            "rapidCashOutRiskScore",
        ),
    )
    llm_note_risk_level: str = Field(
        default="LOW",
        validation_alias=AliasChoices("llm_note_risk_level", "llmNoteRiskLevel"),
    )
    llm_signal_count: int = Field(
        default=0,
        validation_alias=AliasChoices("llm_signal_count", "llmSignalCount"),
    )
    llm_rule_tags: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("llm_rule_tags", "llmRuleTags"),
    )
    llm_signals: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("llm_signals", "llmSignals"),
    )
    llm_summary: str | None = Field(
        default=None,
        validation_alias=AliasChoices("llm_summary", "llmSummary"),
    )
    llm_source: str | None = Field(
        default=None,
        validation_alias=AliasChoices("llm_source", "llmSource"),
    )
    llm_model: str | None = Field(
        default=None,
        validation_alias=AliasChoices("llm_model", "llmModel"),
    )
    session_risk_level: str = Field(
        default="LOW",
        validation_alias=AliasChoices("session_risk_level", "sessionRiskLevel"),
    )
    account_profile: TransactionAccountProfile | None = Field(
        default=None,
        validation_alias=AliasChoices("account_profile", "accountProfile"),
    )
    transfer_context: TransactionTransferContext | None = Field(
        default=None,
        validation_alias=AliasChoices("transfer_context", "transferContext"),
    )
    behavior_snapshot: TransactionBehaviorSnapshot | None = Field(
        default=None,
        validation_alias=AliasChoices("behavior_snapshot", "behaviorSnapshot"),
    )
    llm_context: TransactionLlmContext | None = Field(
        default=None,
        validation_alias=AliasChoices("llm_context", "llmContext"),
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


def _normalize_risk_level(value: str | None) -> str:
    cleaned = str(value or "").strip().upper()
    if cleaned in {"LOW", "MEDIUM", "HIGH"}:
        return cleaned
    return "LOW"


def _normalize_profile_status(value: str | None) -> str:
    cleaned = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    if cleaned in {"PENDING_REVIEW", "VERIFIED", "REQUIRES_REVIEW"}:
        return cleaned
    return "SYSTEM_ASSIGNED"


def normalize_account_segment(value: str | None) -> str:
    cleaned = str(value or "").strip().upper()
    if cleaned in ACCOUNT_SEGMENT_THRESHOLDS:
        return cleaned
    return DEFAULT_ACCOUNT_SEGMENT


def normalize_account_category(value: str | None, segment: str | None = None) -> str:
    cleaned = str(value or "").strip().upper()
    if cleaned == "PERSONAL":
        return cleaned
    if cleaned in {"BUSINESS", "SME", "ENTERPRISE", "CORPORATE", "SMALLBUSINESS"}:
        return "BUSINESS"
    normalized_segment = normalize_account_segment(segment)
    return "BUSINESS" if normalized_segment in {"SME", "ENTERPRISE"} else DEFAULT_ACCOUNT_CATEGORY


def normalize_account_tier(
    category: str | None,
    value: str | None,
    segment: str | None = None,
) -> str:
    normalized_category = normalize_account_category(category, segment)
    cleaned = str(value or "").strip().upper()
    if cleaned == "PRIVATE":
        cleaned = "PREMIUM"
    if cleaned in {"SME", "SMALLBUSINESS", "B1_SMALL_BUSINESS", "B1SMALLBUSINESS"}:
        cleaned = "SMALL_BUSINESS"
    elif cleaned in {"MEDIUMBUSINESS", "B2_MEDIUM_BUSINESS", "B2MEDIUMBUSINESS"}:
        cleaned = "MEDIUM_BUSINESS"
    elif cleaned in {"P1_BASIC", "P1BASIC"}:
        cleaned = "BASIC"
    elif cleaned in {"P2_STANDARD", "P2STANDARD"}:
        cleaned = "STANDARD"
    elif cleaned in {"P3_PREMIUM", "P3PREMIUM"}:
        cleaned = "PREMIUM"
    if normalized_category == "BUSINESS":
        if cleaned in BUSINESS_ACCOUNT_TIERS:
            return cleaned
        return "ENTERPRISE" if normalize_account_segment(segment) == "ENTERPRISE" else DEFAULT_BUSINESS_TIER
    if cleaned in PERSONAL_ACCOUNT_TIERS:
        return cleaned
    return DEFAULT_PERSONAL_TIER


def derive_account_segment(
    category: str | None,
    tier: str | None,
    fallback_segment: str | None = None,
) -> str:
    normalized_category = normalize_account_category(category, fallback_segment)
    normalized_tier = normalize_account_tier(normalized_category, tier, fallback_segment)
    if normalized_category == "BUSINESS":
        return "ENTERPRISE" if normalized_tier == "ENTERPRISE" else "SME"
    return DEFAULT_ACCOUNT_SEGMENT


def build_account_profile_code(
    category: str | None,
    tier: str | None,
    segment: str | None = None,
) -> str:
    normalized_category = normalize_account_category(category, segment)
    normalized_tier = normalize_account_tier(normalized_category, tier, segment)
    return f"{normalized_category}_{normalized_tier}"


def get_account_segment_thresholds(segment: str | None) -> dict[str, float]:
    normalized = normalize_account_segment(segment)
    return ACCOUNT_SEGMENT_THRESHOLDS[normalized]


def get_account_profile_thresholds(
    category: str | None,
    tier: str | None,
    segment: str | None = None,
) -> dict[str, float]:
    profile_code = build_account_profile_code(category, tier, segment)
    return ACCOUNT_PROFILE_THRESHOLDS.get(
        profile_code,
        ACCOUNT_PROFILE_THRESHOLDS["PERSONAL_STANDARD"],
    )


def normalize_transaction_event(event: TransactionEvent) -> TransactionEvent:
    if event.account_profile is not None:
        if event.account_profile.segment:
            event.account_segment = event.account_profile.segment
        if event.account_profile.category:
            event.account_category = event.account_profile.category
        if event.account_profile.tier:
            event.account_tier = event.account_profile.tier
        if event.account_profile.status:
            event.account_profile_status = event.account_profile.status
        if event.account_profile.confidence is not None:
            event.account_profile_confidence = float(event.account_profile.confidence)

    if event.transfer_context is not None:
        if event.transfer_context.channel:
            event.channel = event.transfer_context.channel
        if event.transfer_context.balance_before is not None:
            event.balance_before = float(event.transfer_context.balance_before)
        if event.transfer_context.remaining_balance is not None:
            event.remaining_balance = float(event.transfer_context.remaining_balance)
        if event.transfer_context.recipient_known is not None:
            event.recipient_known = bool(event.transfer_context.recipient_known)
        if event.transfer_context.rolling_outflow_amount is not None:
            event.rolling_outflow_amount = float(event.transfer_context.rolling_outflow_amount)
        if event.transfer_context.face_id_required is not None:
            event.face_id_required = bool(event.transfer_context.face_id_required)
        if event.transfer_context.session_risk_level:
            event.session_risk_level = event.transfer_context.session_risk_level
        if event.transfer_context.session_restrict_large_transfers is not None:
            event.session_restrict_large_transfers = bool(
                event.transfer_context.session_restrict_large_transfers
            )

    if event.behavior_snapshot is not None:
        for attr in [
            "failed_tx_24h",
            "velocity_1h",
            "daily_spend_avg_30d",
            "today_spend_before",
            "projected_daily_spend",
            "recent_review_count_30d",
            "recent_blocked_count_30d",
            "recent_pending_otp_count_7d",
            "recent_inbound_amount_24h",
            "recent_admin_topup_amount_24h",
            "recent_self_deposit_amount_24h",
            "small_probe_count_24h",
            "small_probe_total_24h",
            "distinct_small_probe_recipients_24h",
            "same_recipient_small_probe_count_24h",
            "new_recipient_small_probe_count_24h",
            "probe_then_large_risk_score",
            "rapid_cash_out_risk_score",
        ]:
            value = getattr(event.behavior_snapshot, attr)
            if value is not None:
                setattr(event, attr, value)

    if event.llm_context is not None:
        if event.llm_context.risk_level:
            event.llm_note_risk_level = event.llm_context.risk_level
        if event.llm_context.signal_count is not None:
            event.llm_signal_count = int(event.llm_context.signal_count)
        if event.llm_context.signals:
            event.llm_signals = list(event.llm_context.signals)
        if event.llm_context.rule_tags:
            event.llm_rule_tags = list(event.llm_context.rule_tags)
        if event.llm_context.summary:
            event.llm_summary = event.llm_context.summary
        if event.llm_context.source:
            event.llm_source = event.llm_context.source
        if event.llm_context.model:
            event.llm_model = event.llm_context.model

    event.timestamp = _as_utc(event.timestamp) or event.timestamp
    event.currency = (event.currency or "").strip().upper()[:8] or "UNK"
    event.country = _normalize_country(event.country)
    event.payment_method = (event.payment_method or "").strip().lower()
    event.merchant_category = (event.merchant_category or "").strip().lower()
    event.account_category = normalize_account_category(
        event.account_category,
        event.account_segment,
    )
    event.account_tier = normalize_account_tier(
        event.account_category,
        event.account_tier,
        event.account_segment,
    )
    event.account_segment = derive_account_segment(
        event.account_category,
        event.account_tier,
        event.account_segment,
    )
    event.account_profile_status = _normalize_profile_status(event.account_profile_status)
    event.account_profile_confidence = float(
        min(0.99, max(0.1, float(event.account_profile_confidence or 0.6)))
    )
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
    event.suspicious_note_count = int(max(event.suspicious_note_count, 0))
    event.rolling_outflow_amount = float(max(event.rolling_outflow_amount, 0.0))
    event.recent_review_count_30d = int(max(event.recent_review_count_30d, 0))
    event.recent_blocked_count_30d = int(max(event.recent_blocked_count_30d, 0))
    event.recent_pending_otp_count_7d = int(max(event.recent_pending_otp_count_7d, 0))
    event.small_probe_count_24h = int(max(event.small_probe_count_24h, 0))
    event.small_probe_total_24h = float(max(event.small_probe_total_24h, 0.0))
    event.distinct_small_probe_recipients_24h = int(
        max(event.distinct_small_probe_recipients_24h, 0)
    )
    event.same_recipient_small_probe_count_24h = int(
        max(event.same_recipient_small_probe_count_24h, 0)
    )
    event.new_recipient_small_probe_count_24h = int(
        max(event.new_recipient_small_probe_count_24h, 0)
    )
    event.probe_then_large_risk_score = float(
        min(0.99, max(0.0, float(event.probe_then_large_risk_score or 0.0)))
    )
    event.llm_note_risk_level = _normalize_risk_level(event.llm_note_risk_level)
    event.llm_signal_count = int(max(event.llm_signal_count, 0))
    event.llm_rule_tags = [
        str(tag).strip().lower()
        for tag in event.llm_rule_tags
        if str(tag).strip()
    ][:6]
    event.llm_signals = [
        str(signal).strip()
        for signal in event.llm_signals
        if str(signal).strip()
    ][:6]
    event.llm_summary = str(event.llm_summary).strip()[:240] if event.llm_summary else None
    event.llm_source = str(event.llm_source).strip().lower()[:32] if event.llm_source else None
    event.llm_model = str(event.llm_model).strip()[:120] if event.llm_model else None
    event.session_risk_level = _normalize_risk_level(event.session_risk_level)
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
            str(event.account_segment),
            str(event.account_category),
            str(event.account_tier),
            str(event.account_profile_status),
            str(event.account_profile_confidence),
            str(event.device),
            str(event.failed_tx_24h),
            str(event.velocity_1h),
            str(event.recipient_known),
            str(event.suspicious_note_count),
            str(event.rolling_outflow_amount),
            str(event.session_restrict_large_transfers),
            str(event.small_probe_count_24h),
            str(event.small_probe_total_24h),
            str(event.distinct_small_probe_recipients_24h),
            str(event.same_recipient_small_probe_count_24h),
            str(event.new_recipient_small_probe_count_24h),
            str(event.probe_then_large_risk_score),
            str(event.llm_note_risk_level),
            str(event.llm_signal_count),
            ",".join(event.llm_rule_tags),
            str(event.session_risk_level),
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
        "new_recipient_flag": 0.0 if event.recipient_known else 1.0,
        "suspicious_note_count": float(event.suspicious_note_count),
        "session_transfer_limit_flag": 1.0 if event.session_restrict_large_transfers else 0.0,
        "rolling_outflow_amount_log10": _safe_log10(float(event.rolling_outflow_amount)),
        "face_id_required_flag": 1.0 if event.face_id_required else 0.0,
        "recent_review_count_30d": float(event.recent_review_count_30d),
        "recent_blocked_count_30d": float(event.recent_blocked_count_30d),
        "recent_pending_otp_count_7d": float(event.recent_pending_otp_count_7d),
        # Keep these feature names for backward-compatible artifacts, but
        # decouple LLM note analysis from model-based transaction decisions.
        "llm_note_medium_flag": 0.0,
        "llm_note_high_flag": 0.0,
        "llm_signal_count": 0.0,
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
    thresholds = get_account_profile_thresholds(
        event.account_category,
        event.account_tier,
        event.account_segment,
    )
    historical_risk_amount_floor = max(50.0, float(thresholds["amount_ratio_medium_min"]) * 0.2)
    probe_escalation_amount_floor = max(300.0, float(thresholds["medium_amount"]) * 0.2)
    if event.amount >= thresholds["high_amount"]:
        risk = _max_risk_level(risk, "HIGH")
    elif event.amount >= thresholds["medium_amount"]:
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
        if (
            projected_ratio >= thresholds["projected_high_ratio"]
            and projected_delta >= thresholds["projected_high_delta"]
        ):
            risk = _max_risk_level(risk, "HIGH")
        elif (
            projected_ratio >= thresholds["projected_medium_ratio"]
            and projected_delta >= thresholds["projected_medium_delta"]
        ):
            risk = _max_risk_level(risk, "MEDIUM")
        amount_ratio = event.amount / max(event.daily_spend_avg_30d, 1.0)
        if (
            amount_ratio >= thresholds["amount_ratio_high"]
            and event.amount >= thresholds["amount_ratio_high_min"]
        ):
            risk = _max_risk_level(risk, "HIGH")
        elif (
            amount_ratio >= thresholds["amount_ratio_medium"]
            and event.amount >= thresholds["amount_ratio_medium_min"]
        ):
            risk = _max_risk_level(risk, "MEDIUM")

    if event.balance_before > 0 and _is_material_balance_drain(event):
        drain_ratio = event.amount / max(event.balance_before, 1.0)
        if drain_ratio >= thresholds["high_drain_ratio"]:
            risk = _max_risk_level(risk, "HIGH")
        elif drain_ratio >= thresholds["medium_drain_ratio"]:
            risk = _max_risk_level(risk, "MEDIUM")

    if _is_material_balance_drain(event) and event.remaining_balance <= thresholds["critical_remaining_balance"]:
        risk = _max_risk_level(risk, "HIGH")
    elif _is_material_balance_drain(event) and event.remaining_balance <= thresholds["low_remaining_balance"]:
        risk = _max_risk_level(risk, "MEDIUM")

    if not event.recipient_known and event.amount >= thresholds["new_recipient_amount"]:
        risk = _max_risk_level(risk, "MEDIUM")

    if event.suspicious_note_count >= 2:
        risk = _max_risk_level(risk, "HIGH")
    elif event.suspicious_note_count >= 1 and event.amount >= 500:
        risk = _max_risk_level(risk, "MEDIUM")

    if event.session_restrict_large_transfers and event.amount >= 500:
        risk = _max_risk_level(risk, "HIGH")

    if event.rolling_outflow_amount >= thresholds["rolling_outflow_high"]:
        risk = _max_risk_level(risk, "HIGH")
    elif event.rolling_outflow_amount >= thresholds["rolling_outflow_medium"]:
        risk = _max_risk_level(risk, "MEDIUM")

    if event.face_id_required and event.amount >= 1000:
        risk = _max_risk_level(risk, "MEDIUM")

    if event.amount >= historical_risk_amount_floor and event.recent_blocked_count_30d >= 2:
        risk = _max_risk_level(risk, "HIGH")
    elif (
        event.amount >= historical_risk_amount_floor
        and event.recent_review_count_30d + event.recent_pending_otp_count_7d >= 4
    ):
        risk = _max_risk_level(risk, "MEDIUM")

    if event.amount >= probe_escalation_amount_floor and event.probe_then_large_risk_score >= 0.75:
        risk = _max_risk_level(risk, "HIGH")
    elif event.amount >= probe_escalation_amount_floor and event.probe_then_large_risk_score >= 0.45:
        risk = _max_risk_level(risk, "MEDIUM")

    if (
        event.rapid_cash_out_risk_score >= 0.75
        and event.amount >= max(1000.0, thresholds["medium_amount"] * 0.5)
    ):
        risk = _max_risk_level(risk, "HIGH")
    elif (
        event.rapid_cash_out_risk_score >= 0.45
        and event.amount >= max(750.0, thresholds["medium_amount"] * 0.35)
    ):
        risk = _max_risk_level(risk, "MEDIUM")

    if (
        event.small_probe_count_24h >= 3
        and not event.recipient_known
        and event.amount >= max(500.0, thresholds["medium_amount"] * 0.5)
    ):
        risk = _max_risk_level(risk, "HIGH")
    elif event.same_recipient_small_probe_count_24h >= 2 and event.amount >= 750.0:
        risk = _max_risk_level(risk, "MEDIUM")

    if event.account_profile_status == "PENDING_REVIEW":
        risk = _max_risk_level(risk, "MEDIUM")
    elif event.account_profile_status == "REQUIRES_REVIEW":
        risk = _max_risk_level(risk, "HIGH")

    if event.account_profile_confidence < 0.45 and event.amount >= thresholds["medium_amount"] * 0.75:
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
    thresholds = get_account_profile_thresholds(
        event.account_category,
        event.account_tier,
        event.account_segment,
    )
    historical_risk_amount_floor = max(50.0, float(thresholds["amount_ratio_medium_min"]) * 0.2)
    probe_escalation_amount_floor = max(300.0, float(thresholds["medium_amount"]) * 0.2)
    profile_label = str(
        thresholds.get("label") or normalize_account_segment(event.account_segment).lower()
    )
    feature_names = list(TX_FEATURE_NAMES[: len(features)])
    feature_positions = {name: index for index, name in enumerate(feature_names)}

    if countries and event.country.strip().lower() not in countries:
        reasons.append("New transaction country compared to learned behavior")
    if payment_methods and event.payment_method not in payment_methods:
        reasons.append("New payment method")
    if merchant_categories and event.merchant_category not in merchant_categories:
        reasons.append("New merchant category")
    if event.amount >= thresholds["high_amount"]:
        reasons.append(f"Very high transaction amount for a {profile_label} account")
    elif event.amount >= thresholds["medium_amount"]:
        reasons.append(f"High transaction amount for a {profile_label} account")
    if event.failed_tx_24h >= 1:
        reasons.append("Recent failed transactions within 24h")
    if event.velocity_1h >= 3:
        reasons.append("High transaction velocity in 1h")
    if event.daily_spend_avg_30d > 0:
        projected_ratio = event.projected_daily_spend / max(event.daily_spend_avg_30d, 1.0)
        if projected_ratio >= thresholds["projected_high_ratio"]:
            reasons.append("Projected daily spend is far above normal behavior")
        elif projected_ratio >= thresholds["projected_medium_ratio"]:
            reasons.append("Projected daily spend is significantly above normal behavior")
        amount_ratio = event.amount / max(event.daily_spend_avg_30d, 1.0)
        if amount_ratio >= thresholds["amount_ratio_high"]:
            reasons.append("Transaction amount is far above the user's usual daily spend")
        elif amount_ratio >= thresholds["amount_ratio_medium"]:
            reasons.append("Transaction amount is well above the user's usual daily spend")
    if event.balance_before > 0 and _is_material_balance_drain(event):
        drain_ratio = event.amount / max(event.balance_before, 1.0)
        if drain_ratio >= thresholds["high_drain_ratio"]:
            reasons.append("Transfer would use almost all available wallet balance")
        elif drain_ratio >= thresholds["medium_drain_ratio"]:
            reasons.append("Transfer would use most of the available wallet balance")
    if _is_material_balance_drain(event) and event.remaining_balance <= thresholds["critical_remaining_balance"]:
        reasons.append("Transfer would leave the wallet nearly empty")
    elif _is_material_balance_drain(event) and event.remaining_balance <= thresholds["low_remaining_balance"]:
        reasons.append("Transfer would leave only a very small remaining balance")
    if not event.recipient_known:
        reasons.append("Recipient is new or not established in transfer history")
    if event.suspicious_note_count >= 1:
        reasons.append("Transfer note contains scam-like or pressure language")
    if event.session_restrict_large_transfers:
        reasons.append("This sign-in session is already under temporary large-transfer restriction")
    if event.rolling_outflow_amount >= thresholds["rolling_outflow_medium"]:
        reasons.append("Rolling outgoing transfer volume is elevated for this session")
    if event.face_id_required:
        reasons.append("Server step-up policy already requires FaceID for this transfer path")
    if event.amount >= historical_risk_amount_floor and event.recent_review_count_30d >= 1:
        reasons.append("User had recent transfers sent to review in the last 30 days")
    if event.amount >= historical_risk_amount_floor and event.recent_blocked_count_30d >= 1:
        reasons.append("User had recent transfers blocked in the last 30 days")
    if event.amount >= historical_risk_amount_floor and event.recent_pending_otp_count_7d >= 3:
        reasons.append("Multiple recent transfer OTP flows were started in the last 7 days")
    if event.amount >= probe_escalation_amount_floor and event.small_probe_count_24h >= 3:
        reasons.append("Multiple small outbound transfers appeared shortly before this higher-value transfer")
    if event.amount >= probe_escalation_amount_floor and event.distinct_small_probe_recipients_24h >= 2:
        reasons.append("Recent small-value transfers touched multiple recipients in a short period")
    if event.amount >= probe_escalation_amount_floor and event.same_recipient_small_probe_count_24h >= 2:
        reasons.append("The same recipient already saw repeated small-value tests before this transfer")
    if event.amount >= probe_escalation_amount_floor and event.new_recipient_small_probe_count_24h >= 2:
        reasons.append("Recent small-value probes targeted new recipients")
    if event.amount >= probe_escalation_amount_floor and event.probe_then_large_risk_score >= 0.65:
        reasons.append("Behavior resembles a probe-then-escalate fraud pattern")
    if (
        event.rapid_cash_out_risk_score >= 0.45
        and event.amount >= max(750.0, thresholds["medium_amount"] * 0.35)
    ):
        reasons.append("Funds recently entered the wallet and are being moved back out unusually quickly")
    if (
        event.recent_admin_topup_amount_24h > 0
        and event.amount >= max(1000.0, event.recent_admin_topup_amount_24h * 0.75)
    ):
        reasons.append("Recent admin top-up is being cashed out unusually quickly")
    if event.account_profile_status == "PENDING_REVIEW":
        reasons.append("Account profile change is pending review, so large-value behavior is treated more cautiously")
    elif event.account_profile_status == "REQUIRES_REVIEW":
        reasons.append("Account profile confidence is degraded and requires manual review")
    if event.account_profile_confidence < 0.45:
        reasons.append("Account profile confidence is low, so baseline relaxation is limited")
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
    if (
        feature_positions.get("rolling_outflow_amount_log10") is not None
        and z_scores[feature_positions["rolling_outflow_amount_log10"]] > 2.0
    ):
        reasons.append("Rolling outgoing transfer amount is unusually high")
    if (
        feature_positions.get("recent_blocked_count_30d") is not None
        and z_scores[feature_positions["recent_blocked_count_30d"]] > 2.0
    ):
        reasons.append("Recent blocked-transfer count is unusually high")
    if (
        feature_positions.get("recent_pending_otp_count_7d") is not None
        and z_scores[feature_positions["recent_pending_otp_count_7d"]] > 2.0
    ):
        reasons.append("Recent transfer verification attempts are unusually frequent")
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
