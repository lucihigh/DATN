from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.transaction_model import TransactionEvent

RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
SEVERITY_SCORE = {"LOW": 5, "MEDIUM": 15, "HIGH": 30}
HIGH_RISK_GEO = {"IR", "KP", "SY", "CU", "AF"}
HIGH_RISK_MERCHANTS = {
    "crypto",
    "crypto_exchange",
    "gambling",
    "betting",
    "gift_card",
    "wallet_topup",
    "money_transfer",
    "p2p_transfer",
}
HIGH_RISK_PAYMENT_METHODS = {
    "crypto",
    "wire",
    "bank_transfer",
    "wallet_balance",
    "gift_card",
}
COMMON_CURRENCIES = {"USD", "VND", "EUR", "GBP", "JPY", "SGD", "AUD", "CAD"}


@dataclass
class RuleHit:
    rule_id: str
    title: str
    category: str
    aml_stage: str
    risk_level: str
    reason: str
    user_warning: str
    recommended_actions: list[str]
    tags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "aml_stage": self.aml_stage,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "user_warning": self.user_warning,
            "recommended_actions": self.recommended_actions,
            "tags": self.tags,
        }


@dataclass
class RuleEvaluation:
    rule_risk_level: str
    rule_score: int
    hits: list[RuleHit]
    warning_title: str
    warning_message: str
    do_not: list[str]
    must_do: list[str]
    prompt_template_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_risk_level": self.rule_risk_level,
            "rule_score": self.rule_score,
            "hit_count": len(self.hits),
            "hits": [hit.to_dict() for hit in self.hits],
            "warning_vi": {
                "title": self.warning_title,
                "message": self.warning_message,
                "do_not": self.do_not,
                "must_do": self.must_do,
                "prompt_template_id": self.prompt_template_id,
            },
        }


def _max_risk(a: str, b: str) -> str:
    return a if RISK_RANK.get(a, -1) >= RISK_RANK.get(b, -1) else b


def _append_hit(
    hits: list[RuleHit],
    *,
    rule_id: str,
    title: str,
    category: str,
    aml_stage: str,
    risk_level: str,
    reason: str,
    user_warning: str,
    actions: list[str],
    tags: list[str],
) -> None:
    hits.append(
        RuleHit(
            rule_id=rule_id,
            title=title,
            category=category,
            aml_stage=aml_stage,
            risk_level=risk_level,
            reason=reason,
            user_warning=user_warning,
            recommended_actions=actions,
            tags=tags,
        )
    )


def evaluate_transaction_rules(event: TransactionEvent, learned_countries: set[str] | None = None) -> RuleEvaluation:
    hits: list[RuleHit] = []
    amount = float(event.amount)
    failed = int(event.failed_tx_24h)
    velocity = int(event.velocity_1h)
    daily_avg = max(float(event.daily_spend_avg_30d), 0.0)
    projected = max(float(event.projected_daily_spend), 0.0)
    balance_before = max(float(event.balance_before), 0.0)
    remaining = max(float(event.remaining_balance), 0.0)
    amount_ratio = amount / max(daily_avg, 1.0) if daily_avg > 0 else 0.0
    projected_ratio = projected / max(daily_avg, 1.0) if daily_avg > 0 else 0.0
    projected_delta = max(projected - daily_avg, 0.0)
    drain_ratio = amount / max(balance_before, 1.0) if balance_before > 0 else 0.0
    country = str(event.country or "").upper().strip()
    payment_method = str(event.payment_method or "").lower().strip()
    merchant = str(event.merchant_category or "").lower().strip()
    currency = str(event.currency or "").upper().strip()

    if amount >= 20000:
        _append_hit(
            hits,
            rule_id="TXR001",
            title="Very large transfer",
            category="amount_spike",
            aml_stage="placement",
            risk_level="HIGH",
            reason="Single transfer amount is extremely high.",
            user_warning="Giao dịch giá trị rất lớn, có thể là lừa đảo hoặc rửa tiền.",
            actions=["Tạm dừng giao dịch.", "Xác minh người nhận qua kênh chính thức."],
            tags=["high_amount", "critical"],
        )
    elif amount >= 7000:
        _append_hit(
            hits,
            rule_id="TXR002",
            title="High-value transfer",
            category="amount_spike",
            aml_stage="placement",
            risk_level="MEDIUM",
            reason="Transfer amount is high compared to common behavior.",
            user_warning="Giao dịch cao bất thường, cần kiểm tra thêm trước khi chuyển.",
            actions=["Xác thực lại mục đích chuyển tiền.", "Kiểm tra lịch sử người nhận."],
            tags=["high_amount"],
        )

    if failed >= 3:
        _append_hit(
            hits,
            rule_id="TXR003",
            title="Repeated failed attempts",
            category="account_takeover",
            aml_stage="placement",
            risk_level="HIGH",
            reason="Multiple failed transactions in the last 24h.",
            user_warning="Có dấu hiệu tài khoản bị thử thao tác bất thường.",
            actions=["Đổi mật khẩu và kiểm tra bảo mật tài khoản.", "Bật xác thực 2 lớp."],
            tags=["failed_attempts", "ato"],
        )

    if velocity >= 6:
        _append_hit(
            hits,
            rule_id="TXR004",
            title="Burst transfer velocity",
            category="smurfing",
            aml_stage="layering",
            risk_level="HIGH",
            reason="Transaction velocity in 1h is abnormally high.",
            user_warning="Nhiều giao dịch dồn dập, có thể là chia nhỏ để né kiểm soát.",
            actions=["Tạm khóa luồng chuyển tiền nhanh.", "Yêu cầu xác minh tăng cường."],
            tags=["velocity", "smurfing"],
        )
    elif velocity >= 3:
        _append_hit(
            hits,
            rule_id="TXR005",
            title="Elevated transfer velocity",
            category="velocity",
            aml_stage="layering",
            risk_level="MEDIUM",
            reason="Velocity exceeds normal user pattern.",
            user_warning="Tần suất giao dịch cao hơn bình thường.",
            actions=["Xác nhận từng giao dịch giá trị lớn.", "Giới hạn tốc độ giao dịch tạm thời."],
            tags=["velocity"],
        )

    if daily_avg > 0 and projected_ratio >= 20 and projected_delta >= 4000:
        _append_hit(
            hits,
            rule_id="TXR006",
            title="Extreme projected spend jump",
            category="spend_jump",
            aml_stage="layering",
            risk_level="HIGH",
            reason="Projected daily spend is far above baseline.",
            user_warning="Mức chi dự kiến tăng đột biến so với lịch sử.",
            actions=["Áp dụng xác thực bổ sung.", "Đưa vào hàng chờ review thủ công."],
            tags=["projected_spike"],
        )

    if daily_avg > 0 and amount_ratio >= 8 and amount >= 1500:
        _append_hit(
            hits,
            rule_id="TXR007",
            title="Outlier amount ratio",
            category="behavioral_anomaly",
            aml_stage="placement",
            risk_level="HIGH",
            reason="Amount is many times above user daily average.",
            user_warning="Số tiền vượt rất xa mức chi tiêu quen thuộc.",
            actions=["Yêu cầu xác thực người dùng bằng OTP/Sinh trắc học.", "Xác minh danh tính người nhận."],
            tags=["amount_ratio", "behavior_shift"],
        )

    if balance_before > 0 and drain_ratio >= 0.9 and amount >= 1000:
        _append_hit(
            hits,
            rule_id="TXR008",
            title="Near-total balance drain",
            category="wallet_drain",
            aml_stage="placement",
            risk_level="HIGH",
            reason="Transfer drains almost entire available balance.",
            user_warning="Giao dịch gần như rút cạn số dư ví.",
            actions=["Hiển thị cảnh báo đỏ và trì hoãn chuyển tiền.", "Xác nhận lại ý định giao dịch 2 lần."],
            tags=["drain", "scam_exit"],
        )

    if amount >= 1000 and remaining <= 10:
        _append_hit(
            hits,
            rule_id="TXR009",
            title="Near-empty post transfer balance",
            category="wallet_drain",
            aml_stage="placement",
            risk_level="MEDIUM",
            reason="Transfer leaves the account nearly empty.",
            user_warning="Sau giao dịch số dư còn rất thấp.",
            actions=["Khuyên người dùng kiểm tra lại thông tin người nhận.", "Đề xuất giao dịch thử số tiền nhỏ trước."],
            tags=["low_remaining_balance"],
        )

    if merchant in HIGH_RISK_MERCHANTS:
        _append_hit(
            hits,
            rule_id="TXR010",
            title="High-risk merchant category",
            category="high_risk_counterparty",
            aml_stage="layering",
            risk_level="HIGH" if merchant in {"crypto", "crypto_exchange", "gift_card"} else "MEDIUM",
            reason="Merchant category is frequently used in scam cash-out paths.",
            user_warning="Danh mục người nhận có rủi ro cao.",
            actions=["Yêu cầu thêm thông tin hóa đơn/chứng từ.", "Giảm hạn mức tức thời cho giao dịch này."],
            tags=["merchant_risk", merchant],
        )

    if payment_method in HIGH_RISK_PAYMENT_METHODS:
        _append_hit(
            hits,
            rule_id="TXR011",
            title="High-risk payment rail",
            category="payment_rail",
            aml_stage="layering",
            risk_level="MEDIUM",
            reason="Payment rail has elevated irreversibility or laundering risk.",
            user_warning="Phương thức thanh toán này có độ rủi ro hoàn trả thấp.",
            actions=["Yêu cầu bước xác minh mạnh hơn trước khi gửi.", "Tăng thời gian chờ xác nhận."],
            tags=["payment_method", payment_method],
        )

    if country in HIGH_RISK_GEO:
        _append_hit(
            hits,
            rule_id="TXR012",
            title="Sanction-sensitive geography",
            category="geography",
            aml_stage="integration",
            risk_level="HIGH",
            reason="Destination geography is sanction-sensitive.",
            user_warning="Giao dịch liên quan khu vực rủi ro tuân thủ cao.",
            actions=["Chặn tạm thời và chuyển Compliance review.", "Đối chiếu danh sách cấm vận/PEP."],
            tags=["sanction_geo", country],
        )

    if learned_countries and country and country.lower() not in learned_countries:
        _append_hit(
            hits,
            rule_id="TXR013",
            title="New destination country",
            category="geography",
            aml_stage="placement",
            risk_level="MEDIUM",
            reason="Country differs from learned user behavior.",
            user_warning="Đây là quốc gia giao dịch mới so với lịch sử.",
            actions=["Yêu cầu xác nhận bổ sung.", "Kiểm tra nguồn gốc yêu cầu chuyển tiền."],
            tags=["new_country"],
        )

    hour = int(event.timestamp.hour)
    if hour <= 4 and amount >= 2000:
        _append_hit(
            hits,
            rule_id="TXR014",
            title="Off-hour high transfer",
            category="temporal_anomaly",
            aml_stage="placement",
            risk_level="MEDIUM",
            reason="High-value transfer at unusual off-hour window.",
            user_warning="Giao dịch lớn diễn ra vào khung giờ khuya.",
            actions=["Yêu cầu xác nhận thủ công qua kênh tin cậy.", "Thêm thời gian chờ chống nhầm lẫn."],
            tags=["off_hour"],
        )

    if currency and currency not in COMMON_CURRENCIES and amount >= 1500:
        _append_hit(
            hits,
            rule_id="TXR015",
            title="Uncommon currency with material amount",
            category="currency_anomaly",
            aml_stage="layering",
            risk_level="MEDIUM",
            reason="Uncommon currency combined with significant transfer amount.",
            user_warning="Loại tiền tệ ít dùng kết hợp số tiền đáng kể.",
            actions=["Tăng mức độ xác thực cho giao dịch ngoại lệ.", "Kiểm tra mục đích giao dịch."],
            tags=["currency_anomaly"],
        )

    if 150 <= amount <= 999 and velocity >= 6 and failed >= 1:
        _append_hit(
            hits,
            rule_id="TXR016",
            title="Potential smurfing pattern",
            category="smurfing",
            aml_stage="layering",
            risk_level="HIGH",
            reason="Many medium-small transfers clustered in short time.",
            user_warning="Dấu hiệu chia nhỏ giao dịch để né ngưỡng kiểm soát.",
            actions=["Tổng hợp giao dịch theo cụm 1h để đánh giá.", "Áp ngưỡng kiểm soát tổng theo phiên."],
            tags=["smurfing", "structuring"],
        )

    if payment_method == "crypto" and velocity >= 4 and amount >= 1000:
        _append_hit(
            hits,
            rule_id="TXR017",
            title="Rapid crypto layering behavior",
            category="crypto_layering",
            aml_stage="layering",
            risk_level="HIGH",
            reason="Crypto rail and rapid repeated transfers indicate layering behavior.",
            user_warning="Dòng tiền crypto có tốc độ cao, giống hành vi rửa tiền.",
            actions=["Gắn cờ AML và yêu cầu hồ sơ nguồn tiền.", "Theo dõi chuỗi ví liên quan."],
            tags=["crypto", "layering"],
        )

    if merchant == "p2p_transfer" and velocity >= 5 and failed >= 1:
        _append_hit(
            hits,
            rule_id="TXR018",
            title="Potential mule-account relay",
            category="mule_account",
            aml_stage="layering",
            risk_level="HIGH",
            reason="P2P transfer bursts with failure retries resemble mule relay behavior.",
            user_warning="Có dấu hiệu tài khoản trung gian nhận/chuyển nhanh.",
            actions=["Giới hạn chuyển tiếp P2P.", "Yêu cầu xác minh nâng cao với chủ tài khoản."],
            tags=["mule", "relay"],
        )

    if projected_ratio >= 10 and velocity >= 4 and amount >= 1200:
        _append_hit(
            hits,
            rule_id="TXR019",
            title="Composite laundering indicator",
            category="multi_signal",
            aml_stage="layering",
            risk_level="HIGH",
            reason="Spend spike + speed + amount indicates compounded laundering/scam risk.",
            user_warning="Tổ hợp nhiều tín hiệu rủi ro đồng thời.",
            actions=["Bắt buộc review thủ công trước khi hoàn tất.", "Lưu nhật ký đầy đủ để điều tra."],
            tags=["composite", "high_confidence"],
        )

    if merchant in {"gift_card", "wallet_topup"} and amount >= 500:
        _append_hit(
            hits,
            rule_id="TXR020",
            title="Fast cash-out rail",
            category="cash_out",
            aml_stage="integration",
            risk_level="HIGH",
            reason="Gift-card/wallet-topup rails are often used for irreversible cash-out.",
            user_warning="Kênh chuyển tiền có tính chất rút tiền nhanh, khó thu hồi.",
            actions=["Áp dụng delay bắt buộc.", "Hiển thị cảnh báo chống lừa đảo trước xác nhận."],
            tags=["cash_out", "irreversible"],
        )

    if event.small_probe_count_24h >= 3 and amount >= 500:
        _append_hit(
            hits,
            rule_id="TXR021",
            title="Probe then escalate pattern",
            category="account_takeover",
            aml_stage="placement",
            risk_level="HIGH" if event.probe_then_large_risk_score >= 0.75 else "MEDIUM",
            reason="Several small outbound transfers appeared before a materially larger payment.",
            user_warning="Co dau hieu thu giao dich nho de do tai khoan/nguoi nhan roi moi nang len giao dich lon.",
            actions=[
                "Tam dung giao dich va xac minh nguoi nhan qua kenh doc lap.",
                "Kiem tra cac giao dich nho gan day truoc khi tiep tuc.",
            ],
            tags=["probe", "account_testing", "ato"],
        )

    if event.same_recipient_small_probe_count_24h >= 2 and amount >= 750:
        _append_hit(
            hits,
            rule_id="TXR022",
            title="Recipient validation before payout",
            category="beneficiary_risk",
            aml_stage="placement",
            risk_level="HIGH" if not event.recipient_known else "MEDIUM",
            reason="The same recipient was hit by repeated small-value tests before this transfer.",
            user_warning="Nguoi nhan nay vua co nhieu giao dich nho thu nghiem truoc khi co lenh chuyen lon.",
            actions=[
                "Yeu cau xac minh nguoi nhan va muc dich giao dich.",
                "Tang cuong buoc OTP va review thu cong neu can.",
            ],
            tags=["recipient_probe", "beneficiary_test"],
        )

    if event.distinct_small_probe_recipients_24h >= 3 and amount >= 500:
        _append_hit(
            hits,
            rule_id="TXR023",
            title="Multi-recipient probe burst",
            category="velocity",
            aml_stage="layering",
            risk_level="MEDIUM",
            reason="Small transfers touched multiple recipients in a short period before the current payment.",
            user_warning="Nhieu nguoi nhan da bi thu giao dich nho trong thoi gian ngan.",
            actions=[
                "Kiem tra xem tai khoan co dang bi dung de do hoac relay tien hay khong.",
                "Gioi han giao dich voi nguoi nhan moi cho den khi duoc xac minh.",
            ],
            tags=["multi_recipient_probe", "mule"],
        )

    if (
        event.rapid_cash_out_risk_score >= 0.7
        and amount >= 1000
        and event.recent_inbound_amount_24h > 0
    ):
        _append_hit(
            hits,
            rule_id="TXR024",
            title="Rapid source-in/source-out pattern",
            category="rapid_cash_out",
            aml_stage="layering",
            risk_level="HIGH",
            reason="A large recent inflow is being transferred back out unusually quickly.",
            user_warning="Funds entered this wallet recently and are now leaving too quickly, which resembles a laundering or mule-account cash-out pattern.",
            actions=[
                "Place the transfer on hold and verify the source of funds before releasing it.",
                "Review whether the recent inflow and this outflow are commercially or personally explainable.",
            ],
            tags=["rapid_cash_out", "source_of_funds", "aml"],
        )

    if (
        event.recent_admin_topup_amount_24h > 0
        and amount >= max(1000, event.recent_admin_topup_amount_24h * 0.75)
    ):
        _append_hit(
            hits,
            rule_id="TXR025",
            title="Admin top-up followed by quick cash-out",
            category="topup_cashout",
            aml_stage="layering",
            risk_level="HIGH",
            reason="Recent admin-provided funds are being moved out almost immediately.",
            user_warning="A recent top-up is being cashed out unusually quickly and needs manual verification before release.",
            actions=[
                "Pause the transfer and confirm why recently credited funds are leaving the wallet immediately.",
                "Require manual review before approving this payout.",
            ],
            tags=["admin_topup", "cash_out", "aml"],
        )

    max_level = "LOW"
    score = 0
    for hit in hits:
        max_level = _max_risk(max_level, hit.risk_level)
        score += SEVERITY_SCORE.get(hit.risk_level, 0)

    bucket_level = "LOW"
    if score >= 60:
        bucket_level = "HIGH"
    elif score >= 25:
        bucket_level = "MEDIUM"
    final_level = _max_risk(max_level, bucket_level)

    top_messages = [hit.user_warning for hit in hits[:3]]
    summary = "; ".join(top_messages) if top_messages else "Chưa phát hiện dấu hiệu rủi ro rõ ràng."

    if final_level == "HIGH":
        title = "Canh bao do: Nguy co lua dao/rua tien cao"
        do_not = [
            "Khong chuyen tien ngay khi bi thuc giuc hoac de doa.",
            "Khong chia se OTP, PIN, mat khau, ma xac thuc.",
            "Khong tiep tuc neu khong xac minh duoc nguoi nhan.",
        ]
        must_do = [
            "Pause the transfer and call the official support hotline.",
            "Xac minh danh tinh nguoi nhan qua kenh doc lap.",
            "Bat xac thuc da lop va doi mat khau neu nghi ngo bi lo.",
        ]
        prompt_template_id = "vi_warning_high_v1"
    elif final_level == "MEDIUM":
        title = "Canh bao vang: Giao dich can xac minh them"
        do_not = [
            "Khong bam link la trong tin nhan/chats.",
            "Khong bo qua canh bao an toan de chuyen nhanh.",
            "Khong chuyen toan bo so du trong mot lan.",
        ]
        must_do = [
            "Kiem tra lich su nguoi nhan va noi dung giao dich.",
            "Uu tien chuyen thu so tien nho neu can.",
            "Dung kenh chinh chu de xac thuc thong tin.",
        ]
        prompt_template_id = "vi_warning_medium_v1"
    else:
        title = "Thong bao: Chua thay rui ro cao"
        do_not = ["Khong chia se ma OTP/PIN cho bat ky ai."]
        must_do = ["Tiep tuc theo doi canh bao va bao cao neu thay bat thuong."]
        prompt_template_id = "vi_warning_low_v1"

    return RuleEvaluation(
        rule_risk_level=final_level,
        rule_score=score,
        hits=hits,
        warning_title=title,
        warning_message=summary,
        do_not=do_not,
        must_do=must_do,
        prompt_template_id=prompt_template_id,
    )
