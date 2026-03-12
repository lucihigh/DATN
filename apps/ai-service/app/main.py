import json
import os
import re
import unicodedata
from datetime import datetime, timezone
from math import ceil
from typing import Any, Literal
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen

from fastapi import FastAPI
from pydantic import BaseModel, Field

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

app = FastAPI(title="AI Market Copilot")
openai_client = (
    OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    if OpenAI and os.getenv("OPENAI_API_KEY")
    else None
)

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5-mini")
FX_API_URL = os.getenv("FX_API_URL", "https://open.er-api.com/v6/latest")
CRYPTO_API_URL = os.getenv(
    "CRYPTO_API_URL", "https://api.coingecko.com/api/v3/simple/price"
)
GOLD_API_URL = os.getenv("GOLD_API_URL", "https://api.gold-api.com/price/XAU")
SILVER_API_URL = os.getenv("SILVER_API_URL", "https://api.gold-api.com/price/XAG")
STOCK_API_URL = os.getenv("STOCK_API_URL", "https://stooq.com/q/l/")

VIETNAMESE_ACCENTS = (
    "ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệ"
    "óòỏõọốồổỗộớờởỡợúùủũụứừửữựíìỉĩịýỳỷỹỵ"
)
PRICE_KEYWORDS = {
    "price",
    "quote",
    "gia",
    "bao nhieu",
    "hom nay",
    "today",
    "spot",
    "current",
    "now",
}
COMPARE_KEYWORDS = {"compare", "comparison", "vs", "versus", "so sanh"}
OUTLOOK_KEYWORDS = {
    "outlook",
    "forecast",
    "trend",
    "xu huong",
    "nhan dinh",
    "view",
    "khan nang",
}
STRATEGY_KEYWORDS = {
    "should i buy",
    "should i sell",
    "co nen mua",
    "co nen ban",
    "entry",
    "allocation",
    "phan bo",
    "chien luoc",
    "strategy",
    "dca",
    "all in",
}
EXPLAIN_KEYWORDS = {
    "what is",
    "explain",
    "tai sao",
    "vi sao",
    "la gi",
    "how does",
    "anh huong",
    "impact",
}
OVERVIEW_KEYWORDS = {
    "thi truong",
    "market today",
    "market overview",
    "tong quan",
    "toan canh",
    "money market",
}
DEPOSIT_KEYWORDS = {
    "deposit",
    "top up",
    "top-up",
    "save",
    "saving",
    "emergency",
    "fund",
    "nap",
    "tiet kiem",
    "du phong",
}
CASH_FLOW_KEYWORDS = {
    "cash flow",
    "expense",
    "spending",
    "budget",
    "chi tieu",
    "dong tien",
    "ngan sach",
}
MARKET_SYSTEM_PROMPT = """
You are FPIPay Market Copilot.

Scope:
- Answer questions about forex/currencies, stocks, ETFs, indices, gold, silver, crypto, and market risk.
- Use the supplied marketContext and exchangeRateQuote as the source of truth for live prices.
- If live data is missing for a current-market claim, say that clearly instead of guessing.
- For market outlook questions, discuss drivers, risk, and scenarios. Do not promise returns.
- Be concise, practical, and grounded.

Language:
- Reply in Vietnamese when the user's latest message is Vietnamese.
- Reply in English when the user's latest message is English.

Output:
- Return strict JSON only.
- Schema keys: reply, topic, suggestedActions, suggestedDepositAmount, riskLevel, confidence, followUpQuestion.
- suggestedDepositAmount must be null unless the user is explicitly asking for savings/deposit planning.
- riskLevel must be one of low, medium, high.
- confidence must be between 0 and 1.
""".strip()

CURRENCY_ALIASES = {
    "usd": "USD",
    "dollar": "USD",
    "dollars": "USD",
    "us dollar": "USD",
    "do la": "USD",
    "do": "USD",
    "my": "USD",
    "eur": "EUR",
    "euro": "EUR",
    "vnd": "VND",
    "dong": "VND",
    "viet nam dong": "VND",
    "jpy": "JPY",
    "yen": "JPY",
    "gbp": "GBP",
    "pound": "GBP",
    "aud": "AUD",
    "cad": "CAD",
    "sgd": "SGD",
    "cny": "CNY",
    "yuan": "CNY",
    "hkd": "HKD",
    "krw": "KRW",
    "won": "KRW",
    "thb": "THB",
    "baht": "THB",
    "chf": "CHF",
    "nzd": "NZD",
    "inr": "INR",
    "aed": "AED",
    "sek": "SEK",
    "nok": "NOK",
    "dkk": "DKK",
    "pln": "PLN",
}
SUPPORTED_CURRENCY_CODES = set(CURRENCY_ALIASES.values())
CRYPTO_ALIASES = {
    "bitcoin": ("bitcoin", "BTC"),
    "btc": ("bitcoin", "BTC"),
    "ethereum": ("ethereum", "ETH"),
    "eth": ("ethereum", "ETH"),
    "solana": ("solana", "SOL"),
    "sol": ("solana", "SOL"),
    "binance coin": ("binancecoin", "BNB"),
    "bnb": ("binancecoin", "BNB"),
    "xrp": ("ripple", "XRP"),
    "ripple": ("ripple", "XRP"),
    "doge": ("dogecoin", "DOGE"),
    "dogecoin": ("dogecoin", "DOGE"),
    "ada": ("cardano", "ADA"),
    "cardano": ("cardano", "ADA"),
}
METAL_ALIASES = {
    "gold": ("gold", "XAU", "Gold"),
    "xau": ("gold", "XAU", "Gold"),
    "vang": ("gold", "XAU", "Gold"),
    "silver": ("silver", "XAG", "Silver"),
    "xag": ("silver", "XAG", "Silver"),
    "bac": ("silver", "XAG", "Silver"),
}
STOOQ_REFERENCE_ALIASES = {
    "aapl": ("stock", "aapl.us", "Apple"),
    "apple": ("stock", "aapl.us", "Apple"),
    "msft": ("stock", "msft.us", "Microsoft"),
    "microsoft": ("stock", "msft.us", "Microsoft"),
    "nvda": ("stock", "nvda.us", "NVIDIA"),
    "nvidia": ("stock", "nvda.us", "NVIDIA"),
    "tsla": ("stock", "tsla.us", "Tesla"),
    "tesla": ("stock", "tsla.us", "Tesla"),
    "amzn": ("stock", "amzn.us", "Amazon"),
    "amazon": ("stock", "amzn.us", "Amazon"),
    "googl": ("stock", "googl.us", "Alphabet"),
    "goog": ("stock", "goog.us", "Alphabet"),
    "google": ("stock", "googl.us", "Alphabet"),
    "alphabet": ("stock", "googl.us", "Alphabet"),
    "meta": ("stock", "meta.us", "Meta"),
    "facebook": ("stock", "meta.us", "Meta"),
    "amd": ("stock", "amd.us", "AMD"),
    "spy": ("etf", "spy.us", "SPDR S&P 500 ETF"),
    "qqq": ("etf", "qqq.us", "Invesco QQQ"),
    "dia": ("etf", "dia.us", "SPDR Dow Jones ETF"),
    "gld": ("etf", "gld.us", "SPDR Gold Shares"),
    "slv": ("etf", "slv.us", "iShares Silver Trust"),
    "sp500": ("index", "^spx", "S&P 500"),
    "s&p 500": ("index", "^spx", "S&P 500"),
    "spx": ("index", "^spx", "S&P 500"),
    "nasdaq": ("index", "^ndq", "Nasdaq 100"),
    "nasdaq 100": ("index", "^ndq", "Nasdaq 100"),
    "ndx": ("index", "^ndq", "Nasdaq 100"),
    "dow": ("index", "^dji", "Dow Jones Industrial Average"),
    "dow jones": ("index", "^dji", "Dow Jones Industrial Average"),
    "djia": ("index", "^dji", "Dow Jones Industrial Average"),
    "dxy": ("index", "dx.f", "US Dollar Index"),
    "usd index": ("index", "dx.f", "US Dollar Index"),
    "dollar index": ("index", "dx.f", "US Dollar Index"),
    "oil": ("commodity", "cl.f", "WTI Crude Oil"),
    "crude": ("commodity", "cl.f", "WTI Crude Oil"),
    "wti": ("commodity", "cl.f", "WTI Crude Oil"),
}
COMMON_TICKER_STOPWORDS = {
    "THE",
    "AND",
    "FOR",
    "YOU",
    "FED",
    "ETF",
    "USD",
    "EUR",
    "VND",
    "JPY",
    "GBP",
    "AUD",
    "CAD",
    "SGD",
    "CNY",
    "THB",
    "XAU",
    "XAG",
    "BTC",
    "ETH",
    "SOL",
    "BNB",
    "XRP",
    "ADA",
}


class LoginEvent(BaseModel):
    userId: str | None = None
    ipAddress: str
    userAgent: str | None = None
    timestamp: str | None = None


class DepositAgentRequest(BaseModel):
    userId: str | None = None
    goal: str
    currency: str = "USD"
    currentBalance: float = 0
    monthlyIncome: float | None = None
    monthlyExpenses: float | None = None


class DepositAgentResponse(BaseModel):
    recommendedAmount: float
    reasoning: list[str]
    riskLevel: Literal["low", "medium", "high"]
    nextAction: str
    confidence: float


class CopilotMessage(BaseModel):
    role: str
    content: str


class CopilotTransaction(BaseModel):
    amount: float
    type: str
    description: str | None = None
    createdAt: str
    direction: str = "debit"


class CopilotRequest(BaseModel):
    userId: str | None = None
    currency: str = "USD"
    currentBalance: float = 0
    monthlyIncome: float | None = None
    monthlyExpenses: float | None = None
    recentTransactions: list[CopilotTransaction] = Field(default_factory=list)
    messages: list[CopilotMessage]


class CopilotResponse(BaseModel):
    reply: str
    topic: str
    suggestedActions: list[str]
    suggestedDepositAmount: float | None = None
    riskLevel: str
    confidence: float
    followUpQuestion: str | None = None


class CopilotResult(BaseModel):
    reply: str
    topic: str
    suggestedActions: list[str]
    suggestedDepositAmount: float | None = None
    riskLevel: str
    confidence: float
    followUpQuestion: str | None = None


class ExchangeRateQuote(BaseModel):
    base: str
    quote: str
    amount: float
    convertedAmount: float
    rate: float
    date: str
    source: str


class MarketQuote(BaseModel):
    assetType: str
    symbol: str
    name: str
    price: float
    currency: str
    convertedPrice: float | None = None
    convertedCurrency: str | None = None
    updatedAt: str
    source: str
    note: str
    openPrice: float | None = None
    highPrice: float | None = None
    lowPrice: float | None = None
    sessionChangePct: float | None = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def fold_text(text: str) -> str:
    lowered = (text or "").lower().strip()
    normalized = "".join(
        char
        for char in unicodedata.normalize("NFKD", lowered)
        if not unicodedata.combining(char)
    )
    normalized = normalized.replace("đ", "d")
    return re.sub(r"\s+", " ", normalized)


def contains_term(text: str, term: str) -> bool:
    pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
    return re.search(pattern, text) is not None


def parse_float(value: str | None) -> float | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned or cleaned == "N/D":
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def detect_language(text: str) -> Literal["vi", "en"]:
    lowered = (text or "").lower()
    folded = fold_text(text)
    if any(char in lowered for char in VIETNAMESE_ACCENTS):
        return "vi"
    vi_markers = [
        "ti gia",
        "bao nhieu",
        "hom nay",
        "thi truong",
        "co phieu",
        "vang",
        "bac",
        "dong tien",
        "co nen",
        "giup toi",
    ]
    if any(contains_term(folded, marker) for marker in vi_markers):
        return "vi"
    return "en"


def normalize_currency_mentions(text: str) -> str:
    normalized = fold_text(text)
    replacements = {
        "do la my": "usd",
        "us dollar": "usd",
        "do la": "usd",
        "usd/vnd": "usd vnd",
        "usdvnd": "usd vnd",
        "eur/usd": "eur usd",
        "eurusd": "eur usd",
        "dong viet nam": "vnd",
        "viet nam dong": "vnd",
    }
    for source, target in replacements.items():
        normalized = normalized.replace(source, target)
    return normalized


def extract_amount(text: str) -> float:
    for raw in re.findall(r"\d[\d,]*(?:\.\d+)?", text or ""):
        cleaned = raw.replace(",", "")
        try:
            value = float(cleaned)
        except ValueError:
            continue
        if value > 0:
            return value
    return 1.0


def extract_currency_codes(text: str) -> list[str]:
    normalized = normalize_currency_mentions(text)
    found: list[str] = []

    for alias, code in sorted(
        CURRENCY_ALIASES.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if contains_term(normalized, alias) and code not in found:
            found.append(code)

    words = re.findall(r"[a-z]{3}", normalized)
    for word in words:
        upper = word.upper()
        if upper in SUPPORTED_CURRENCY_CODES and upper not in found:
            found.append(upper)
    return found


def looks_like_exchange_rate_question(text: str) -> bool:
    normalized = normalize_currency_mentions(text)
    codes = extract_currency_codes(text)
    keywords = [
        "exchange rate",
        "fx",
        "forex",
        "rate today",
        "today",
        "ti gia",
        "ty gia",
        "hom nay",
        "bao nhieu",
        "quy doi",
        "convert",
        "pair",
    ]
    has_fx_keyword = any(keyword in normalized for keyword in keywords)
    explicit_pair = "/" in normalized or len(codes) >= 2
    single_currency_lookup = len(codes) == 1 and any(
        keyword in normalized
        for keyword in ["ty gia", "ti gia", "bao nhieu", "quy doi", "convert", "today", "hom nay"]
    )
    return has_fx_keyword and (explicit_pair or single_currency_lookup)


def fetch_json(url: str) -> dict[str, Any] | list[Any] | None:
    try:
        with urlopen(url, timeout=8) as response:
            return json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, ValueError):
        return None


def fetch_exchange_rate(base: str, quote: str, amount: float) -> ExchangeRateQuote | None:
    payload = fetch_json(f"{FX_API_URL}/{base}")
    rates = payload.get("rates") if isinstance(payload, dict) else None
    if not isinstance(rates, dict):
        return None

    raw_rate = rates.get(quote)
    if not isinstance(raw_rate, (int, float)):
        return None

    converted_amount = round(amount * float(raw_rate), 4)
    raw_updated_at = payload.get("time_last_update_utc") if isinstance(payload, dict) else None
    as_of = str(raw_updated_at) if raw_updated_at else datetime.now(timezone.utc).date().isoformat()

    return ExchangeRateQuote(
        base=base,
        quote=quote,
        amount=float(amount),
        convertedAmount=converted_amount,
        rate=float(raw_rate),
        date=as_of,
        source="ExchangeRate-API",
    )


def convert_quote_currency(amount: float, from_currency: str, to_currency: str) -> float | None:
    if from_currency == to_currency:
        return amount
    fx_quote = fetch_exchange_rate(from_currency, to_currency, amount)
    return fx_quote.convertedAmount if fx_quote else None


def maybe_get_exchange_rate_quote(
    latest_user_message: str, payload: CopilotRequest
) -> ExchangeRateQuote | None:
    if not latest_user_message or not looks_like_exchange_rate_question(latest_user_message):
        return None

    codes = extract_currency_codes(latest_user_message)
    if not codes:
        return None

    base = codes[0]
    quote = codes[1] if len(codes) > 1 else ("VND" if base == "USD" else payload.currency.upper())
    if base == quote:
        quote = "VND" if base != "VND" else "USD"

    amount = extract_amount(latest_user_message)
    return fetch_exchange_rate(base, quote, amount)


def format_number(value: float, digits: int = 4) -> str:
    if abs(value) >= 1000:
        template = "{:,.2f}"
    elif abs(value) >= 1:
        template = "{:,.4f}"
    else:
        template = "{:,.6f}"
    if digits == 0:
        template = "{:,.0f}"
    return template.format(value).rstrip("0").rstrip(".")


def build_exchange_rate_reply(
    quote: ExchangeRateQuote, language: Literal["vi", "en"]
) -> CopilotResponse:
    amount_text = (
        f"{quote.amount:.2f}".rstrip("0").rstrip(".")
        if quote.amount % 1
        else f"{int(quote.amount)}"
    )
    converted_text = (
        f"{quote.convertedAmount:,.4f}".rstrip("0").rstrip(".")
        if quote.quote not in {"VND", "JPY", "KRW"}
        else f"{quote.convertedAmount:,.0f}"
    )
    rate_text = f"{quote.rate:,.6f}".rstrip("0").rstrip(".")

    if language == "vi":
        reply = (
            f"Tỷ giá mới nhất tại thời điểm {quote.date}: 1 {quote.base} = {rate_text} {quote.quote}. "
            f"Vì vậy {amount_text} {quote.base} tương đương khoảng {converted_text} {quote.quote}."
        )
        suggested_actions = [
            f"Nguồn dữ liệu: {quote.source}.",
            "Đây là tỷ giá tham chiếu, có thể khác tỷ giá giao dịch thực tế tại ngân hàng hoặc ứng dụng.",
            f"Bạn có thể hỏi thêm cặp như {quote.base}/VND, EUR/USD hoặc JPY/VND.",
        ]
        follow_up = f"Bạn có muốn tôi so sánh thêm cặp {quote.base}/{quote.quote} với cặp khác không?"
    else:
        reply = (
            f"Latest available rate on {quote.date}: 1 {quote.base} = {rate_text} {quote.quote}. "
            f"So {amount_text} {quote.base} is about {converted_text} {quote.quote}."
        )
        suggested_actions = [
            f"Source: {quote.source}.",
            "These are reference rates and may differ from your bank or card network.",
            "Ask for another pair like EUR/USD, USD/VND, or JPY/VND.",
        ]
        follow_up = f"Do you want me to compare {quote.base}/{quote.quote} with another pair?"

    return CopilotResponse(
        reply=reply,
        topic="exchange-rate",
        suggestedActions=suggested_actions,
        suggestedDepositAmount=None,
        riskLevel="low",
        confidence=0.97,
        followUpQuestion=follow_up,
    )


def extract_quote_currency(text: str, payload: CopilotRequest, default: str = "USD") -> str:
    codes = extract_currency_codes(text)
    for code in reversed(codes):
        if code in SUPPORTED_CURRENCY_CODES:
            return code
    return payload.currency.upper() if payload.currency else default


def asset_reference(
    asset_type: str, provider: str, symbol: str, name: str, asset_id: str | None = None
) -> dict[str, str]:
    return {
        "assetType": asset_type,
        "provider": provider,
        "symbol": symbol,
        "name": name,
        "id": asset_id or symbol,
    }


def extract_market_references(text: str) -> list[dict[str, str]]:
    folded = fold_text(text)
    references: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for alias, (asset_type, symbol, name) in sorted(
        METAL_ALIASES.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if contains_term(folded, alias):
            key = (asset_type, symbol)
            if key not in seen:
                seen.add(key)
                references.append(asset_reference(asset_type, "metal", symbol, name))

    for alias, (asset_id, symbol) in sorted(
        CRYPTO_ALIASES.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if contains_term(folded, alias):
            key = ("crypto", symbol)
            if key not in seen:
                seen.add(key)
                references.append(
                    asset_reference(
                        "crypto",
                        "crypto",
                        symbol,
                        asset_id.replace("-", " ").title(),
                        asset_id,
                    )
                )

    for alias, (asset_type, symbol, name) in sorted(
        STOOQ_REFERENCE_ALIASES.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if contains_term(folded, alias):
            key = (asset_type, symbol)
            if key not in seen:
                seen.add(key)
                references.append(asset_reference(asset_type, "stooq", symbol, name))

    for raw_token in re.findall(r"\$?([A-Z]{1,5})\b", text or ""):
        token = raw_token.upper()
        if token in COMMON_TICKER_STOPWORDS or token in SUPPORTED_CURRENCY_CODES:
            continue
        key = ("stock", f"{token.lower()}.us")
        if key not in seen:
            seen.add(key)
            references.append(asset_reference("stock", "stooq", f"{token.lower()}.us", token))

    return references[:4]


def detect_market_intent(text: str, references: list[dict[str, str]]) -> str:
    folded = fold_text(text)
    if any(keyword in folded for keyword in STRATEGY_KEYWORDS):
        return "strategy"
    if any(keyword in folded for keyword in COMPARE_KEYWORDS):
        return "comparison"
    if any(keyword in folded for keyword in OVERVIEW_KEYWORDS) and not references:
        return "market-overview"
    if any(keyword in folded for keyword in OUTLOOK_KEYWORDS):
        return "outlook"
    if any(keyword in folded for keyword in EXPLAIN_KEYWORDS):
        return "explanation"
    if references and any(keyword in folded for keyword in PRICE_KEYWORDS):
        return "price-lookup"
    if len(references) >= 2:
        return "comparison"
    if references:
        return "asset-analysis"
    return "general-market"


def fetch_metal_quote(symbol: str, target_currency: str) -> MarketQuote | None:
    url = GOLD_API_URL if symbol == "XAU" else SILVER_API_URL
    payload = fetch_json(url)
    raw_price = payload.get("price") if isinstance(payload, dict) else None
    if not isinstance(raw_price, (int, float)):
        return None

    price_usd = float(raw_price)
    converted_price = convert_quote_currency(price_usd, "USD", target_currency)
    return MarketQuote(
        assetType="gold" if symbol == "XAU" else "silver",
        symbol=symbol,
        name=str(payload.get("name") or ("Gold" if symbol == "XAU" else "Silver")),
        price=price_usd,
        currency="USD",
        convertedPrice=converted_price if target_currency != "USD" else None,
        convertedCurrency=target_currency if target_currency != "USD" else None,
        updatedAt=str(payload.get("updatedAt") or utc_now_iso()),
        source="gold-api.com",
        note=f"Reference spot price for {symbol} per troy ounce.",
    )


def fetch_crypto_quote(asset_id: str, symbol: str, target_currency: str) -> MarketQuote | None:
    vs_currency = target_currency.lower()
    params = urlencode(
        {
            "ids": asset_id,
            "vs_currencies": vs_currency,
            "include_last_updated_at": "true",
        }
    )
    payload = fetch_json(f"{CRYPTO_API_URL}?{params}")
    asset_data = payload.get(asset_id) if isinstance(payload, dict) else None
    raw_price = asset_data.get(vs_currency) if isinstance(asset_data, dict) else None
    if not isinstance(raw_price, (int, float)):
        return None

    updated_at = asset_data.get("last_updated_at") if isinstance(asset_data, dict) else None
    updated_label = (
        datetime.fromtimestamp(updated_at, timezone.utc).isoformat()
        if isinstance(updated_at, (int, float))
        else utc_now_iso()
    )
    return MarketQuote(
        assetType="crypto",
        symbol=symbol,
        name=asset_id.replace("-", " ").title(),
        price=float(raw_price),
        currency=target_currency,
        updatedAt=updated_label,
        source="CoinGecko",
        note="Public spot crypto reference.",
    )


def fetch_stooq_quote(
    symbol: str, asset_type: str, name: str, target_currency: str
) -> MarketQuote | None:
    params = urlencode({"s": symbol.lower(), "i": "d"})
    try:
        with urlopen(f"{STOCK_API_URL}?{params}", timeout=8) as response:
            raw = response.read().decode("utf-8").strip()
    except (URLError, TimeoutError, ValueError):
        return None

    parts = [part.strip() for part in raw.split(",")]
    if len(parts) < 7 or parts[1] == "N/D":
        return None

    trade_date = parts[1]
    trade_time = parts[2] if len(parts) > 2 else "000000"
    open_price = parse_float(parts[3] if len(parts) > 3 else None)
    high_price = parse_float(parts[4] if len(parts) > 4 else None)
    low_price = parse_float(parts[5] if len(parts) > 5 else None)
    close_price = parse_float(parts[6] if len(parts) > 6 else None)
    if close_price is None:
        return None

    if asset_type in {"stock", "etf", "commodity"}:
        currency = "USD"
        converted_price = (
            convert_quote_currency(close_price, "USD", target_currency)
            if target_currency != "USD"
            else None
        )
        converted_currency = target_currency if target_currency != "USD" else None
    else:
        currency = "points"
        converted_price = None
        converted_currency = None

    session_change_pct = None
    if open_price and open_price > 0:
        session_change_pct = ((close_price - open_price) / open_price) * 100.0

    updated_at = (
        f"{trade_date[:4]}-{trade_date[4:6]}-{trade_date[6:8]} "
        f"{trade_time[:2]}:{trade_time[2:4]} UTC"
    )
    note_map = {
        "stock": "Public equity quote feed. Quotes may be delayed.",
        "etf": "Public ETF quote feed. Quotes may be delayed.",
        "index": "Public index feed. Values are market reference levels.",
        "commodity": "Public commodity futures reference. Quotes may be delayed.",
    }

    return MarketQuote(
        assetType=asset_type,
        symbol=symbol.replace(".us", "").replace("^", "").upper(),
        name=name,
        price=close_price,
        currency=currency,
        convertedPrice=converted_price,
        convertedCurrency=converted_currency,
        updatedAt=updated_at,
        source="Stooq",
        note=note_map.get(asset_type, "Public market quote feed."),
        openPrice=open_price,
        highPrice=high_price,
        lowPrice=low_price,
        sessionChangePct=session_change_pct,
    )


def fetch_market_quote(reference: dict[str, str], target_currency: str) -> MarketQuote | None:
    provider = reference["provider"]
    if provider == "metal":
        return fetch_metal_quote(reference["symbol"], target_currency)
    if provider == "crypto":
        return fetch_crypto_quote(reference["id"], reference["symbol"], target_currency)
    if provider == "stooq":
        return fetch_stooq_quote(
            reference["symbol"], reference["assetType"], reference["name"], target_currency
        )
    return None


def build_market_overview(target_currency: str) -> list[MarketQuote]:
    references = [
        asset_reference("index", "stooq", "^spx", "S&P 500"),
        asset_reference("index", "stooq", "^ndq", "Nasdaq 100"),
        asset_reference("index", "stooq", "dx.f", "US Dollar Index"),
        asset_reference("gold", "metal", "XAU", "Gold"),
        asset_reference("silver", "metal", "XAG", "Silver"),
        asset_reference("crypto", "crypto", "BTC", "Bitcoin", "bitcoin"),
    ]
    quotes: list[MarketQuote] = []
    for reference in references:
        quote = fetch_market_quote(reference, target_currency)
        if quote:
            quotes.append(quote)
    return quotes


def build_market_context(latest_user_message: str, payload: CopilotRequest) -> dict[str, Any]:
    references = extract_market_references(latest_user_message)
    intent = detect_market_intent(latest_user_message, references)
    target_currency = extract_quote_currency(latest_user_message, payload, "USD")
    quotes: list[MarketQuote] = []

    for reference in references:
        quote = fetch_market_quote(reference, target_currency)
        if quote:
            quotes.append(quote)

    overview_quotes: list[MarketQuote] = []
    if intent == "market-overview" and not quotes:
        overview_quotes = build_market_overview(target_currency)

    return {
        "intent": intent,
        "targetCurrency": target_currency,
        "assetsDetected": [
            {
                "name": reference["name"],
                "symbol": reference["symbol"],
                "assetType": reference["assetType"],
            }
            for reference in references
        ],
        "quotes": [quote.model_dump() for quote in quotes],
        "overview": [quote.model_dump() for quote in overview_quotes],
        "hasLiveData": bool(quotes or overview_quotes),
    }


def quote_risk_level(quote: MarketQuote) -> str:
    if quote.assetType == "crypto":
        return "high"
    if quote.assetType in {"stock", "etf", "commodity"}:
        return "medium"
    return "low"


def aggregate_risk_level(quotes: list[MarketQuote]) -> str:
    levels = {quote_risk_level(quote) for quote in quotes}
    if "high" in levels:
        return "high"
    if "medium" in levels:
        return "medium"
    return "low"


def format_price(value: float, currency: str) -> str:
    if currency == "points":
        return format_number(value)
    if currency in {"VND", "JPY", "KRW"}:
        return f"{value:,.0f} {currency}"
    return f"{format_number(value)} {currency}"


def format_change(value: float, language: Literal["vi", "en"]) -> str:
    prefix = "+" if value > 0 else ""
    if language == "vi":
        return f"{prefix}{value:.2f}% so với giá mở cửa"
    return f"{prefix}{value:.2f}% versus the session open"


def quote_summary_line(quote: MarketQuote, language: Literal["vi", "en"]) -> str:
    line = f"{quote.name} ({quote.symbol}): {format_price(quote.price, quote.currency)}"
    if quote.sessionChangePct is not None:
        line += f", {format_change(quote.sessionChangePct, language)}"
    if (
        quote.convertedPrice is not None
        and quote.convertedCurrency
        and quote.convertedCurrency != quote.currency
    ):
        line += f" ({format_price(quote.convertedPrice, quote.convertedCurrency)})"
    return line


def build_market_price_reply(
    quotes: list[MarketQuote], language: Literal["vi", "en"]
) -> CopilotResponse:
    lines = [quote_summary_line(quote, language) for quote in quotes[:4]]
    if language == "vi":
        reply = "Giá thị trường mới nhất tôi lấy được:\n" + "\n".join(lines)
        actions = [
            "Đây là dữ liệu tham chiếu công khai, có thể trễ nhẹ so với broker hoặc sàn giao dịch.",
            "Bạn có thể yêu cầu so sánh thêm với tài sản khác hoặc đổi sang đơn vị tiền tệ khác.",
            "Nếu cần, tôi có thể phân tích nhanh rủi ro ngắn hạn và dài hạn cho mã này.",
        ]
        follow_up = "Bạn muốn tôi so sánh tài sản này với vàng, bạc, USD hay một mã cổ phiếu khác không?"
    else:
        reply = "Latest market quotes I could ground:\n" + "\n".join(lines)
        actions = [
            "These are public reference quotes and can lag your broker or exchange feed.",
            "Ask for a comparison or another quote currency if needed.",
            "I can also give you a quick short-term versus long-term risk view.",
        ]
        follow_up = "Do you want a comparison against another asset or a quick risk view?"

    return CopilotResponse(
        reply=reply,
        topic="market-price",
        suggestedActions=actions,
        suggestedDepositAmount=None,
        riskLevel=aggregate_risk_level(quotes),
        confidence=0.94,
        followUpQuestion=follow_up,
    )


def build_market_overview_reply(
    quotes: list[MarketQuote], language: Literal["vi", "en"]
) -> CopilotResponse:
    lines = [quote_summary_line(quote, language) for quote in quotes[:6]]
    if language == "vi":
        reply = "Toàn cảnh thị trường hiện tại:\n" + "\n".join(lines)
        actions = [
            "Nếu bạn đang tìm cơ hội giao dịch, hãy xác định rõ là bạn ưu tiên phòng thủ hay tăng trưởng.",
            "Tôi có thể đào sâu vào một tài sản cụ thể như BTC, vàng, bạc, S&P 500 hoặc AAPL.",
            "Nếu bạn muốn vào lệnh, nên xác định trước khung thời gian nắm giữ và mức lỗ tối đa chấp nhận được.",
        ]
        follow_up = "Bạn muốn tôi bóc tách sâu hơn asset nào trong bức tranh này?"
    else:
        reply = "Current market overview:\n" + "\n".join(lines)
        actions = [
            "Decide first whether you are leaning defensive or growth before acting on this snapshot.",
            "I can drill into a single asset such as BTC, gold, silver, the S&P 500, or AAPL.",
            "If you plan to trade, define your holding period and max tolerated drawdown first.",
        ]
        follow_up = "Which asset do you want me to break down next?"

    return CopilotResponse(
        reply=reply,
        topic="market-overview",
        suggestedActions=actions,
        suggestedDepositAmount=None,
        riskLevel="medium",
        confidence=0.92,
        followUpQuestion=follow_up,
    )


def build_market_comparison_reply(
    quotes: list[MarketQuote], language: Literal["vi", "en"]
) -> CopilotResponse:
    lines = [quote_summary_line(quote, language) for quote in quotes[:4]]
    asset_types = {quote.assetType for quote in quotes}
    if language == "vi":
        risk_line = (
            "Nhóm tài sản này có độ biến động cao vì có crypto trong so sánh."
            if "crypto" in asset_types
            else "So sánh này thiên về cân bằng giữa tăng trưởng và phòng thủ."
        )
        reply = "So sánh nhanh theo dữ liệu hiện tại:\n" + "\n".join(lines) + f"\n{risk_line}"
        actions = [
            "So sánh giá tuyệt đối giữa các nhóm tài sản khác nhau không đủ ý nghĩa; nên so theo vai trò và rủi ro.",
            "Crypto thường nhạy hơn với thanh khoản và tâm lý rủi ro, còn vàng/bạc nhạy hơn với USD và lãi suất thực.",
            "Nếu bạn muốn, tôi có thể chuyển sang so sánh theo kịch bản ngắn hạn, trung hạn và dài hạn.",
        ]
        follow_up = "Bạn muốn tôi so sánh theo tiêu chí nào: an toàn vốn, tăng trưởng hay phòng thủ lạm phát?"
    else:
        risk_line = (
            "This set is high volatility because crypto is part of the comparison."
            if "crypto" in asset_types
            else "This mix is more about balancing growth versus defense."
        )
        reply = "Quick comparison based on current data:\n" + "\n".join(lines) + f"\n{risk_line}"
        actions = [
            "Absolute price alone is not a useful cross-asset comparison; compare role, volatility, and drivers.",
            "Crypto is usually more liquidity and sentiment sensitive, while gold and silver react more to USD and real yields.",
            "I can turn this into bull, base, and bear-case scenarios if you want.",
        ]
        follow_up = "Do you want the comparison framed around capital preservation, growth, or inflation defense?"

    return CopilotResponse(
        reply=reply,
        topic="market-comparison",
        suggestedActions=actions,
        suggestedDepositAmount=None,
        riskLevel=aggregate_risk_level(quotes),
        confidence=0.9,
        followUpQuestion=follow_up,
    )


def build_market_strategy_reply(
    quotes: list[MarketQuote], language: Literal["vi", "en"]
) -> CopilotResponse:
    anchor = quote_summary_line(quotes[0], language)
    risk_level = aggregate_risk_level(quotes)
    if language == "vi":
        reply = (
            f"Điểm neo hiện tại: {anchor}. "
            "Nếu bạn đang cân nhắc vào lệnh, cách an toàn hơn là chia điểm mua theo từng phần thay vì all-in ngay một mức giá. "
            "Quyết định hợp lý phụ thuộc chủ yếu vào thời gian nắm giữ, mức chịu lỗ và tỷ trọng tài sản này trong tổng danh mục."
        )
        actions = [
            "Với ngắn hạn, ưu tiên chờ xác nhận xu hướng và đặt ngưỡng cắt lỗ rõ ràng.",
            "Với dài hạn, giải ngân từng phần thường hợp lý hơn cố đoán đúng đáy.",
            "Không nên để một vị thế rủi ro cao chiếm tỷ trọng quá lớn so với tiền mặt dự phòng.",
        ]
        follow_up = "Bạn định nắm giữ tài sản này trong bao lâu và chịu được drawdown khoảng bao nhiêu phần trăm?"
    else:
        reply = (
            f"Current anchor point: {anchor}. "
            "If you are considering an entry, scaling in is usually safer than going all-in at one price. "
            "The sensible choice depends mostly on your time horizon, drawdown tolerance, and portfolio weight."
        )
        actions = [
            "For short-term trades, wait for trend confirmation and define a hard stop first.",
            "For long-term exposure, phased entries are usually more defensible than trying to call the exact bottom.",
            "Do not let a high-risk position dominate the cash buffer you still need elsewhere.",
        ]
        follow_up = "What holding period and drawdown tolerance are you working with?"

    return CopilotResponse(
        reply=reply,
        topic="market-strategy",
        suggestedActions=actions,
        suggestedDepositAmount=None,
        riskLevel=risk_level,
        confidence=0.83,
        followUpQuestion=follow_up,
    )


def build_market_explanation_reply(
    latest_user_message: str, language: Literal["vi", "en"]
) -> CopilotResponse:
    folded = fold_text(latest_user_message)
    if "gold" in folded or "vang" in folded or "xau" in folded:
        if language == "vi":
            reply = (
                "Vàng thường nhạy với ba biến chính: lãi suất thực của Mỹ, sức mạnh đồng USD và nhu cầu phòng thủ rủi ro. "
                "Lãi suất thực tăng thường gây áp lực lên vàng, còn USD yếu hoặc rủi ro vĩ mô tăng thường hỗ trợ vàng."
            )
            actions = [
                "Muốn nhìn vàng đúng hơn, nên theo dõi cùng lúc lợi suất thực, DXY và kỳ vọng lãi suất Fed.",
                "Nếu bạn cần, tôi có thể gắn phần giải thích này với giá vàng hiện tại.",
                "Tôi cũng có thể so sánh vai trò của vàng với bạc hoặc Bitcoin.",
            ]
            follow_up = "Bạn muốn tôi gắn phần giải thích này với diễn biến vàng hiện tại không?"
        else:
            reply = (
                "Gold usually reacts to three big drivers: US real yields, the strength of the US dollar, and demand for risk hedges. "
                "Higher real yields often pressure gold, while a weaker dollar or higher macro stress often supports it."
            )
            actions = [
                "Watch real yields, DXY, and Fed rate expectations together rather than in isolation.",
                "I can tie this explanation to the current gold quote if you want.",
                "I can also compare the role of gold versus silver or Bitcoin.",
            ]
            follow_up = "Do you want me to connect that explanation to the current gold price?"
    elif "silver" in folded or "bac" in folded or "xag" in folded:
        if language == "vi":
            reply = (
                "Bạc vừa có tính chất kim loại quý vừa có thành phần nhu cầu công nghiệp, nên thường biến động mạnh hơn vàng. "
                "Khi kỳ vọng tăng trưởng công nghiệp tốt, bạc có thể mạnh hơn vàng; khi thị trường phòng thủ mạnh, vàng thường ổn định hơn."
            )
            actions = [
                "Nếu so bạc với vàng, hãy nhìn thêm tỷ lệ gold/silver và kỳ vọng tăng trưởng toàn cầu.",
                "Tôi có thể lấy thêm giá bạc hiện tại để nối với phần giải thích này.",
                "Tôi cũng có thể so bạc với vàng theo góc nhìn phòng thủ và biến động.",
            ]
            follow_up = "Bạn muốn tôi so bạc với vàng bằng dữ liệu hiện tại không?"
        else:
            reply = (
                "Silver behaves partly like a precious metal and partly like an industrial metal, so it often moves more violently than gold. "
                "When industrial growth expectations improve, silver can outperform gold; in stronger risk-off phases, gold is usually steadier."
            )
            actions = [
                "If you compare silver with gold, also watch the gold/silver ratio and global growth expectations.",
                "I can pull the current silver quote to ground this explanation.",
                "I can also compare silver versus gold from a defense versus volatility angle.",
            ]
            follow_up = "Do you want a live silver versus gold comparison?"
    else:
        if language == "vi":
            reply = (
                "Tôi có thể giải thích theo góc nhìn thị trường, nhưng để trả lời sắc hơn bạn nên chỉ rõ tài sản hoặc biến số bạn muốn hỏi, "
                "ví dụ lãi suất Fed, USD, vàng, bạc, Bitcoin, S&P 500 hoặc một mã cổ phiếu cụ thể."
            )
            actions = [
                "Bạn có thể hỏi kiểu: Fed ảnh hưởng vàng thế nào, so sánh BTC với vàng, hay AAPL đang chịu rủi ro gì.",
                "Nếu câu hỏi cần giá hiện tại, tôi có thể cố gắng lấy thêm dữ liệu live trước khi trả lời.",
                "Nếu câu hỏi thiên về chiến lược, hãy nói thêm khung thời gian và mức chịu rủi ro.",
            ]
            follow_up = "Bạn muốn tôi giải thích tài sản hoặc biến số nào trước?"
        else:
            reply = (
                "I can explain the market angle, but the answer will be sharper if you name the asset or driver first, "
                "for example the Fed, USD, gold, silver, Bitcoin, the S&P 500, or a specific stock."
            )
            actions = [
                "You can ask things like: how the Fed affects gold, BTC versus gold, or what risks AAPL is facing.",
                "If the question needs current prices, I can try to ground it with live data first.",
                "If it is more strategic, include your time horizon and risk tolerance.",
            ]
            follow_up = "Which asset or macro driver do you want explained first?"

    return CopilotResponse(
        reply=reply,
        topic="market-explanation",
        suggestedActions=actions,
        suggestedDepositAmount=None,
        riskLevel="medium",
        confidence=0.8,
        followUpQuestion=follow_up,
    )


def build_market_fallback_reply(
    latest_user_message: str,
    market_context: dict[str, Any],
    language: Literal["vi", "en"],
) -> CopilotResponse | None:
    quotes = [MarketQuote.model_validate(item) for item in market_context.get("quotes", [])]
    overview = [MarketQuote.model_validate(item) for item in market_context.get("overview", [])]
    intent = market_context.get("intent", "general-market")

    if intent == "market-overview" and overview:
        return build_market_overview_reply(overview, language)
    if intent == "comparison" and quotes:
        return build_market_comparison_reply(quotes, language)
    if intent in {"strategy", "outlook", "asset-analysis"} and quotes:
        return build_market_strategy_reply(quotes, language)
    if intent == "price-lookup" and quotes:
        return build_market_price_reply(quotes, language)
    if intent in {"explanation", "general-market"}:
        return build_market_explanation_reply(latest_user_message, language)
    if quotes:
        return build_market_price_reply(quotes, language)
    return None


def build_deposit_plan(goal_text: str, balance: float, income: float, expenses: float):
    goal = fold_text(goal_text)
    balance = max(balance, 0)
    income = max(income or 0, 0)
    expenses = max(expenses or 0, 0)
    disposable = max(income - expenses, 0)

    base_amount = 100.0
    reasons: list[str] = []
    risk: Literal["low", "medium", "high"] = "low"
    next_action = "Deposit the suggested amount now."
    confidence = 0.83

    if "emergency" in goal or "rainy" in goal or "du phong" in goal:
        base_amount = max(
            150.0,
            min(ceil(max(disposable, 300) * 0.25 / 10) * 10, 1000.0),
        )
        reasons.append("Emergency goals benefit from steady cash-buffer deposits.")
        reasons.append("The recommendation stays meaningful without overcommitting funds.")
        next_action = "Start with this amount, then repeat weekly until you reach one month of expenses."
        confidence = 0.88
    elif "travel" in goal or "trip" in goal or "vacation" in goal:
        base_amount = max(
            120.0,
            min(ceil(max(disposable, 240) * 0.2 / 10) * 10, 800.0),
        )
        reasons.append("Travel goals work best with predictable medium-sized deposits.")
        reasons.append("This keeps progress visible while preserving room for daily spending.")
        confidence = 0.82
    elif "bill" in goal or "rent" in goal or "tuition" in goal:
        base_amount = max(
            100.0,
            min(ceil(max(disposable, 200) * 0.35 / 10) * 10, 1500.0),
        )
        reasons.append("Upcoming obligations should be funded faster than lifestyle goals.")
        reasons.append("The suggestion prioritizes liquidity and near-term certainty.")
        risk = "medium"
        next_action = "Deposit this amount and review again after the next paycheck."
        confidence = 0.86
    elif "invest" in goal or "business" in goal or "project" in goal:
        base_amount = max(
            200.0,
            min(ceil(max(disposable, 400) * 0.3 / 10) * 10, 2000.0),
        )
        reasons.append("Growth-oriented goals can justify a larger top-up if cash flow supports it.")
        reasons.append("The suggestion stays below a level that should not strain short-term spending.")
        risk = "medium"
        confidence = 0.79
    else:
        base_amount = max(
            100.0,
            min(ceil(max(disposable, 250) * 0.22 / 10) * 10, 900.0),
        )
        reasons.append("The goal was treated as a general savings target.")
        reasons.append("The amount is sized to be practical for a first deposit.")

    if balance < 100:
        reasons.append("Current wallet balance is still low, so the recommendation leans slightly higher.")
        base_amount += 50.0

    if disposable <= 0:
        reasons.append("Monthly cash-flow data is limited, so a conservative starter amount was used.")
        base_amount = min(base_amount, 150.0)
        risk = "medium"
        confidence = 0.68

    recommended = float(max(50.0, ceil(base_amount / 10) * 10))
    return {
        "recommendedAmount": recommended,
        "reasoning": reasons,
        "riskLevel": risk,
        "nextAction": next_action,
        "confidence": confidence,
    }


def build_copilot_reply(
    payload: CopilotRequest,
    language: Literal["vi", "en"],
    market_context: dict[str, Any],
) -> CopilotResponse:
    latest_user_message = next(
        (
            message.content.strip()
            for message in reversed(payload.messages)
            if message.role == "user" and message.content.strip()
        ),
        "",
    )
    folded = fold_text(latest_user_message)
    market_reply = build_market_fallback_reply(latest_user_message, market_context, language)
    if market_reply:
        return market_reply

    income = max(payload.monthlyIncome or 0, 0)
    expenses = max(payload.monthlyExpenses or 0, 0)
    net_flow = income - expenses
    transactions = payload.recentTransactions[:12]
    credits = sum(tx.amount for tx in transactions if tx.direction == "credit")
    debits = sum(tx.amount for tx in transactions if tx.direction != "credit")

    if any(keyword in folded for keyword in DEPOSIT_KEYWORDS):
        plan = build_deposit_plan(latest_user_message, payload.currentBalance, income, expenses)
        return CopilotResponse(
            reply=(
                f"Một mức nạp hợp lý là khoảng {plan['recommendedAmount']:.0f} {payload.currency}. {plan['reasoning'][0]}"
                if language == "vi"
                else f"A practical top-up is about {plan['recommendedAmount']:.0f} {payload.currency}. {plan['reasoning'][0]}"
            ),
            topic="deposit-planning",
            suggestedActions=plan["reasoning"][:3],
            suggestedDepositAmount=plan["recommendedAmount"],
            riskLevel=plan["riskLevel"],
            confidence=plan["confidence"],
            followUpQuestion=(
                "Bạn có muốn tôi lập kế hoạch tiết kiệm theo tuần cho mục tiêu này không?"
                if language == "vi"
                else "Do you want a weekly savings plan based on this target?"
            ),
        )

    if any(keyword in folded for keyword in CASH_FLOW_KEYWORDS):
        if language == "vi":
            reply = (
                f"{'Dòng tiền hàng tháng của bạn hiện vẫn đủ bù chi tiêu.' if net_flow >= 0 else 'Chi tiêu hàng tháng của bạn đang cao hơn dòng tiền vào.'} "
                f"Số dư hiện tại là {payload.currentBalance:.2f} {payload.currency}. "
                f"Theo các giao dịch gần nhất, khoảng {debits:.2f} đang đi ra so với {credits:.2f} đi vào."
            )
        else:
            reply = (
                f"{'Your monthly inflow appears to cover spending.' if net_flow >= 0 else 'Your monthly spending appears to be ahead of inflow.'} "
                f"Current balance is {payload.currentBalance:.2f} {payload.currency}. "
                f"From the latest recorded activity, about {debits:.2f} is going out versus {credits:.2f} coming in."
            )
        return CopilotResponse(
            reply=reply,
            topic="cash-flow",
            suggestedActions=(
                [
                    "Hãy giới hạn một nhóm chi tiêu linh hoạt trong 7 ngày tới.",
                    "Giữ ít nhất một tuần chi phí sinh hoạt ở dạng thanh khoản.",
                    "Rà lại 10 giao dịch gần nhất để tìm khoản thất thoát lặp lại.",
                ]
                if language == "vi"
                else [
                    "Cap one discretionary category for the next 7 days.",
                    "Keep at least one week of expenses in liquid form.",
                    "Review the last 10 transactions for repeatable leaks.",
                ]
            ),
            suggestedDepositAmount=None,
            riskLevel="low" if net_flow >= 0 else "medium",
            confidence=0.82,
            followUpQuestion=(
                "Bạn có muốn tôi tách dòng tiền thành khoản chi an toàn, hóa đơn và quỹ đệm không?"
                if language == "vi"
                else "Do you want me to break your cash flow into safe spend, bills, and buffer?"
            ),
        )

    return CopilotResponse(
        reply=(
            "Tôi có thể hỗ trợ về thị trường tiền tệ, chứng khoán, vàng, bạc, crypto, tỷ giá, rủi ro danh mục và cả dòng tiền trong ví. "
            "Bạn có thể hỏi giá hiện tại, so sánh tài sản, giải thích vì sao thị trường biến động, hoặc hỏi chiến lược theo khung thời gian của bạn."
            if language == "vi"
            else "I can help with currencies, stocks, gold, silver, crypto, exchange rates, portfolio risk, and wallet cash flow. "
            "Ask for a current quote, an asset comparison, a market explanation, or a strategy view for your time horizon."
        ),
        topic="general",
        suggestedActions=(
            [
                "Hỏi giá vàng, bạc, Bitcoin, USD/VND, S&P 500 hoặc một mã cổ phiếu cụ thể.",
                "Hỏi so sánh như BTC với vàng, AAPL với S&P 500, hoặc vàng với bạc.",
                "Nếu muốn chiến lược, hãy nói thêm thời gian nắm giữ và mức chịu rủi ro.",
            ]
            if language == "vi"
            else [
                "Ask for gold, silver, Bitcoin, USD/VND, the S&P 500, or a specific stock.",
                "Ask for a comparison such as BTC versus gold or AAPL versus the S&P 500.",
                "For strategy questions, include your time horizon and risk tolerance.",
            ]
        ),
        suggestedDepositAmount=None,
        riskLevel="low",
        confidence=0.73,
        followUpQuestion=(
            "Bạn muốn tôi bắt đầu từ giá hiện tại, so sánh tài sản hay góc nhìn chiến lược?"
            if language == "vi"
            else "Do you want to start with live quotes, a comparison, or a strategy view?"
        ),
    )


@app.get("/health")
def health():
    return {"status": "ok", "service": "ai", "timestamp": utc_now_iso()}


@app.post("/ai/score")
def score(event: LoginEvent):
    score_value = 0.2 if event.userAgent else 0.5
    reasons = ["stubbed-model"]
    return {"score": score_value, "reasons": reasons, "received": event.model_dump()}


@app.post("/ai/deposit-agent", response_model=DepositAgentResponse)
def deposit_agent(payload: DepositAgentRequest):
    plan = build_deposit_plan(
        payload.goal,
        payload.currentBalance,
        payload.monthlyIncome or 0,
        payload.monthlyExpenses or 0,
    )
    return DepositAgentResponse.model_validate(plan)


@app.post("/ai/copilot-chat", response_model=CopilotResponse)
def copilot_chat(payload: CopilotRequest):
    latest_user_message = next(
        (
            message.content.strip()
            for message in reversed(payload.messages)
            if message.role == "user" and message.content.strip()
        ),
        "",
    )
    language = detect_language(latest_user_message)
    live_fx_quote = maybe_get_exchange_rate_quote(latest_user_message, payload)
    if live_fx_quote:
        return build_exchange_rate_reply(live_fx_quote, language)

    market_context = build_market_context(latest_user_message, payload)
    fallback = build_copilot_reply(payload, language, market_context)
    if not openai_client:
        return fallback

    try:
        recent_messages = payload.messages[-8:]
        prompt_payload = {
            "userId": payload.userId or "unknown",
            "currency": payload.currency,
            "currentBalance": payload.currentBalance,
            "monthlyIncome": payload.monthlyIncome or 0,
            "monthlyExpenses": payload.monthlyExpenses or 0,
            "recentTransactions": [
                {
                    "amount": tx.amount,
                    "type": tx.type,
                    "description": tx.description,
                    "createdAt": tx.createdAt,
                    "direction": tx.direction,
                }
                for tx in payload.recentTransactions[:12]
            ],
            "messages": [
                {"role": message.role, "content": message.content}
                for message in recent_messages
            ],
            "latestUserMessage": latest_user_message,
            "language": language,
            "marketContext": market_context,
            "exchangeRateQuote": live_fx_quote.model_dump() if live_fx_quote else None,
        }

        response = openai_client.responses.create(
            model=OPENAI_MODEL,
            input=[
                {"role": "system", "content": MARKET_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(prompt_payload, ensure_ascii=False)},
            ],
            text={"format": {"type": "json_object"}},
        )

        raw = (getattr(response, "output_text", "") or "").strip()
        if not raw:
            return fallback

        parsed = CopilotResult.model_validate_json(raw)
        recommended = None
        if parsed.suggestedDepositAmount is not None and parsed.suggestedDepositAmount > 0:
            recommended = float(max(50.0, ceil(parsed.suggestedDepositAmount / 10) * 10))
        confidence = min(max(float(parsed.confidence), 0.0), 1.0)

        return CopilotResponse(
            reply=parsed.reply.strip(),
            topic=parsed.topic.strip() or fallback.topic,
            suggestedActions=parsed.suggestedActions[:4] or fallback.suggestedActions,
            suggestedDepositAmount=recommended,
            riskLevel=parsed.riskLevel if parsed.riskLevel in {"low", "medium", "high"} else fallback.riskLevel,
            confidence=confidence,
            followUpQuestion=parsed.followUpQuestion.strip() if parsed.followUpQuestion else fallback.followUpQuestion,
        )
    except Exception:
        return fallback


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
