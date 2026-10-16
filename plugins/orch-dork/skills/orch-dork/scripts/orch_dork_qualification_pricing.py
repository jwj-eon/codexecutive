"""Bound the frozen Issue 171 worker budget from published endpoint prices.

This pure validator performs no credential, network, model, or file operation.
Its caller preserves the bounded public response before validation, including
on refusal. Discount metadata is separate from priced SKUs; the bound removes
positive discounts and never depends on a promotion continuing.
"""

from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext
import hashlib
import json
from typing import Any


MODEL_ID = "qwen/qwen3.8-27b"
MAX_RESPONSE_BYTES = 65_536
MAX_WORKER_TOKENS = 80_000
MAX_COST_USD = Decimal("5")
TOKEN_FIELDS = frozenset(
    {"prompt", "completion", "internal_reasoning", "input_cache_read", "input_cache_write"}
)


class QualificationPricingError(ValueError):
    """Published pricing cannot establish the frozen worker budget."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise QualificationPricingError("pricing:" + reason)


def _number(value: Any) -> Decimal:
    _require(type(value) in (str, int, Decimal), "rate_type_invalid")
    try:
        result = Decimal(str(value))
    except InvalidOperation as error:
        raise QualificationPricingError("pricing:rate_invalid") from error
    _require(result.is_finite() and result >= 0, "rate_invalid")
    digits = result.as_tuple()
    _require(
        len(digits.digits) <= 128 and -128 <= digits.exponent <= 128,
        "rate_precision_invalid",
    )
    return result


def _reject_nonfinite_literal(value: str) -> None:
    raise QualificationPricingError("pricing:response_invalid")


def bound_published_worker_pricing(response_body: bytes) -> dict[str, Any]:
    """Require a conservative USD 5 bound for 80,000 exact-model tokens.

    Unsupported non-token fees and unknown rates refuse. Nonnegative discount
    fractions below one are metadata; negative discounts (markups) refuse.
    Sum every token SKU and remove any positive discount, which is conservative
    whether the published rates include that discount or remain base rates.
    Parse the original response bytes with Decimal, never an already-rounded
    float projection. Actual billing is never inferred from this report.
    """
    _require(isinstance(response_body, bytes), "response_bytes_required")
    _require(len(response_body) <= MAX_RESPONSE_BYTES, "response_too_large")
    try:
        value = json.loads(
            response_body, parse_float=Decimal,
            parse_constant=_reject_nonfinite_literal,
        )
    except (ValueError, UnicodeError, InvalidOperation, RecursionError) as error:
        raise QualificationPricingError("pricing:response_invalid") from error
    _require(isinstance(value, dict), "response_invalid")
    data = value.get("data")
    _require(isinstance(data, dict), "response_invalid")
    _require(data.get("id") == MODEL_ID, "model_mismatch")
    endpoints = data.get("endpoints")
    _require(isinstance(endpoints, list) and bool(endpoints), "endpoints_missing")
    maximum = Decimal(0)
    discount_count = 0
    for endpoint in endpoints:
        _require(isinstance(endpoint, dict), "endpoint_invalid")
        prices = endpoint.get("pricing")
        _require(isinstance(prices, dict), "missing")
        _require(
            prices.get("prompt") is not None and prices.get("completion") is not None,
            "token_rates_missing",
        )
        discount = _number(prices.get("discount", 0))
        _require(discount < 1, "discount_invalid")
        discount_count += int(discount > 0)
        rates = {key: _number(rate) for key, rate in prices.items() if key != "discount"}
        _require(
            all(rate == 0 for key, rate in rates.items() if key not in TOKEN_FIELDS),
            "non_token_charge_unbounded",
        )
        _require(all(rate <= MAX_COST_USD for rate in rates.values()), "budget_unavailable")
        # Accepted decimal encodings have at most 128 digits and decimal
        # places. Subtraction is exact; division rounds the bound upward.
        with localcontext() as context:
            context.prec = 256
            context.rounding = ROUND_CEILING
            rate_sum = sum((rate for key, rate in rates.items() if key in TOKEN_FIELDS), Decimal(0))
            rate_bound = rate_sum / (Decimal(1) - discount)
            _require(rate_bound * MAX_WORKER_TOKENS <= MAX_COST_USD, "budget_unavailable")
            maximum = max(maximum, rate_bound)
    with localcontext() as context:
        context.prec = max(64, len(maximum.as_tuple().digits) + 8)
        context.rounding = ROUND_CEILING
        cost_bound = maximum * MAX_WORKER_TOKENS
    return {
        "schema": "orch-dork/qualification-worker-price-bound/v1",
        "status": "PASS",
        "disposition": "PUBLISHED_RATE_BOUND",
        "model_id": MODEL_ID,
        "pricing_response_sha256": hashlib.sha256(response_body).hexdigest(),
        "maximum_usd_per_token": str(maximum),
        "reserved_worker_tokens": MAX_WORKER_TOKENS,
        "published_rate_cost_bound_usd": str(cost_bound),
        "discounted_endpoint_count": discount_count,
        "discount_policy": "remove_positive_discount_for_conservative_upper_bound",
        "actual_billed_cost": "unknown_until_provider_billing",
    }
