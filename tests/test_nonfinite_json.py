# SPDX-License-Identifier: Apache-2.0
"""Non-JSON numeric constants must never become verifiable receipts."""
import base64
import hashlib
import json

import pytest

from szl_guardrail_receipt import GuardrailReceiptChain, RuleBasedGuardrail
from szl_guardrail_receipt import receipt
from szl_guardrail_receipt._canonical import dsse_pae
from szl_guardrail_receipt.verify import verify_records_assurance


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize("location", ["ts", "lambda_score", "metadata"])
def test_emitter_rejects_nonfinite_before_signing_or_advancing(monkeypatch, value, location):
    chain = GuardrailReceiptChain()
    first = chain.emit(RuleBasedGuardrail().check("first"), input_text="first", ts=1.0)
    head = chain.head
    verdict = RuleBasedGuardrail().check("next")
    kwargs = {"ts": 2.0}
    if location == "ts":
        kwargs["ts"] = value
    elif location == "lambda_score":
        verdict.lambda_score = value
    else:
        verdict.metadata = {"nested": [{"score": value}]}
    signed = []
    chain.private_key_pem = b"test key must never be used"
    monkeypatch.setattr(receipt._sign, "crypto_available", lambda: True)
    monkeypatch.setattr(receipt._sign, "sign_pae", lambda *args: signed.append(args) or "unused")

    with pytest.raises(ValueError, match="Out of range float values"):
        chain.emit(verdict, input_text="next", **kwargs)
    assert signed == []
    assert chain.head == head

    chain.private_key_pem = None
    second = chain.emit(RuleBasedGuardrail().check("next"), input_text="next", ts=2.0)
    body = receipt.decode_decision(second)
    assert body["seq"] == 1
    assert body["prev"] == head
    assert verify_records_assurance([first, second]).ok


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize("location", ["ts", "lambda_score", "metadata"])
def test_verifier_rejects_nonfinite_even_with_recomputed_hashes(value, location):
    record = GuardrailReceiptChain().emit(
        RuleBasedGuardrail().check("hello"), input_text="hello", ts=1.0
    )
    body = receipt.decode_decision(record)
    if location == "ts":
        body["ts"] = record["ts"] = value
    elif location == "lambda_score":
        body["lambda"]["score"] = value
    else:
        body["guardrail"]["metadata"] = {"nested": [{"score": value}]}

    # Deliberately use Python's permissive serializer to model an external
    # producer, not the issuer's canonical serializer under test.
    def permissive_bytes(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    body["digest"] = hashlib.sha256(
        permissive_bytes({key: val for key, val in body.items() if key != "digest"})
    ).hexdigest()
    payload = permissive_bytes(body)
    envelope = record["envelope"]
    envelope["payload"] = base64.b64encode(payload).decode("ascii")
    envelope["_pae_sha256"] = hashlib.sha256(dsse_pae(envelope["payloadType"], payload)).hexdigest()

    result = verify_records_assurance([record])
    assert result.ok is False
    assert any("canon:" in line and "FAIL" in line for line in result.lines)
