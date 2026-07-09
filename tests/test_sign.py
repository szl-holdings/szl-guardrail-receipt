# SPDX-License-Identifier: Apache-2.0
"""Tests for ECDSA-P256 DSSE signing + verification (requires cryptography)."""
from __future__ import annotations

import base64
import json

import pytest

from szl_guardrail_receipt import (
    GuardrailReceiptChain,
    RuleBasedGuardrail,
    crypto_available,
    generate_keypair,
    verify_records,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="cryptography not installed"
)


def _body(record):
    return json.loads(base64.b64decode(record["envelope"]["payload"]).decode("utf-8"))


def test_signed_receipt_verifies():
    priv, pub = generate_keypair()
    gr = RuleBasedGuardrail()
    chain = GuardrailReceiptChain(private_key_pem=priv, keyid="test-key")
    rec = chain.emit(gr.check("hello"), input_text="hello")
    assert rec["envelope"]["signed"] is True
    assert rec["envelope"]["signatures"][0]["keyid"] == "test-key"
    ok, lines = verify_records([rec], public_key_pem=pub)
    assert ok, "\n".join(lines)


def test_tampered_payload_fails_signature():
    priv, pub = generate_keypair()
    gr = RuleBasedGuardrail()
    chain = GuardrailReceiptChain(private_key_pem=priv)
    rec = chain.emit(gr.check("hello"), input_text="hello")
    # flip the decision inside the signed payload
    body = _body(rec)
    body["decision"] = "allow" if body["decision"] != "allow" else "deny"
    rec["envelope"]["payload"] = base64.b64encode(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    ok, lines = verify_records([rec], public_key_pem=pub)
    assert not ok, "tampered payload must fail:\n" + "\n".join(lines)


def test_wrong_key_fails():
    priv, _pub = generate_keypair()
    _priv2, pub2 = generate_keypair()
    gr = RuleBasedGuardrail()
    chain = GuardrailReceiptChain(private_key_pem=priv)
    rec = chain.emit(gr.check("hello"), input_text="hello")
    ok, lines = verify_records([rec], public_key_pem=pub2)
    assert not ok, "verification against wrong key must fail"


def test_signed_receipt_without_key_is_not_a_pass():
    priv, _pub = generate_keypair()
    gr = RuleBasedGuardrail()
    chain = GuardrailReceiptChain(private_key_pem=priv)
    rec = chain.emit(gr.check("hello"), input_text="hello")
    # no public key => signature is SKIPPED (not verified), but structure/hash/chain still pass
    ok, lines = verify_records([rec], public_key_pem=None)
    assert ok
    assert any("signature not checked" in ln for ln in lines)
