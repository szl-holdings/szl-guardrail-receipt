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


# --------------------------------------------------------------------------- #
# RQ-03 / B-005: authenticated assurance. Every key below is an ephemeral      #
# in-test key; nothing signed here is committed or published.                  #
# --------------------------------------------------------------------------- #
import hashlib

from szl_guardrail_receipt import (
    PAYLOAD_TYPE,
    sign_pae,
    verify_dsse,
    verify_pae,
    verify_records_assurance,
)
from szl_guardrail_receipt._canonical import canonical_json, dsse_pae
from szl_guardrail_receipt.verify import main as verify_cli


def _signed(text="hello"):
    priv, pub = generate_keypair()
    chain = GuardrailReceiptChain(private_key_pem=priv, keyid="test-key")
    return chain.emit(RuleBasedGuardrail().check(text), input_text=text), pub


def _reseal_raw(record, payload_bytes, payload_type=None):
    env = record["envelope"]
    if payload_type is not None:
        env["payloadType"] = payload_type
    env["payload"] = base64.b64encode(payload_bytes).decode("ascii")
    env["_pae_sha256"] = hashlib.sha256(dsse_pae(env["payloadType"], payload_bytes)).hexdigest()
    return record


def _downgrade(record):
    env = record["envelope"]
    env["signatures"] = []
    env["signed"] = False
    return record


def test_signed_receipt_with_key_is_authenticated():
    rec, pub = _signed()
    result = verify_records_assurance([rec], public_key_pem=pub)
    assert result.ok is True
    assert result.assurance == "authenticated"
    assert result.authenticated is True
    assert any("AUTHENTICATED" in ln and "UNAUTHENTICATED" not in ln for ln in result.lines)


def test_signed_marker_downgrade_fails_when_a_key_is_supplied():
    rec, pub = _signed()
    _downgrade(rec)
    ok, lines = verify_records([rec], public_key_pem=pub)
    assert ok is False, "\n".join(lines)
    result = verify_records_assurance([rec], public_key_pem=pub)
    assert result.assurance == "unauthenticated"
    assert result.authenticated is False


def test_signed_marker_downgrade_without_key_is_structural_only():
    rec, _pub = _signed()
    _downgrade(rec)
    result = verify_records_assurance([rec])
    assert result.ok is True
    assert result.assurance == "structural-only"
    assert result.authenticated is False


def test_missing_key_is_never_authenticated():
    rec, _pub = _signed()
    result = verify_records_assurance([rec])
    assert result.ok is True  # documented structural-only compatibility mode
    assert result.assurance == "structural-only"
    assert any("UNAUTHENTICATED" in ln and "no public key" in ln for ln in result.lines)
    strict = verify_records_assurance([rec], require_authenticated=True)
    assert strict.ok is False
    assert strict.assurance == "unauthenticated"


def test_missing_crypto_backend_is_never_authenticated(monkeypatch):
    rec, pub = _signed()
    from szl_guardrail_receipt import _sign as sign_mod

    monkeypatch.setattr(sign_mod, "crypto_available", lambda: False)
    result = verify_records_assurance([rec], public_key_pem=pub)
    assert result.ok is False
    assert result.assurance == "unauthenticated"
    assert any("cryptography" in ln for ln in result.lines)
    relaxed = verify_records_assurance([rec], public_key_pem=pub, require_authenticated=False)
    assert relaxed.ok is True
    assert relaxed.assurance == "structural-only"


def test_mixed_signed_and_unsigned_chain_is_not_authenticated():
    priv, pub = generate_keypair()
    chain = GuardrailReceiptChain(private_key_pem=priv, keyid="test-key")
    gr = RuleBasedGuardrail()
    r0 = chain.emit(gr.check("a"), input_text="a")
    chain.private_key_pem = None
    r1 = chain.emit(gr.check("b"), input_text="b")
    assert r0["envelope"]["signed"] is True and r1["envelope"]["signed"] is False
    assert verify_records_assurance([r0, r1], public_key_pem=pub).assurance == "unauthenticated"
    assert verify_records_assurance([r0, r1]).assurance == "structural-only"


def test_wrong_payload_type_with_valid_signature_rejects():
    # The old helper re-derived the PAE with a constant type, so a valid
    # signature survived a payloadType swap once _pae_sha256 was recomputed.
    rec, pub = _signed()
    raw = base64.b64decode(rec["envelope"]["payload"])
    _reseal_raw(rec, raw, payload_type="application/vnd.in-toto+json")
    result = verify_records_assurance([rec], public_key_pem=pub)
    assert result.ok is False
    assert result.assurance == "failed"


def test_alternate_serialization_with_valid_signature_rejects():
    # The old helper re-canonicalised the decoded body, so re-serialised bytes
    # still "verified". Signatures bind the exact decoded envelope bytes.
    rec, pub = _signed()
    body = _body(rec)
    _reseal_raw(rec, json.dumps(body, indent=2, ensure_ascii=False).encode("utf-8"))
    result = verify_records_assurance([rec], public_key_pem=pub)
    assert result.ok is False
    assert result.assurance == "failed"


def test_verify_dsse_binds_exact_bytes_and_type():
    rec, pub = _signed()
    env = rec["envelope"]
    raw = base64.b64decode(env["payload"])
    sig = env["signatures"][0]["sig"]
    assert verify_dsse(PAYLOAD_TYPE, raw, sig, pub) == (True, "ok")
    assert verify_dsse("application/vnd.in-toto+json", raw, sig, pub)[0] is False
    respaced = json.dumps(json.loads(raw), indent=1).encode("utf-8")
    assert verify_dsse(PAYLOAD_TYPE, respaced, sig, pub)[0] is False
    assert verify_dsse(PAYLOAD_TYPE, raw, "!!not-base64!!", pub)[0] is False


def test_extra_invalid_signature_rejects():
    rec, pub = _signed()
    rec["envelope"]["signatures"].append({"keyid": "x", "sig": "AAAA"})
    result = verify_records_assurance([rec], public_key_pem=pub)
    assert result.ok is False
    assert result.assurance == "failed"


@pytest.mark.parametrize("entry", ["not-a-dict", {"keyid": "k"}, {"sig": 5}])
def test_malformed_signature_entry_is_a_bounded_failure(entry):
    rec, pub = _signed()
    rec["envelope"]["signatures"] = [entry]
    result = verify_records_assurance([rec], public_key_pem=pub)
    assert result.ok is False
    assert result.assurance == "failed"


def test_non_p256_key_is_rejected():
    # ECDSA-P256-SHA256 is the declared algorithm; a P-384 key that really did
    # sign these exact PAE bytes must still not authenticate the receipt.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    rec, _pub = _signed()
    env = rec["envelope"]
    raw = base64.b64decode(env["payload"])
    p384 = ec.generate_private_key(ec.SECP384R1())
    sig = p384.sign(dsse_pae(env["payloadType"], raw), ec.ECDSA(hashes.SHA256()))
    env["signatures"] = [{"keyid": "p384", "sig": base64.b64encode(sig).decode("ascii")}]
    pub384 = p384.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    result = verify_records_assurance([rec], public_key_pem=pub384)
    assert result.ok is False
    assert any("P-256" in ln for ln in result.lines)


def test_cli_authenticated_and_downgrade_outcomes(tmp_path, capsys):
    rec, pub = _signed()
    key = tmp_path / "test-key.pub.pem"
    key.write_bytes(pub)
    good = tmp_path / "good.json"
    good.write_text(json.dumps([rec]), encoding="utf-8")
    assert verify_cli([str(good), "--pubkey", str(key)]) == 0
    out = capsys.readouterr().out
    assert "RESULT: PASS (authenticated" in out
    assert "OVERALL: PASS (authenticated" in out

    downgraded = tmp_path / "downgraded.json"
    downgraded.write_text(json.dumps([_downgrade(rec)]), encoding="utf-8")
    assert verify_cli([str(downgraded), "--pubkey", str(key)]) == 3
    out = capsys.readouterr().out
    assert "RESULT: FAIL (unauthenticated" in out
    assert "OVERALL: FAIL (unauthenticated" in out


def test_legacy_verify_pae_contract_is_unchanged():
    # Direct callers of the exported helper keep its documented semantics.
    priv, pub = generate_keypair()
    body = {"a": 1, "b": [1, 2]}
    sig = sign_pae(body, priv)
    assert verify_pae(body, sig, pub) == (True, "ok")
    assert verify_dsse(PAYLOAD_TYPE, canonical_json(body), sig, pub) == (True, "ok")
