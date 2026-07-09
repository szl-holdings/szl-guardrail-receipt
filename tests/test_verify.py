# SPDX-License-Identifier: Apache-2.0
"""Tests for the receipt verifier (structure, content hash, chain, honesty)."""
from __future__ import annotations

import base64
import json

from szl_guardrail_receipt import (
    GuardrailReceiptChain,
    RuleBasedGuardrail,
    emit_receipt,
    verify_records,
)


def _tamper_payload(record, mutate):
    body = json.loads(base64.b64decode(record["envelope"]["payload"]).decode("utf-8"))
    mutate(body)
    record["envelope"]["payload"] = base64.b64encode(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return record


def test_valid_unsigned_receipt_passes():
    gr = RuleBasedGuardrail()
    rec = emit_receipt(gr.check("hello"), input_text="hello")
    ok, lines = verify_records([rec])
    assert ok, "\n".join(lines)


def test_valid_chain_passes():
    gr = RuleBasedGuardrail()
    chain = GuardrailReceiptChain()
    recs = [chain.emit(gr.check(t), input_text=t) for t in ("a", "b", "c")]
    ok, lines = verify_records(recs)
    assert ok, "\n".join(lines)
    assert any("hash chain intact across 3" in ln for ln in lines)


def test_tampered_content_hash_fails():
    gr = RuleBasedGuardrail()
    rec = emit_receipt(gr.check("hello"), input_text="hello")
    # change the payload without updating _pae_sha256 -> content-hash check fails
    _tamper_payload(rec, lambda b: b.__setitem__("decision", "block"))
    ok, lines = verify_records([rec])
    assert not ok
    assert any("PAE sha256 mismatch" in ln for ln in lines)


def test_broken_chain_fails():
    gr = RuleBasedGuardrail()
    chain = GuardrailReceiptChain()
    r0 = chain.emit(gr.check("a"), input_text="a")
    r1 = chain.emit(gr.check("b"), input_text="b")
    # rewrite r1.prev inside the payload AND fix _pae_sha256 so only the chain breaks
    from szl_guardrail_receipt._canonical import canonical_json, dsse_pae
    from szl_guardrail_receipt._sign import PAYLOAD_TYPE
    import hashlib

    body = json.loads(base64.b64decode(r1["envelope"]["payload"]).decode("utf-8"))
    body["prev"] = "f" * 64
    payload_bytes = canonical_json(body)
    r1["envelope"]["payload"] = base64.b64encode(payload_bytes).decode("ascii")
    r1["envelope"]["_pae_sha256"] = hashlib.sha256(
        dsse_pae(PAYLOAD_TYPE, payload_bytes)
    ).hexdigest()
    ok, lines = verify_records([r0, r1])
    assert not ok
    assert any("prev" in ln and "FAIL" in ln for ln in lines)


def test_fabricated_energy_joule_is_rejected():
    gr = RuleBasedGuardrail()
    rec = emit_receipt(gr.check("hello"), input_text="hello")
    # set a fabricated joule while label stays UNAVAILABLE -> honesty check fails
    from szl_guardrail_receipt._canonical import canonical_json, dsse_pae
    from szl_guardrail_receipt._sign import PAYLOAD_TYPE
    import hashlib

    body = json.loads(base64.b64decode(rec["envelope"]["payload"]).decode("utf-8"))
    body["energy"]["joules"] = 42.0
    payload_bytes = canonical_json(body)
    rec["envelope"]["payload"] = base64.b64encode(payload_bytes).decode("ascii")
    rec["envelope"]["_pae_sha256"] = hashlib.sha256(
        dsse_pae(PAYLOAD_TYPE, payload_bytes)
    ).hexdigest()
    ok, lines = verify_records([rec])
    assert not ok
    assert any("fabricated joule" in ln for ln in lines)


def test_unsigned_signature_is_skip_not_pass():
    gr = RuleBasedGuardrail()
    rec = emit_receipt(gr.check("hello"), input_text="hello")
    ok, lines = verify_records([rec])
    assert ok
    assert any("SKIP" in ln and "UNSIGNED-honest" in ln for ln in lines)
