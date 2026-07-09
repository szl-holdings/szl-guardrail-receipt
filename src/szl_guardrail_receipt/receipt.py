# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""Build signed, hash-chained guardrail decision receipts.

A guardrail *decision receipt* is the small, replayable record emitted for one
allow/deny decision. Its field names are aligned with SZL's
``governed-receipt-spec`` so a receipt emitted here validates with that repo's
dependency-free offline verifier.

Trust posture (honest, non-negotiable):
  * The receipt is NOT a proof the guardrail is correct and NOT zero-knowledge.
    It is a signed, tamper-evident audit record of *what was decided*.
  * ``decision`` is one of ``allow`` / ``deny`` / ``block``. The deny-by-default
    "honest-blocked" (``szl-blocked``) posture is carried by
    ``honest_blocked: true`` alongside ``decision: "deny"``.
  * Λ is advisory only — ``lambda.label`` stays "Λ = Conjecture 1 — never green".
  * A guardrail decision measures no inference energy, so ``energy`` is honestly
    ``{joules: null, label: "UNAVAILABLE", ...}`` — never a fabricated joule.
  * No key present ⇒ UNSIGNED-honest envelope (``signed: false``), never a fake
    signature.
"""
from __future__ import annotations

import base64
import hashlib
import time
from typing import Any, Dict, List, Optional

from . import _sign
from ._canonical import canonical_json, dsse_pae
from ._sign import PAYLOAD_TYPE
from .guardrail import LAMBDA_LABEL, GuardrailVerdict

ZERO_HASH = "0" * 64
RECEIPT_SCHEMA = "szl.guardrail.receipt/v1"
RECORD_SCHEMA = "szl.guardrail.record/v1"

_UNSIGNED_HONESTY = (
    "UNSIGNED-honest: no private key present, so this envelope is NOT signed. "
    "The content hash and chain are still verifiable; authenticity is not."
)
_SIGNED_HONESTY = (
    "REAL — ECDSA-P256-SHA256 over the standard DSSE PAE. Proves this receipt "
    "body was signed by the holder of the key; it does NOT prove the guardrail "
    "verdict is correct and is NOT zero-knowledge."
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def input_digest(text: str) -> str:
    """SHA-256 (hex) of *text* encoded UTF-8 — the receipt's ``payload_digest``."""
    return _sha256_hex(text.encode("utf-8"))


def build_decision_body(
    verdict: GuardrailVerdict,
    *,
    ns: str,
    seq: int,
    prev: str,
    payload_digest: str,
    ts: Optional[float] = None,
    organ: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble the canonical decision body (the object that gets signed).

    ``digest`` is computed here as ``sha256(canonical_json(body-without-digest))``
    — a documented, reproducible chain-link value. The next receipt's ``prev``
    equals this ``digest``.

    Returns:
        The decision body dict, including ``digest`` and a
        ``signature: "DSSE_PLACEHOLDER"`` slot (the authoritative signature
        lives in the DSSE envelope, matching the estate convention).
    """
    if ts is None:
        ts = time.time()
    decision = "allow" if verdict.allowed else "deny"
    body: Dict[str, Any] = {
        "action": "guardrail",
        "ns": ns,
        "organ": organ or verdict.guardrail_name,
        "seq": seq,
        "prev": prev,
        "payload_digest": payload_digest,
        "ts": ts,
        "decision": decision,
        "honest_blocked": not verdict.allowed,
        "guardrail": {
            "name": verdict.guardrail_name,
            "version": verdict.guardrail_version,
            "reason": verdict.reason,
            "categories": list(verdict.categories),
        },
        "lambda": {
            "score": verdict.lambda_score,
            "label": LAMBDA_LABEL,
            "note": "advisory, non-compensatory; never a proof of safety.",
        },
        "energy": {
            "joules": None,
            "label": "UNAVAILABLE",
            "evidence": {
                "reason": "a guardrail allow/deny decision performs no metered "
                "inference; no NVML/energy reading applies.",
            },
        },
        "chain_verified": prev == ZERO_HASH or seq > 0,
        "schema": RECEIPT_SCHEMA,
        "signature": "DSSE_PLACEHOLDER",
    }
    if verdict.metadata:
        body["guardrail"]["metadata"] = dict(verdict.metadata)
    body_wo_digest = {k: v for k, v in body.items() if k != "digest"}
    body["digest"] = _sha256_hex(canonical_json(body_wo_digest))
    return body


def _make_envelope(
    body: Dict[str, Any],
    *,
    private_key_pem: Optional[bytes | str],
    keyid: str,
    verify_key_url: Optional[str],
) -> Dict[str, Any]:
    """Wrap a decision body in a DSSE envelope, signing when a key is present."""
    payload_bytes = canonical_json(body)
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")
    pae_sha256 = _sha256_hex(dsse_pae(PAYLOAD_TYPE, payload_bytes))
    signed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    envelope: Dict[str, Any] = {
        "_dsse": "DSSEv1",
        "payloadType": PAYLOAD_TYPE,
        "payload": payload_b64,
        "_pae_sha256": pae_sha256,
        "_signed_at": signed_at,
        "signatures": [],
        "signed": False,
        "honesty": _UNSIGNED_HONESTY,
    }

    if private_key_pem and _sign.crypto_available():
        sig_b64 = _sign.sign_pae(body, private_key_pem)
        envelope["signatures"] = [{"keyid": keyid or "ephemeral", "sig": sig_b64}]
        envelope["signed"] = True
        envelope["honesty"] = _SIGNED_HONESTY
        if verify_key_url:
            envelope["verify_key_url"] = verify_key_url
    return envelope


class GuardrailReceiptChain:
    """Stateful emitter that hash-chains guardrail decision receipts.

    Each :meth:`emit` appends one receipt whose ``prev`` links to the previous
    receipt's ``digest`` (genesis ``prev`` is 64 zeros at ``seq`` 0).

    Args:
        ns: Namespace recorded on every receipt.
        organ: Optional sub-surface label (defaults to the guardrail name).
        private_key_pem: PEM private key for real ECDSA-P256 DSSE signing, or
            ``None`` for UNSIGNED-honest receipts.
        keyid: Key identifier stamped into signatures.
        verify_key_url: Public URL of the verifying key (recorded when signed).
    """

    def __init__(
        self,
        *,
        ns: str = "szl-guardrail-receipt",
        organ: Optional[str] = None,
        private_key_pem: Optional[bytes | str] = None,
        keyid: str = "",
        verify_key_url: Optional[str] = None,
    ) -> None:
        self.ns = ns
        self.organ = organ
        self.private_key_pem = private_key_pem
        self.keyid = keyid
        self.verify_key_url = verify_key_url
        self._seq = 0
        self._prev = ZERO_HASH

    @property
    def head(self) -> str:
        """The ``digest`` the next receipt will link to (``prev``)."""
        return self._prev

    def emit(
        self,
        verdict: GuardrailVerdict,
        *,
        input_text: Optional[str] = None,
        payload_digest: Optional[str] = None,
        ts: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Emit one receipt record for *verdict* and advance the chain.

        Provide EITHER *input_text* (its SHA-256 becomes ``payload_digest``) or
        an explicit *payload_digest*. The screened content itself is never
        embedded — only its digest binds the receipt to the input.

        Returns:
            A receipt *record*: ``{schema, ns, ts, envelope, verify}`` where the
            DSSE ``envelope`` carries the base64 decision body. This record
            shape is understood by ``governed-receipt-spec/verify.py``.
        """
        if payload_digest is None:
            if input_text is None:
                raise ValueError("provide input_text or payload_digest")
            payload_digest = input_digest(input_text)

        body = build_decision_body(
            verdict,
            ns=self.ns,
            seq=self._seq,
            prev=self._prev,
            payload_digest=payload_digest,
            ts=ts,
            organ=self.organ,
        )
        envelope = _make_envelope(
            body,
            private_key_pem=self.private_key_pem,
            keyid=self.keyid,
            verify_key_url=self.verify_key_url,
        )
        record: Dict[str, Any] = {
            "schema": RECORD_SCHEMA,
            "ns": self.ns,
            "ts": body["ts"],
            "envelope": envelope,
            "verify": {
                "algorithm": "ECDSA-P256-SHA256 over DSSE PAE (DSSEv1)",
                "how_to_verify": (
                    "python -m szl_guardrail_receipt verify <file>  — or the "
                    "dependency-free governed-receipt-spec/verify.py."
                ),
                "spec": "https://github.com/szl-holdings/governed-receipt-spec",
            },
        }
        # advance chain
        self._prev = body["digest"]
        self._seq += 1
        return record


def emit_receipt(
    verdict: GuardrailVerdict,
    *,
    input_text: Optional[str] = None,
    payload_digest: Optional[str] = None,
    ns: str = "szl-guardrail-receipt",
    organ: Optional[str] = None,
    seq: int = 0,
    prev: str = ZERO_HASH,
    ts: Optional[float] = None,
    private_key_pem: Optional[bytes | str] = None,
    keyid: str = "",
    verify_key_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Emit a single guardrail decision receipt (one-shot, no chain state).

    Convenience wrapper over :class:`GuardrailReceiptChain` for the common
    "wrap one verdict" case. For a linked sequence, use the chain directly.

    Returns:
        A receipt record (see :meth:`GuardrailReceiptChain.emit`).
    """
    if payload_digest is None:
        if input_text is None:
            raise ValueError("provide input_text or payload_digest")
        payload_digest = input_digest(input_text)
    chain = GuardrailReceiptChain(
        ns=ns,
        organ=organ,
        private_key_pem=private_key_pem,
        keyid=keyid,
        verify_key_url=verify_key_url,
    )
    chain._seq = seq
    chain._prev = prev
    return chain.emit(verdict, payload_digest=payload_digest, ts=ts)


def decode_decision(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the decoded decision body from a receipt *record*, or ``None``."""
    env = record.get("envelope") if isinstance(record, dict) else None
    if not isinstance(env, dict) or "payload" not in env:
        if isinstance(record, dict) and "seq" in record and "prev" in record:
            return record
        return None
    try:
        raw = base64.b64decode(env["payload"])
        import json

        return json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def decisions_from_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Decode the decision bodies from a list of receipt records."""
    out = []
    for r in records:
        d = decode_decision(r)
        if d is not None:
            out.append(d)
    return out
