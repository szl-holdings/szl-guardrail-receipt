# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""Verify guardrail decision receipts.

The content-hash, chain, and structural checks are pure-stdlib (no third-party
imports, no network) — the same relations ``governed-receipt-spec/verify.py``
checks. Real ECDSA-P256 signature verification is performed additionally when
``cryptography`` is installed and a public key is supplied.

For each record the verifier:
  (a) structurally checks the DSSE envelope (strict, canonical base64 payload),
  (b) recomputes ``sha256(DSSE PAE)`` and checks it equals ``_pae_sha256`` —
      the content hash is REQUIRED; a missing or malformed one fails,
  (c) binds every clear wrapper claim (``schema``/``ns``/``ts``/``verify``/…)
      to an identical value inside the sealed payload, and rejects unknown
      envelope extension fields (the governed-receipt-spec binding contract),
  (d) checks required decision fields are present, well-typed and honest
      (decision enum, honest_blocked/deny agreement, no fabricated joule),
  (e) recomputes the body ``digest`` with the issuer's definition
      (:func:`~szl_guardrail_receipt.receipt.body_digest`) and rejects a stale
      or forged declared digest,
  (f) verifies the ECDSA-P256 signature when signed + a key is given, and
  (g) checks the ``prev``→``digest`` hash chain across a receipt list against
      the RECOMPUTED digests, never the declared ones.

Malformed input of any shape yields a bounded ``FAIL`` result; the verifier
never raises on receipt content.

CLI:
    python -m szl_guardrail_receipt verify <file.json> [--pubkey key.pem]
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import _sign
from ._canonical import canonical_json, dsse_pae
from ._sign import PAYLOAD_TYPE
from .receipt import body_digest

ZERO_HASH = "0" * 64
_DECISION_ENUM = {"allow", "deny", "block", "review", "abstain"}
_REQUIRED = ["action", "ns", "seq", "prev", "digest", "payload_digest", "ts", "decision"]
_HEX64 = re.compile(r"[0-9a-f]{64}")
#: Keys that carry the envelope inside a record (exactly one may be present).
_TRANSPORT_KEYS = ("envelope", "dsse")
#: Envelope fields the issuer emits (``receipt._make_envelope``). Anything else
#: is an unbound extension claim that the sealed bytes do not cover.
_ENVELOPE_FIELDS = frozenset(
    {
        "_dsse",
        "_pae_sha256",
        "_signed_at",
        "honesty",
        "payload",
        "payloadType",
        "signatures",
        "signed",
        "verify_key_url",
    }
)


def _brief(value: Any, limit: int = 64) -> str:
    """Bounded repr for report lines (receipt content is untrusted)."""
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _is_seq(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _payload_bytes(envelope: Any) -> Tuple[Optional[bytes], str]:
    """Strictly decode the envelope payload: canonical standard base64 only.

    A lenient decoder silently drops non-alphabet characters, so two different
    payload strings could share one content hash. Only the exact canonical
    encoding of the decoded bytes is accepted.
    """
    if not isinstance(envelope, dict):
        return None, "no DSSE envelope"
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        return None, "payload missing/not a string"
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        return None, f"payload not strict base64: {exc}"
    if base64.b64encode(raw).decode("ascii") != payload:
        return None, "payload not canonical base64"
    return raw, ""


def _find_envelope(record: Any) -> Optional[Dict[str, Any]]:
    if isinstance(record, dict):
        if "payloadType" in record and isinstance(record.get("payload"), str):
            return record
        for key in ("envelope", "dsse"):
            env = record.get(key)
            if isinstance(env, dict) and "payloadType" in env:
                return env
    return None


def _decode_body(envelope: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    raw, err = _payload_bytes(envelope)
    if raw is None:
        return None, err
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, f"payload not UTF-8 JSON: {_brief(str(exc), 120)}"
    if not isinstance(body, dict):
        return None, f"payload is not a JSON object (got {type(body).__name__})"
    return body, ""


def check_dsse_structure(envelope: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """Structural checks on a DSSE envelope."""
    if not isinstance(envelope, dict):
        return False, "no DSSE envelope found"
    problems: List[str] = []
    ptype = envelope.get("payloadType")
    if not isinstance(ptype, str) or not ptype:
        problems.append("payloadType missing/empty/not a string")
    raw, err = _payload_bytes(envelope)
    if raw is None:
        problems.append(err)
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list):
        problems.append("signatures missing/not a list")
        sigs = []
    if envelope.get("signed") is True:
        if not sigs:
            problems.append("signed=true but signatures empty")
        for i, s in enumerate(sigs):
            if not isinstance(s, dict) or "sig" not in s:
                problems.append(f"signature[{i}] missing 'sig'")
    if problems:
        return False, "; ".join(problems)
    kind = "signed" if envelope.get("signed") else "unsigned-honest"
    return True, f"DSSE envelope well-formed ({kind}, {len(sigs)} signature(s))"


def check_content_hash(envelope: Dict[str, Any]) -> Tuple[bool, str]:
    """Recompute sha256(DSSE PAE) and check it equals ``_pae_sha256``.

    The issuer always emits ``_pae_sha256``; its absence is a FAIL, never an
    "n/a" pass, so stripping the hash cannot downgrade the integrity check.
    """
    body, err = _payload_bytes(envelope)
    if body is None:
        return False, err
    ptype = envelope.get("payloadType")
    if not isinstance(ptype, str) or not ptype:
        return False, "payloadType missing/not a string — PAE cannot be recomputed"
    if "_pae_sha256" not in envelope:
        return False, "_pae_sha256 missing — the DSSE content hash is required"
    want = envelope["_pae_sha256"]
    if not _is_hex64(want):
        return False, f"_pae_sha256 malformed (want 64 lowercase hex): {_brief(want)}"
    got = hashlib.sha256(dsse_pae(ptype, body)).hexdigest()
    if got != want:
        return False, f"PAE sha256 mismatch: recomputed {got} != _pae_sha256 {want}"
    return True, f"DSSE PAE sha256 verified ({got[:16]}…)"


def check_clear_claim_binding(record: Any, envelope: Any) -> Tuple[bool, str]:
    """Require every clear wrapper claim to be sealed identically in the payload.

    The envelope's integrity covers only its decoded payload. A clear record
    field (``schema``, ``ns``, ``ts``, ``verify``, or anything else beside the
    envelope) must therefore appear with the identical canonical JSON value
    inside the sealed body, or it is reported UNBOUND. Envelope fields beyond
    the issuer's set are unbound extension claims. This mirrors
    ``governed-receipt-spec`` ``check_clear_claim_binding``.
    """
    if not isinstance(envelope, dict):
        return False, "UNBOUND no DSSE envelope to bind clear claims to"
    unknown = sorted(str(k) for k in set(envelope) - _ENVELOPE_FIELDS)
    if unknown:
        return False, "UNBOUND envelope extension claim(s): " + ", ".join(unknown)
    if record is envelope:
        return True, "flat envelope carries no clear wrapper claims (n/a)"
    if not isinstance(record, dict):
        return False, "UNBOUND record is not a JSON object"
    locations = [k for k in _TRANSPORT_KEYS if k in record]
    if len(locations) != 1:
        return False, "UNBOUND ambiguous envelope locations: " + (
            ", ".join(locations) or "none"
        )
    sealed, err = _decode_body(envelope)
    if sealed is None:
        return False, f"UNBOUND cannot bind clear claims: {err}"
    unbound: List[str] = []
    for key, value in record.items():
        if key in _TRANSPORT_KEYS:
            continue
        try:
            same = key in sealed and canonical_json(value) == canonical_json(sealed[key])
        except Exception:  # noqa: BLE001 - an unserialisable clear value is unbound
            same = False
        if not same:
            unbound.append(str(key))
    if unbound:
        return False, (
            "UNBOUND clear claim(s) absent or different in sealed payload: "
            + ", ".join(sorted(unbound))
        )
    return True, "all clear wrapper claims match the sealed payload"


def check_body_digest(decision: Dict[str, Any]) -> Tuple[bool, str]:
    """Recompute the issuer-defined body ``digest`` and compare it to the claim.

    Uses :func:`~szl_guardrail_receipt.receipt.body_digest` (the same function
    the issuer uses), so the excluded-field set cannot drift between them.
    """
    if not isinstance(decision, dict):
        return False, "decision body is not a JSON object"
    declared = decision.get("digest")
    if not _is_hex64(declared):
        return False, f"digest missing/malformed (want 64 lowercase hex): {_brief(declared)}"
    try:
        got = body_digest(decision)
    except Exception as exc:  # noqa: BLE001
        return False, f"digest not recomputable: {type(exc).__name__}"
    if got != declared:
        return False, f"digest stale or forged: declared {declared} != recomputed {got}"
    return True, f"body digest recomputed and verified ({got[:16]}…)"


def check_decision_fields(decision: Dict[str, Any]) -> Tuple[bool, str]:
    """Check required fields and types, decision enum, and honesty invariants."""
    if not isinstance(decision, dict):
        return False, f"decision body is not a JSON object (got {type(decision).__name__})"
    problems: List[str] = []
    for req in _REQUIRED:
        if req not in decision:
            problems.append(f"missing '{req}'")
    for key in ("action", "ns", "payload_digest"):
        if key in decision and not isinstance(decision[key], str):
            problems.append(f"'{key}' must be a string")
    if "seq" in decision and not _is_seq(decision["seq"]):
        problems.append(f"'seq' must be a non-negative integer, got {_brief(decision['seq'])}")
    if "prev" in decision and not _is_hex64(decision["prev"]):
        problems.append(f"'prev' must be 64 lowercase hex, got {_brief(decision['prev'])}")
    ts = decision.get("ts")
    if "ts" in decision and (isinstance(ts, bool) or not isinstance(ts, (int, float))):
        problems.append(f"'ts' must be a number, got {_brief(ts)}")
    dec = decision.get("decision")
    if dec is not None and not (isinstance(dec, str) and dec in _DECISION_ENUM):
        problems.append(f"decision {_brief(dec)} not in {sorted(_DECISION_ENUM)}")
    hb = decision.get("honest_blocked")
    if isinstance(hb, bool) and dec in {"deny", "block"} and hb is not True:
        problems.append("deny/block must set honest_blocked=true (szl-blocked)")
    energy = decision.get("energy")
    if isinstance(energy, dict):
        if energy.get("label") == "UNAVAILABLE" and energy.get("joules") is not None:
            problems.append("energy UNAVAILABLE but joules is not null (fabricated joule)")
    if problems:
        return False, "; ".join(problems)
    return True, f"decision fields OK (decision={dec}, honest_blocked={hb})"


def check_signature(
    decision: Dict[str, Any],
    envelope: Dict[str, Any],
    public_key_pem: Optional[bytes | str],
) -> Tuple[Optional[bool], str]:
    """Verify the ECDSA-P256 signature. Returns (result, message).

    result is ``None`` when verification was not attempted (unsigned envelope,
    no key, or no crypto backend) — that is honest, not a pass.
    """
    if not envelope.get("signed"):
        return None, "UNSIGNED-honest envelope — nothing to verify (not a pass)"
    if not public_key_pem:
        return None, "signed, but no public key supplied — signature not checked"
    if not _sign.crypto_available():
        return None, "signed, but 'cryptography' not installed — signature not checked"
    sigs = envelope.get("signatures") or []
    if not sigs:
        return False, "signed=true but no signatures present"
    ok, detail = _sign.verify_pae(decision, sigs[0].get("sig", ""), public_key_pem)
    return ok, ("signature verified" if ok else f"signature invalid: {detail}")


def _recomputed_digest(decision: Dict[str, Any]) -> Optional[str]:
    try:
        return body_digest(decision)
    except Exception:  # noqa: BLE001
        return None


def check_chain(decisions: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Check the prev→digest chain across ordered decision bodies.

    Each ``prev`` is compared with the RECOMPUTED digest of its predecessor, so
    a body rewritten under its old declared digest breaks the link.
    """
    chainable = [
        d for d in decisions if isinstance(d, dict) and "prev" in d and "digest" in d
    ]
    if not chainable:
        return True, ["no chainable receipts (n/a)"]
    bad_seq = [_brief(d.get("seq")) for d in chainable if not _is_seq(d.get("seq"))]
    if bad_seq:
        return False, [
            "seq must be a non-negative integer on every chained receipt, got "
            + ", ".join(bad_seq)
        ]
    chainable = sorted(chainable, key=lambda d: d["seq"])
    ok = True
    msgs: List[str] = []
    first = chainable[0]
    if first.get("seq") == 0 and first.get("prev") != ZERO_HASH:
        ok = False
        msgs.append(f"genesis prev must be 64 zeros, got {_brief(first.get('prev'))}")
    for i in range(1, len(chainable)):
        prev_rec, cur = chainable[i - 1], chainable[i]
        link = _recomputed_digest(prev_rec)
        if link is None or cur.get("prev") != link:
            ok = False
            msgs.append(
                f"seq {cur.get('seq')} prev != recomputed digest of seq {prev_rec.get('seq')}"
            )
        if cur.get("seq") != prev_rec.get("seq", -1) + 1:
            ok = False
            msgs.append(f"seq not contiguous: {cur.get('seq')} follows {prev_rec.get('seq')}")
    if ok:
        msgs.append(f"hash chain intact across {len(chainable)} receipt(s)")
    return ok, msgs


def load_records(path: str) -> List[Dict[str, Any]]:
    """Load a JSON object, JSON array, or NDJSON file into a record list."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def _verify_one(
    record: Any,
    public_key_pem: Optional[bytes | str],
    lines: List[str],
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Verify one record, appending report lines. Returns (ok, decoded body)."""
    env = _find_envelope(record)
    s_ok, s_msg = check_dsse_structure(env)
    lines.append(f"    dsse:   {'PASS' if s_ok else 'FAIL'} {s_msg}")
    if env is None:
        return False, None
    h_ok, h_msg = check_content_hash(env)
    lines.append(f"    hash:   {'PASS' if h_ok else 'FAIL'} {h_msg}")
    b_ok, b_msg = check_clear_claim_binding(record, env)
    lines.append(f"    bind:   {'PASS' if b_ok else 'FAIL'} {b_msg}")
    body, err = _decode_body(env)
    if body is None:
        lines.append(f"    body:   FAIL {err}")
        return False, None
    f_ok, f_msg = check_decision_fields(body)
    lines.append(f"    fields: {'PASS' if f_ok else 'FAIL'} {f_msg}")
    d_ok, d_msg = check_body_digest(body)
    lines.append(f"    digest: {'PASS' if d_ok else 'FAIL'} {d_msg}")
    sig_ok, sig_msg = check_signature(body, env, public_key_pem)
    tag = "PASS" if sig_ok else ("FAIL" if sig_ok is False else "SKIP")
    lines.append(f"    sig:    {tag} {sig_msg}")
    r_ok = s_ok and h_ok and b_ok and f_ok and d_ok and sig_ok is not False
    return r_ok, body


def verify_records(
    records: List[Dict[str, Any]],
    public_key_pem: Optional[bytes | str] = None,
) -> Tuple[bool, List[str]]:
    """Verify a list of receipt records. Returns (ok, report_lines)."""
    lines: List[str] = []
    ok = True
    decisions: List[Dict[str, Any]] = []
    for idx, record in enumerate(records):
        lines.append(f"- receipt[{idx}]")
        try:
            r_ok, body = _verify_one(record, public_key_pem, lines)
        except Exception as exc:  # noqa: BLE001 - backstop: bounded, fail-closed
            r_ok, body = False, None
            lines.append(f"    error:  FAIL receipt could not be verified ({type(exc).__name__})")
        ok = ok and r_ok
        if body is not None:
            decisions.append(body)
    try:
        c_ok, c_msgs = check_chain(decisions)
    except Exception as exc:  # noqa: BLE001 - backstop: bounded, fail-closed
        c_ok, c_msgs = False, [f"chain could not be verified ({type(exc).__name__})"]
    ok = ok and c_ok
    for m in c_msgs:
        lines.append(f"- chain:  {'PASS' if c_ok else 'FAIL'} {m}")
    return ok, lines


def verify_file(
    path: str, public_key_pem: Optional[bytes | str] = None
) -> Tuple[bool, List[str]]:
    """Verify one receipt file (JSON / array / NDJSON)."""
    return verify_records(load_records(path), public_key_pem)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI: ``verify <files...> [--pubkey key.pem]``."""
    parser = argparse.ArgumentParser(
        prog="szl_guardrail_receipt.verify",
        description="Verify SZL guardrail decision receipts.",
    )
    parser.add_argument("receipts", nargs="+", help="receipt JSON/NDJSON file(s)")
    parser.add_argument("--pubkey", help="PEM public key for signature verification")
    args = parser.parse_args(argv)

    pub = None
    if args.pubkey:
        with open(args.pubkey, "rb") as fh:
            pub = fh.read()

    all_ok = True
    for path in args.receipts:
        print(f"=== {path} ===")
        try:
            file_ok, lines = verify_file(path, pub)
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL could not process file: {exc}")
            all_ok = False
            continue
        for line in lines:
            print("  " + line)
        print(f"  RESULT: {'PASS' if file_ok else 'FAIL'}")
        all_ok = all_ok and file_ok
    print()
    print(f"OVERALL: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
