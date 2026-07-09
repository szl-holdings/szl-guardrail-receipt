# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""Verify guardrail decision receipts.

The content-hash, chain, and structural checks are pure-stdlib (no third-party
imports, no network) — the same relations ``governed-receipt-spec/verify.py``
checks. Real ECDSA-P256 signature verification is performed additionally when
``cryptography`` is installed and a public key is supplied.

For each record the verifier:
  (a) structurally checks the DSSE envelope,
  (b) recomputes ``sha256(DSSE PAE)`` and checks it equals ``_pae_sha256``,
  (c) checks required decision fields are present and honest (decision enum,
      honest_blocked/deny agreement, energy never a fabricated joule),
  (d) verifies the ECDSA-P256 signature when signed + a key is given, and
  (e) checks the ``prev``→``digest`` hash chain across a receipt list.

CLI:
    python -m szl_guardrail_receipt verify <file.json> [--pubkey key.pem]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import _sign
from ._canonical import dsse_pae
from ._sign import PAYLOAD_TYPE

ZERO_HASH = "0" * 64
_DECISION_ENUM = {"allow", "deny", "block", "review", "abstain"}
_REQUIRED = ["action", "ns", "seq", "prev", "digest", "payload_digest", "ts", "decision"]


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
    try:
        raw = base64.b64decode(envelope["payload"])
    except Exception as exc:  # noqa: BLE001
        return None, f"payload not base64: {exc}"
    try:
        return json.loads(raw.decode("utf-8")), ""
    except Exception as exc:  # noqa: BLE001
        return None, f"payload not JSON: {exc}"


def check_dsse_structure(envelope: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """Structural checks on a DSSE envelope."""
    if envelope is None:
        return False, "no DSSE envelope found"
    problems: List[str] = []
    if not envelope.get("payloadType"):
        problems.append("payloadType missing/empty")
    if not isinstance(envelope.get("payload"), str):
        problems.append("payload missing/not a string")
    else:
        try:
            base64.b64decode(envelope["payload"])
        except Exception:  # noqa: BLE001
            problems.append("payload not base64-decodable")
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
    """Recompute sha256(DSSE PAE) and check it equals ``_pae_sha256``."""
    try:
        body = base64.b64decode(envelope["payload"])
    except Exception as exc:  # noqa: BLE001
        return False, f"payload not base64: {exc}"
    ptype = envelope.get("payloadType", "")
    if "_pae_sha256" not in envelope:
        return True, "no _pae_sha256 present (n/a)"
    got = hashlib.sha256(dsse_pae(ptype, body)).hexdigest()
    want = envelope["_pae_sha256"]
    if got != want:
        return False, f"PAE sha256 mismatch: recomputed {got} != _pae_sha256 {want}"
    return True, f"DSSE PAE sha256 verified ({got[:16]}…)"


def check_decision_fields(decision: Dict[str, Any]) -> Tuple[bool, str]:
    """Check required fields, decision enum, and honesty invariants."""
    problems: List[str] = []
    for req in _REQUIRED:
        if req not in decision:
            problems.append(f"missing '{req}'")
    dec = decision.get("decision")
    if dec is not None and dec not in _DECISION_ENUM:
        problems.append(f"decision {dec!r} not in {sorted(_DECISION_ENUM)}")
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


def check_chain(decisions: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Check the prev→digest chain across ordered decision bodies."""
    chainable = [
        d for d in decisions if isinstance(d, dict) and "prev" in d and "digest" in d
    ]
    if not chainable:
        return True, ["no chainable receipts (n/a)"]
    if all("seq" in d for d in chainable):
        chainable = sorted(chainable, key=lambda d: d["seq"])
    ok = True
    msgs: List[str] = []
    first = chainable[0]
    if first.get("seq") == 0 and first.get("prev") != ZERO_HASH:
        ok = False
        msgs.append(f"genesis prev must be 64 zeros, got {first.get('prev')}")
    for i in range(1, len(chainable)):
        prev_rec, cur = chainable[i - 1], chainable[i]
        if cur.get("prev") != prev_rec.get("digest"):
            ok = False
            msgs.append(
                f"seq {cur.get('seq')} prev != seq {prev_rec.get('seq')} digest"
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
        env = _find_envelope(record)
        s_ok, s_msg = check_dsse_structure(env)
        ok = ok and s_ok
        lines.append(f"    dsse:   {'PASS' if s_ok else 'FAIL'} {s_msg}")
        if env is None:
            continue
        h_ok, h_msg = check_content_hash(env)
        ok = ok and h_ok
        lines.append(f"    hash:   {'PASS' if h_ok else 'FAIL'} {h_msg}")
        body, err = _decode_body(env)
        if body is None:
            ok = False
            lines.append(f"    body:   FAIL {err}")
            continue
        f_ok, f_msg = check_decision_fields(body)
        ok = ok and f_ok
        lines.append(f"    fields: {'PASS' if f_ok else 'FAIL'} {f_msg}")
        sig_ok, sig_msg = check_signature(body, env, public_key_pem)
        if sig_ok is False:
            ok = False
        tag = "PASS" if sig_ok else ("FAIL" if sig_ok is False else "SKIP")
        lines.append(f"    sig:    {tag} {sig_msg}")
        decisions.append(body)
    c_ok, c_msgs = check_chain(decisions)
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
