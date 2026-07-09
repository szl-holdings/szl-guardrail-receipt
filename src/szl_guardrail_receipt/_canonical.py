# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""Canonical JSON + DSSE Pre-Authentication Encoding (stdlib only).

These two primitives are the byte-level contract that makes a guardrail
receipt independently re-checkable:

* :func:`canonical_json` — compact, sorted-key UTF-8 bytes. The single source
  of truth for every hash we compute.
* :func:`dsse_pae` — the **standard** DSSE Pre-Authentication Encoding
  (ASCII-decimal lengths, per the DSSE spec). This is byte-for-byte identical
  to the PAE the ``governed-receipt-spec`` offline verifier recomputes, so a
  receipt emitted here validates there.

No third-party imports, no network, no disk.
"""
from __future__ import annotations

import json


def canonical_json(obj: object) -> bytes:
    """Return compact, sorted-key JSON encoded as UTF-8 bytes.

    Args:
        obj: Any JSON-serialisable Python object.

    Returns:
        UTF-8 bytes with sorted keys and no insignificant whitespace.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def dsse_pae(payload_type: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (DSSEv1), standard ASCII-decimal form.

    ``PAE = b"DSSEv1 " + len(type) + b" " + type + b" " + len(body) + b" " + body``
    with the lengths written as ASCII decimal digits. This matches the encoding
    recomputed by ``governed-receipt-spec/verify.py`` and by generic DSSE
    tooling, so ``sha256(dsse_pae(...))`` here equals the receipt's
    ``_pae_sha256`` field there.

    Args:
        payload_type: DSSE payload-type string.
        body: Raw payload bytes (the ``canonical_json`` of the decision body).

    Returns:
        PAE-encoded bytes ready for hashing / signing.
    """
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt)).encode("ascii")
        + b" "
        + pt
        + b" "
        + str(len(body)).encode("ascii")
        + b" "
        + body
    )
