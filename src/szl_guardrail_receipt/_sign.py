# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""ECDSA-P256-SHA256 DSSE sign/verify primitives (cosign-compatible).

Signing style mirrors the SZL estate (``szl-receipt`` / ``khipu-consensus``):
ECDSA-P256 over SHA-256 of the **standard DSSE PAE**, DER signature, base64.

``cryptography`` is an OPTIONAL dependency. When it is not installed, signing is
unavailable and callers fall back to the UNSIGNED-honest path — we never
fabricate a signature. Import guard keeps the receipt core pure-stdlib.
"""
from __future__ import annotations

import base64
import binascii
from typing import Tuple

from ._canonical import canonical_json, dsse_pae

#: DSSE payload type for guardrail decision receipts.
PAYLOAD_TYPE: str = "application/vnd.szl.guardrail-receipt+json"

try:  # optional dependency — only needed to *make* or *check* real signatures
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001 - any import failure means "no crypto here"
    HAVE_CRYPTO = False


class SigningUnavailable(RuntimeError):
    """Raised when a signing/verify op needs ``cryptography`` but it is absent."""


def crypto_available() -> bool:
    """True iff the optional ``cryptography`` backend is importable."""
    return HAVE_CRYPTO


def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate an ephemeral ECDSA-P256 keypair as unencrypted PEM bytes.

    Returns:
        ``(private_key_pem, public_key_pem)``.

    Raises:
        SigningUnavailable: when ``cryptography`` is not installed.
    """
    if not HAVE_CRYPTO:
        raise SigningUnavailable("cryptography is not installed")
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def sign_pae(body_dict: object, private_key_pem: bytes | str) -> str:
    """Sign a decision body with ECDSA-P256-SHA256 over its DSSE PAE.

    Args:
        body_dict: JSON-serialisable decision body.
        private_key_pem: PEM-encoded ECDSA-P256 private key.

    Returns:
        Base64 (standard, cosign-style) DER signature string.

    Raises:
        SigningUnavailable: when ``cryptography`` is not installed.
    """
    if not HAVE_CRYPTO:
        raise SigningUnavailable("cryptography is not installed")
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    signing_bytes = dsse_pae(PAYLOAD_TYPE, canonical_json(body_dict))
    der_sig = priv.sign(signing_bytes, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(der_sig).decode("ascii")


def verify_dsse(
    payload_type: str,
    payload_bytes: bytes,
    signature_b64: str,
    public_key_pem: bytes | str,
) -> Tuple[bool, str]:
    """Verify an ECDSA-P256-SHA256 signature over the DSSE PAE of EXACT bytes.

    The preimage is ``dsse_pae(payload_type, payload_bytes)`` built from the
    envelope's own declared ``payloadType`` and its exact decoded payload
    bytes — never a re-serialisation of the decoded body — so a payload-type
    swap or an alternate serialisation cannot inherit a signature. The key
    must be an ECDSA P-256 public key (the receipt's declared algorithm).

    Returns:
        ``(True, "ok")`` on success, ``(False, "<reason>")`` otherwise. Never
        raises on a bad signature/key/shape — that is a graceful ``False``.

    Raises:
        SigningUnavailable: when ``cryptography`` is not installed.
    """
    if not HAVE_CRYPTO:
        raise SigningUnavailable("cryptography is not installed")
    if not isinstance(payload_type, str) or not isinstance(payload_bytes, (bytes, bytearray)):
        return False, "payloadType must be str and payload must be bytes"
    if not isinstance(signature_b64, str):
        return False, "signature is not a base64 string"
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False, "signature is not strict base64"
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    try:
        pub = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:  # noqa: BLE001
        return False, f"invalid key or encoding: {exc}"
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        return False, "public key is not an ECDSA P-256 key (declared ECDSA-P256-SHA256)"
    try:
        pub.verify(signature, dsse_pae(payload_type, bytes(payload_bytes)), ec.ECDSA(hashes.SHA256()))
        return True, "ok"
    except InvalidSignature:
        return False, "signature mismatch"
    except Exception as exc:  # noqa: BLE001
        return False, f"invalid signature encoding: {exc}"


def verify_pae(
    body_dict: object,
    signature_b64: str,
    public_key_pem: bytes | str,
) -> Tuple[bool, str]:
    """Verify a signature produced by :func:`sign_pae` over *body_dict*.

    This helper re-derives the preimage as
    ``dsse_pae(PAYLOAD_TYPE, canonical_json(body_dict))``, so it answers "was
    this body signed?" — not "is this envelope authentic?". Receipt
    verification uses :func:`verify_dsse` over the envelope's exact decoded
    bytes and declared type instead.

    Returns:
        ``(True, "ok")`` on success, ``(False, "<reason>")`` otherwise. Never
        raises on a bad signature/key — a bad shape is a graceful ``False``.

    Raises:
        SigningUnavailable: when ``cryptography`` is not installed.
    """
    if not HAVE_CRYPTO:
        raise SigningUnavailable("cryptography is not installed")
    try:
        payload_bytes = canonical_json(body_dict)
    except Exception as exc:  # noqa: BLE001
        return False, f"body is not JSON-serialisable: {exc}"
    return verify_dsse(PAYLOAD_TYPE, payload_bytes, signature_b64, public_key_pem)
