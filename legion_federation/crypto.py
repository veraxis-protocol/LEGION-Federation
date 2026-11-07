# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Veraxis. Independently authored; contains no LEGION Core source.
"""Ed25519 signed envelopes.

An envelope is ``{"domain", "payload", "signer": {"key_id", "pub"}, "sig"}``. The signature
covers ``domain || 0x00 || canonical(payload)`` so a signature in one domain can never be
replayed as another kind of object. A self-reported key is NOT an identity: verifiers must
check ``signer.key_id`` against a trusted registry (``verify(..., trusted=...)``).
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

from .canonical import canonical, sha256_hex

DOMAINS = {
    "peer": "lmf.peer-descriptor.v1",
    "grant": "lmf.disclosure-grant.v1",
    "opportunity": "lmf.opportunity.v1",
    "offer": "lmf.offer.v1",
    "contract": "lmf.coalition-contract.v1",
    "commitment": "lmf.owner-commitment.v1",
    "receipt": "lmf.evidence-receipt.v1",
    "judgement": "lmf.judgement.v1",
    "request": "lmf.peer-request.v1",
    "permit": "lmf.action-permit.v1",
}


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


class KeyPair:
    def __init__(self, priv: Ed25519PrivateKey = None):
        self._priv = priv or Ed25519PrivateKey.generate()
        raw = self._priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw)
        self.pub = b64(raw)
        self.key_id = key_id(self.pub)

    def sign(self, domain: str, payload: dict) -> dict:
        msg = domain.encode() + b"\x00" + canonical(payload)
        return {"domain": domain, "payload": payload,
                "signer": {"key_id": self.key_id, "pub": self.pub},
                "sig": b64(self._priv.sign(msg))}

    def private_bytes(self) -> bytes:
        return self._priv.private_bytes(serialization.Encoding.Raw,
                                        serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())

    @classmethod
    def from_private_bytes(cls, raw: bytes):
        return cls(Ed25519PrivateKey.from_private_bytes(raw))


def key_id(pub_b64: str) -> str:
    return "ed25519:" + sha256_hex(unb64(pub_b64))[:24]


class VerifyError(Exception):
    pass


def verify(env: dict, domain: str, trusted: dict = None) -> dict:
    """Verify an envelope. ``trusted`` maps key_id -> pub; when given the signer must be in it.

    Returns the payload or raises VerifyError (fail closed)."""
    try:
        if env.get("domain") != domain:
            raise VerifyError(f"domain mismatch: {env.get('domain')} != {domain}")
        signer = env["signer"]
        pub = signer["pub"]
        if key_id(pub) != signer["key_id"]:
            raise VerifyError("key_id does not match pub")
        if trusted is not None:
            if signer["key_id"] not in trusted or trusted[signer["key_id"]] != pub:
                raise VerifyError("signer not in trusted registry")
        msg = domain.encode() + b"\x00" + canonical(env["payload"])
        Ed25519PublicKey.from_public_bytes(unb64(pub)).verify(unb64(env["sig"]), msg)
        return env["payload"]
    except VerifyError:
        raise
    except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
        raise VerifyError(f"invalid envelope: {type(exc).__name__}") from None
