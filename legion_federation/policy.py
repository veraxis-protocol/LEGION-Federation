# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Veraxis. Independently authored; contains no LEGION Core source.
"""Federation-edge policies: disclosure and peer-request admission.

STATUS: new conservative wrapper policy, TESTED, NOT LEAN-PROVED. LEGION-Formal-Core v1.0.0 proves
properties of the single-collective Core model; it does not cover cross-collective disclosure or
contracts. Every decision is three-valued: T (allow), F (refuse), Z (unknown/stale/unverifiable ->
refuse). Only T permits an outbound release or a native effect.
"""
import re
import time

from . import crypto
from .canonical import sha256_hex

T, F, Z = "T", "F", "Z"

# Data classes that are NEVER released, whatever a grant says.
ALWAYS_PRIVATE = {"unit_cost_cents", "margin_floor_cents", "customer_ids", "supplier_list", "internal_estimate",
                  "private_plan", "private_prompt", "wallet", "budget_reserve", "secret"}


class DisclosurePolicy:
    """``public``: fields releasable to anyone for discovery. ``grantable``: fields releasable only with a
    valid owner-signed grant naming this recipient and purpose."""

    def __init__(self, owner_id, public, grantable, owner_key_id):
        self.owner_id, self.public, self.grantable = owner_id, set(public), set(grantable)
        self.owner_key_id = owner_key_id
        self.revoked_grants, self.epoch = set(), 1

    def policy_hash(self):
        return sha256_hex({"owner": self.owner_id, "public": sorted(self.public),
                           "grantable": sorted(self.grantable), "private": sorted(ALWAYS_PRIVATE)})

    def decide(self, field, recipient, purpose, grant_env=None, trusted=None, now=None):
        now = now or time.time()
        if not re.fullmatch(r"[a-z_]{2,40}", str(field)):
            return F, "malformed field name"
        if field in ALWAYS_PRIVATE:
            return F, "field is always private"
        if field in self.public and purpose == "discovery":
            return T, "public discovery field"
        if field not in self.grantable and field not in self.public:
            return F, "unknown field (default deny)"
        if grant_env is None:
            return F, "no grant"
        try:
            g = crypto.verify(grant_env, crypto.DOMAINS["grant"], trusted=trusted)
        except crypto.VerifyError as exc:
            return F, f"grant signature: {exc}"
        if g["grantor_owner_id"] != self.owner_id or grant_env["signer"]["key_id"] != self.owner_key_id:
            return F, "grant not issued by this owner"
        if g["grant_id"] in self.revoked_grants:
            return F, "grant revoked"
        if g["epoch"] != self.epoch:
            return Z, "grant from stale epoch"
        if now > g["expires_at"]:
            return Z, "grant expired"
        if g["recipient"] != recipient:
            return F, "wrong recipient"
        if g["purpose"] != purpose:
            return F, "wrong purpose"
        if field not in g["fields"]:
            return F, "field not in grant"
        return T, "granted"

    def revoke(self, grant_id):
        self.revoked_grants.add(grant_id)
        self.epoch += 1


class NonceStore:
    def __init__(self):
        self.seen = set()

    def first_use(self, nonce):
        if nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True


def admit_request(env, me_owner, registry, epochs, contract, nonces, now=None, max_age=300.0):
    """Admission for a consequential peer request ``env`` (domain lmf.peer-request.v1).

    registry: trusted key_id -> pub for each known owner, plus owner_of[key_id].
    epochs: owner_id -> current epoch (revocation). contract: dict with ``hash``, ``allowed`` list of
    {tool,target,args} or arg bounds, and ``parties``. Returns (verdict, reasons, payload|None)."""
    now = now or time.time()
    try:
        p = crypto.verify(env, crypto.DOMAINS["request"], trusted=registry["keys"])
    except crypto.VerifyError as exc:
        return F, [f"signature/identity: {exc}"], None
    signer_owner = registry["owner_of"].get(env["signer"]["key_id"])
    if signer_owner != p.get("from_owner"):
        return F, ["from_owner does not match the registered owner of the signing key"], p
    if p.get("to_owner") != me_owner:
        return F, ["wrong recipient"], p
    if p.get("from_owner") not in contract["parties"]:
        return F, ["requester is not a contract party"], p
    if p.get("contract_hash") != contract["hash"]:
        return F, ["contract version hash mismatch (stale or tampered terms)"], p
    if epochs.get(p["from_owner"]) != p.get("epoch"):
        return Z, ["requester epoch is not current (revoked or stale)"], p
    if not (p.get("issued_at", 0) <= now + 5 and now - p.get("issued_at", 0) <= max_age):
        return Z, ["request not fresh"], p
    if now > p.get("expires_at", 0):
        return Z, ["request expired"], p
    if not p.get("commitment_ref"):
        return F, ["no owner commitment bound to request"], p
    allowed = [a for a in contract["allowed"] if a["tool"] == p.get("tool") and a["target"] == p.get("target")]
    if not allowed:
        return F, ["tool/target not authorized by contract"], p
    a = allowed[0]
    for k, v in (p.get("args") or {}).items():
        spec = a["args"].get(k)
        if spec is None:
            return F, [f"argument {k} not in contract"], p
        if isinstance(spec, dict) and "max" in spec:
            if not isinstance(v, int) or v > spec["max"] or v < spec.get("min", 0):
                return F, [f"argument {k}={v} outside contracted bounds"], p
        elif isinstance(spec, list):
            if v not in spec:
                return F, [f"argument {k}={v!r} not contracted"], p
        elif v != spec:
            return F, [f"argument {k}={v!r} differs from contract"], p
    if set(a["args"]) - set((p.get("args") or {})):
        return F, ["missing contracted argument"], p
    if not nonces.first_use(p.get("nonce")):
        return F, ["replayed nonce"], p
    return T, ["admitted at federation edge"], p
