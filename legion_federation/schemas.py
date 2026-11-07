# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Veraxis. Independently authored; contains no LEGION Core source.
"""Versioned, transport-neutral JSON Schemas for Federation and Marketplace objects.

All money is integer cents. All times are UNIX seconds (float). Every object carries an owner,
an epoch and an expiry so a stale or revoked object is detectable without a global clock service.
"""
import json
import os

import jsonschema

S = "https://json-schema.org/draft/2020-12/schema"
ID = {"type": "string", "minLength": 3, "maxLength": 128, "pattern": r"^[A-Za-z0-9:_.\-]+$"}
OWNER = {"type": "string", "pattern": r"^owner:[a-z0-9\-]{2,40}$"}
PEER = {"type": "string", "pattern": r"^peer:[a-z0-9\-]{2,40}$"}
CENTS = {"type": "integer", "minimum": 0, "maximum": 10_000_000_00}
T = {"type": "number", "minimum": 1.7e9, "maximum": 4.0e9}
EPOCH = {"type": "integer", "minimum": 1}
HASH = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
SHORT = {"type": "string", "maxLength": 240}

ROLE = {"enum": ["buyer", "factory", "engineer", "operator", "requester", "marketplace", "judge"]}

DEFS = {
    "PeerDescriptor": {
        "required": ["schema", "peer_id", "owner_id", "owner_pseudonym", "role", "endpoint",
                     "signing_key_id", "epoch", "issued_at", "expires_at", "registered_workers",
                     "policy_hash", "version"],
        "properties": {
            "schema": {"const": "lmf.peer-descriptor.v1"}, "peer_id": PEER, "owner_id": OWNER,
            "owner_pseudonym": {"type": "string", "pattern": r"^[A-Za-z0-9\-]{2,32}$"},
            "role": ROLE, "endpoint": {"type": "string", "pattern": r"^http://127\.0\.0\.1:[0-9]{2,5}$"},
            "signing_key_id": {"type": "string", "pattern": r"^ed25519:[0-9a-f]{24}$"},
            "epoch": EPOCH, "issued_at": T, "expires_at": T,
            "registered_workers": {"type": "integer", "minimum": 1, "maximum": 100},
            "policy_hash": HASH, "version": {"const": 1}}},
    "DisclosureGrant": {
        "required": ["schema", "grant_id", "grantor_owner_id", "recipient", "purpose", "fields",
                     "epoch", "issued_at", "expires_at", "nonce", "policy_hash"],
        "properties": {
            "schema": {"const": "lmf.disclosure-grant.v1"}, "grant_id": ID, "grantor_owner_id": OWNER,
            "recipient": {"type": "string", "pattern": r"^(peer:[a-z0-9\-]{2,40}|marketplace|coalition:[A-Za-z0-9\-]+)$"},
            "purpose": {"enum": ["discovery", "negotiation", "contract", "execution", "audit"]},
            "fields": {"type": "array", "items": {"type": "string", "pattern": r"^[a-z_]{2,40}$"},
                       "maxItems": 20, "uniqueItems": True},
            "epoch": EPOCH, "issued_at": T, "expires_at": T,
            "nonce": {"type": "string", "pattern": r"^[0-9a-f]{16,64}$"}, "policy_hash": HASH}},
    "Opportunity": {
        "required": ["schema", "intent_id", "owner_id", "owner_pseudonym", "peer_id", "kind", "class",
                     "spec_hash", "valid_until", "epoch", "grant_id", "version"],
        "properties": {
            "schema": {"const": "lmf.opportunity.v1"}, "intent_id": ID, "owner_id": OWNER,
            "owner_pseudonym": {"type": "string", "pattern": r"^[A-Za-z0-9\-]{2,32}$"}, "peer_id": PEER,
            "kind": {"enum": ["demand", "supply", "service"]},
            "class": {"type": "string", "pattern": r"^[a-z0-9\-]{2,40}$"}, "spec_hash": HASH,
            "quantity": {"type": "integer", "minimum": 1, "maximum": 100000},
            "minimum_quantity": {"type": "integer", "minimum": 1, "maximum": 100000},
            "available_capacity": {"type": "integer", "minimum": 0, "maximum": 100000},
            "max_payment_cents": CENTS, "service": {"type": "string", "pattern": r"^[a-z\-]{2,40}$"},
            "valid_until": T, "epoch": EPOCH, "grant_id": ID, "version": {"type": "integer", "minimum": 1},
            "description": SHORT},
        "additionalProperties": False},
    "Offer": {
        "required": ["schema", "offer_id", "from_owner", "to", "basis", "lines", "epoch", "issued_at",
                     "expires_at", "offer_version"],
        "properties": {
            "schema": {"const": "lmf.offer.v1"}, "offer_id": ID, "from_owner": OWNER,
            "to": {"type": "string"}, "basis": {"type": "array", "items": ID, "maxItems": 20},
            "lines": {"type": "array", "minItems": 1, "maxItems": 10, "items": {
                "type": "object", "required": ["item", "quantity", "amount_cents"],
                "properties": {"item": {"type": "string", "pattern": r"^[a-z0-9\-]{2,40}$"},
                               "design_id": {"type": "string", "pattern": r"^[A-Za-z0-9\-]{2,40}$"},
                               "quantity": {"type": "integer", "minimum": 1}, "amount_cents": CENTS},
                "additionalProperties": False}},
            "conditions": {"type": "array", "items": SHORT, "maxItems": 10},
            "epoch": EPOCH, "issued_at": T, "expires_at": T, "offer_version": {"type": "integer", "minimum": 1},
            "supersedes": {"type": ["string", "null"]}}},
    "CoalitionContract": {
        "required": ["schema", "contract_id", "version", "prev_version_hash", "mission_ids", "parties",
                     "payments", "quantity", "spec_hash", "design_id", "qualification", "deadline",
                     "partial_failure_policy", "currency", "created_at"],
        "properties": {
            "schema": {"const": "lmf.coalition-contract.v1"}, "contract_id": ID,
            "version": {"type": "integer", "minimum": 1}, "prev_version_hash": {"type": ["string", "null"]},
            "mission_ids": {"type": "array", "items": ID, "minItems": 2},
            "parties": {"type": "array", "minItems": 2, "maxItems": 20, "items": {
                "type": "object", "required": ["owner_id", "peer_id", "role", "obligations"],
                "properties": {"owner_id": OWNER, "peer_id": PEER, "role": ROLE,
                               "obligations": {"type": "array", "minItems": 1, "items": {
                                   "type": "object", "required": ["obligation_id", "kind"],
                                   "properties": {"obligation_id": ID, "kind": {"enum": [
                                       "pay", "receive_units", "manufacture", "qualify", "ship"]},
                                       "quantity": {"type": "integer", "minimum": 0},
                                       "amount_cents": CENTS, "counterparty": {"type": "string"}}}}}}},
            "payments": {"type": "array", "items": {"type": "object",
                         "required": ["payer", "payee", "amount_cents", "purpose"],
                         "properties": {"payer": OWNER, "payee": OWNER, "amount_cents": CENTS,
                                        "purpose": SHORT}}},
            "quantity": {"type": "integer", "minimum": 1}, "spec_hash": HASH,
            "design_id": {"type": "string"}, "qualification": {"type": "object"},
            "deadline": T, "partial_failure_policy": SHORT, "currency": {"const": "USD"},
            "created_at": T, "price_basis": {"type": "object"}}},
    "OwnerCommitment": {
        "required": ["schema", "commitment_id", "owner_id", "contract_id", "contract_version_hash",
                     "decision", "scope", "max_amount_cents", "epoch", "issued_at", "expires_at"],
        "properties": {
            "schema": {"const": "lmf.owner-commitment.v1"}, "commitment_id": ID, "owner_id": OWNER,
            "contract_id": ID, "contract_version_hash": HASH, "decision": {"enum": ["ACCEPT", "REJECT"]},
            "scope": {"type": "array", "items": ID}, "max_amount_cents": CENTS, "epoch": EPOCH,
            "issued_at": T, "expires_at": T, "rationale": SHORT,
            "model_decision_ref": {"type": ["string", "null"]}}},
    "EvidenceReceipt": {
        "required": ["schema", "receipt_id", "issuer_owner_id", "contract_version_hash", "obligation_id",
                     "action", "command_id", "effect_id", "readback_sha256", "mode", "issued_at"],
        "properties": {
            "schema": {"const": "lmf.evidence-receipt.v1"}, "receipt_id": ID, "issuer_owner_id": OWNER,
            "contract_version_hash": HASH, "obligation_id": ID, "action": {"type": "string"},
            "command_id": ID, "effect_id": {"type": "string"}, "readback_sha256": HASH,
            "mode": {"enum": ["SIMULATED", "REAL_SANDBOX"]}, "issued_at": T}},
    "Judgement": {
        "required": ["schema", "judgement_id", "mission_id", "verdict", "checks", "evidence_sha256",
                     "judge_process", "issued_at"],
        "properties": {
            "schema": {"const": "lmf.judgement.v1"}, "judgement_id": ID, "mission_id": ID,
            "verdict": {"enum": ["PASS_COMPLETED", "FAIL", "SAFE_STOP", "INDETERMINATE", "INVALID_TEST"]},
            "checks": {"type": "array", "items": {"type": "object", "required": ["check", "pass"]}},
            "evidence_sha256": {"type": "object"}, "judge_process": {"type": "object"}, "issued_at": T}},
}


def schema(name: str) -> dict:
    d = DEFS[name]
    out = {"$schema": S, "$id": f"https://github.com/veraxis-protocol/LEGION-Federation/schemas/{name}.schema.json",
           "title": name, "type": "object", "required": d["required"], "properties": d["properties"]}
    if "additionalProperties" in d:
        out["additionalProperties"] = d["additionalProperties"]
    return out


def validate(name: str, obj: dict) -> None:
    jsonschema.Draft202012Validator(schema(name)).validate(obj)


def is_valid(name: str, obj: dict) -> bool:
    try:
        validate(name, obj)
        return True
    except jsonschema.ValidationError:
        return False


def write_all(directory: str) -> list:
    os.makedirs(directory, exist_ok=True)
    paths = []
    for name in DEFS:
        p = os.path.join(directory, f"{name}.schema.json")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(schema(name), fh, indent=2, sort_keys=True)
            fh.write("\n")
        paths.append(p)
    return paths
