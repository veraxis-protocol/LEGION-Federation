# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""WO-LMF-001: every schema validates a sample, survives sign/serialize/parse/verify, and rejects tampering."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from legion_federation import crypto, schemas  # noqa: E402
from legion_federation.canonical import sha256_hex  # noqa: E402

NOW = 1794000000.0
H = "a" * 64


def samples():
    return {
        "PeerDescriptor": {"schema": "lmf.peer-descriptor.v1", "peer_id": "peer:b1", "owner_id": "owner:b1",
                           "owner_pseudonym": "Buyer-1", "role": "buyer", "endpoint": "http://127.0.0.1:9101",
                           "signing_key_id": "ed25519:" + "0" * 24, "epoch": 1, "issued_at": NOW,
                           "expires_at": NOW + 3600, "registered_workers": 100, "policy_hash": H, "version": 1},
        "DisclosureGrant": {"schema": "lmf.disclosure-grant.v1", "grant_id": "grant-1", "grantor_owner_id": "owner:b1",
                            "recipient": "marketplace", "purpose": "discovery", "fields": ["class", "quantity"],
                            "epoch": 1, "issued_at": NOW, "expires_at": NOW + 600, "nonce": "0123456789abcdef",
                            "policy_hash": H},
        "Opportunity": {"schema": "lmf.opportunity.v1", "intent_id": "intent-1", "owner_id": "owner:b1",
                        "owner_pseudonym": "Buyer-1", "peer_id": "peer:b1", "kind": "demand", "class": "sensor-module",
                        "spec_hash": H, "quantity": 20, "max_payment_cents": 10000, "valid_until": NOW + 600,
                        "epoch": 1, "grant_id": "grant-1", "version": 1},
        "Offer": {"schema": "lmf.offer.v1", "offer_id": "offer-1", "from_owner": "owner:f1", "to": "coalition:c1",
                  "basis": ["intent-1"], "lines": [{"item": "sensor-module", "design_id": "D-A", "quantity": 100,
                                                    "amount_cents": 40000}],
                  "epoch": 1, "issued_at": NOW, "expires_at": NOW + 600, "offer_version": 1, "supersedes": None},
        "CoalitionContract": {"schema": "lmf.coalition-contract.v1", "contract_id": "contract-1", "version": 1,
                              "prev_version_hash": None, "mission_ids": ["m-b1", "m-f1"],
                              "parties": [{"owner_id": "owner:b1", "peer_id": "peer:b1", "role": "buyer",
                                           "obligations": [{"obligation_id": "ob-b1-pay", "kind": "pay",
                                                            "amount_cents": 9600}]},
                                          {"owner_id": "owner:f1", "peer_id": "peer:f1", "role": "factory",
                                           "obligations": [{"obligation_id": "ob-f1-mfg", "kind": "manufacture",
                                                            "quantity": 100}]}],
                              "payments": [{"payer": "owner:b1", "payee": "owner:f1", "amount_cents": 9600,
                                            "purpose": "units"}],
                              "quantity": 100, "spec_hash": H, "design_id": "D-A", "qualification": {},
                              "deadline": NOW + 3600, "partial_failure_policy": "no unit ships unless all paid",
                              "currency": "USD", "created_at": NOW},
        "OwnerCommitment": {"schema": "lmf.owner-commitment.v1", "commitment_id": "commit-1", "owner_id": "owner:b1",
                            "contract_id": "contract-1", "contract_version_hash": H, "decision": "ACCEPT",
                            "scope": ["ob-b1-pay"], "max_amount_cents": 9600, "epoch": 1, "issued_at": NOW,
                            "expires_at": NOW + 600},
        "EvidenceReceipt": {"schema": "lmf.evidence-receipt.v1", "receipt_id": "rcpt-1", "issuer_owner_id": "owner:f1",
                            "contract_version_hash": H, "obligation_id": "ob-f1-mfg", "action": "factory.manufacture",
                            "command_id": "cmd-1", "effect_id": "eff-1", "readback_sha256": H, "mode": "SIMULATED",
                            "issued_at": NOW},
        "Judgement": {"schema": "lmf.judgement.v1", "judgement_id": "judge-1", "mission_id": "mission-1",
                      "verdict": "PASS_COMPLETED", "checks": [{"check": "x", "pass": True}],
                      "evidence_sha256": {}, "judge_process": {"pid": 1}, "issued_at": NOW},
    }


class SchemaRoundTrip(unittest.TestCase):
    def test_every_schema_has_a_valid_sample(self):
        s = samples()
        self.assertEqual(set(s), set(schemas.DEFS))
        for name, obj in s.items():
            schemas.validate(name, obj)

    def test_sign_serialize_parse_verify(self):
        kp = crypto.KeyPair()
        dom = {"PeerDescriptor": "peer", "DisclosureGrant": "grant", "Opportunity": "opportunity", "Offer": "offer",
               "CoalitionContract": "contract", "OwnerCommitment": "commitment", "EvidenceReceipt": "receipt",
               "Judgement": "judgement"}
        for name, obj in samples().items():
            env = kp.sign(crypto.DOMAINS[dom[name]], obj)
            wire = json.dumps(env)
            back = json.loads(wire)
            payload = crypto.verify(back, crypto.DOMAINS[dom[name]], trusted={kp.key_id: kp.pub})
            self.assertEqual(sha256_hex(payload), sha256_hex(obj))
            schemas.validate(name, payload)

    def test_tamper_wrong_domain_untrusted_key_rejected(self):
        kp, other = crypto.KeyPair(), crypto.KeyPair()
        obj = samples()["OwnerCommitment"]
        env = kp.sign(crypto.DOMAINS["commitment"], obj)
        bad = json.loads(json.dumps(env))
        bad["payload"]["max_amount_cents"] = 10100
        with self.assertRaises(crypto.VerifyError):
            crypto.verify(bad, crypto.DOMAINS["commitment"])
        with self.assertRaises(crypto.VerifyError):
            crypto.verify(env, crypto.DOMAINS["contract"])
        with self.assertRaises(crypto.VerifyError):
            crypto.verify(env, crypto.DOMAINS["commitment"], trusted={other.key_id: other.pub})
        forged = dict(env, signer={"key_id": other.key_id, "pub": other.pub})
        with self.assertRaises(crypto.VerifyError):
            crypto.verify(forged, crypto.DOMAINS["commitment"])

    def test_schema_rejects_bad_values(self):
        o = samples()["Opportunity"]
        for bad in ({"max_payment_cents": 99.5}, {"owner_id": "b1"}, {"unit_cost_cents": 300}, {"kind": "steal"}):
            self.assertFalse(schemas.is_valid("Opportunity", dict(o, **bad)), bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
