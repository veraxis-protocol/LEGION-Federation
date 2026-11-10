# LEGION-Federation

Owner-isolated federation of independent LEGION-100 collectives: signed peer identity, owner-scoped disclosure,
multi-owner negotiation, coalition contracts and per-owner commitments, without a shared superuser.

**Status (2026-11-07):** research demonstration. Federation-edge admission and disclosure policies are *tested,
not Lean-proved*. LEGION-Formal-Core proves the single-collective Core model, not cross-collective composition.

## What is here
* `legion_federation/` – canonical JSON, Ed25519 envelopes, schemas (`PeerDescriptor`, `DisclosureGrant`, `Opportunity`,
  `Offer`, `CoalitionContract`, `OwnerCommitment`, `EvidenceReceipt`, `Judgement`), hash-chained journals, disclosure
  policy, peer-request admission, owner peer processes, the 13-world operator peer.
* `schemas/` – generated JSON Schemas (draft 2020-12).
* `tools/run_world_cases.py`, `tools/judge_world_cases.py` – 13 worlds x 4 federated cases with an independent Judge.
* `tests/` – unit and negative tests.

## Run
```
python -m venv .venv && .venv\Scripts\pip install -r requirements.lock
.venv\Scripts\python -m unittest discover -s tests
```
The 13-world harness needs a separately obtained LEGION Core checkout at the pinned revision (PolyForm Noncommercial;
see `SOURCE_PINS.json`): `python tools/run_world_cases.py --cases <FED_WORLD_CASES.json> --core <LEGION> --out <dir>`.

## Related repositories

| Repository | Role | License |
|---|---|---|
| [LEGION-Deal-Rescue](https://github.com/veraxis-protocol/LEGION-Deal-Rescue) | Merchant application and PayPal AI Hackathon entry built on this stack | Apache-2.0 |
| [LEGION](https://github.com/veraxis-protocol/LEGION) | LEGION Core runtime (100 registered workers per collective, worlds, Judge) | PolyForm Noncommercial 1.0.0 |
| [LEGION-Formal-Core](https://github.com/veraxis-protocol/LEGION-Formal-Core) | Lean 4 model of single-collective admission and completion | PolyForm Noncommercial 1.0.0 |
| [LEGION-Federation](https://github.com/veraxis-protocol/LEGION-Federation) | Owner-isolated peers, disclosure policy, multi-owner contracts | PolyForm Noncommercial 1.0.0 |
| [LEGION-Marketplace](https://github.com/veraxis-protocol/LEGION-Marketplace) | Intent publication, discovery, end-to-end harness, independent Judge | PolyForm Noncommercial 1.0.0 |
| [LEGION-Commerce](https://github.com/veraxis-protocol/LEGION-Commerce) | PayPal Sandbox gateway, admission bridge, payment orchestration | no license file (all rights reserved) |

## License
PolyForm Noncommercial License 1.0.0 (owner decision, 2026-11-07), the same license as LEGION Core. Noncommercial use
only; commercial use requires a separate license from Veraxis. This is **not** an OSI open-source license. See `NOTICE`.
