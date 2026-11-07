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

## License
PolyForm Noncommercial License 1.0.0 (owner decision, 2026-11-07), the same license as LEGION Core. Noncommercial use
only; commercial use requires a separate license from Veraxis. This is **not** an OSI open-source license. See `NOTICE`.
