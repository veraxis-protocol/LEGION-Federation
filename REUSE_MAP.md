# REUSE_MAP — source file → Federation/Marketplace operation

Pinned revisions: see `SOURCE_PINS.json`. "Invoked" = imported/executed at run time from the pinned checkout, unmodified.

| External source (pinned) | Status | Federation / Marketplace operation |
|---|---|---|
| LEGION `tests/legion_struct/worlds/INDEX.json`, `SYN-*.world.json` (13) | Invoked (read) | 13-world federated cases: world definitions loaded by the operator peer |
| LEGION `tests/legion_struct/world_engine.py` (`World`) | Invoked | Native system of the operator owner: params, native preconditions, faults, idempotent `command_id`, effect ledger, reconcile, events |
| LEGION `judge/components/judge_s1/legion_judge/core.py` (`predicate`, `at_path`) | Invoked | Goal predicate evaluation inside the independent federated Judge |
| LEGION `tests/legion_struct/struct_controller.py`, `struct_plugin.py` | Inspected, NOT reused | Single-collective controller (CAGE/ZTL plumbing, NIM agents); Federation does not drive it. UNVERIFIED as a cross-owner interface |
| LEGION `judge/components/struct_adapter.py` | Inspected, NOT reused | Adapter for single-collective struct runs; federated Judge is new |
| LEGION `tests/legion_scale/` | Inspected, NOT reused today | 100-worker scale harness; registration counts here are new code |
| LEGION-Formal-Core v1.0.0 (Lean T1–T15/J1–J6) | Cited only | Scope statement: proves the Core model; does NOT prove federation, disclosure, or external payment |
| LEGION-Commerce `commerce_adapter/{gateway,paypal,readback,approval}.py` @228899a | Invoked only in WO-LMF-007 | PayPal Sandbox Orders v2 create/approve/capture, independent readback, durable budget ledger |
| LEGION-Commerce `commerce_bridge` (qualified BCh, Lean decider) | Invoked only in WO-LMF-007 | Exact-action Lean T for each capture (sandbox-demo profile) |
| ZTL / ztl-swarm / ztl-stand | Provenance only | Not invoked today |

New (PolyForm NC, Veraxis-authored) mechanisms with NO Core equivalent: peer identity registry, disclosure grants & policy, peer-request
admission (edge wrapper, tested not proved), coalition contract versioning, owner commitments, marketplace registry,
coalition solver, feasibility oracle, comparators, federated Judge.
