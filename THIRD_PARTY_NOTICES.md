# Third-party notices

| Component | Use | License | How it is used |
|---|---|---|---|
| LEGION Core (`veraxis-protocol/LEGION` @ d083c44) | 13 synthetic world definitions, `world_engine.py`, reference Judge `legion_judge.core.predicate` | PolyForm Noncommercial 1.0.0 (+ Apache-2.0 for upstream Google CAGE parts) | Imported at run time from a separate pinned checkout (`LEGION_CORE` path). Not copied, not modified, not relicensed. |
| LEGION-Formal-Core (`v1.0.0` → f5ea79c) | Proof scope reference only | PolyForm Noncommercial 1.0.0 | Cited, not linked. Its Lean proofs cover the single-collective Core model, not this federation. |
| LEGION-Commerce (`claude/wo-com-authority-005` @ 228899a) | PayPal Sandbox A04 gateway / readback (payment stage only) | No license selected by its owner | Invoked from its own checkout; not copied. |
| `cryptography` | Ed25519 signatures | Apache-2.0 / BSD-3-Clause | pip dependency |
| `jsonschema` | Schema validation | MIT | pip dependency |
| NVIDIA NIM API (`nvidia/nemotron-3.5-lightning-30b-a3b`) | Model-driven agent decisions | Provider terms | Remote API; key read from a local file, never committed |

**Whole-stack status:** the two Apache-2.0 overlays are open source; the runnable demonstration requires the
PolyForm-Noncommercial LEGION Core, so the complete runnable stack is NOT OSI open source. Hackathon
eligibility on that point is an explicit open question (see PAYPAL_ELIGIBILITY.md in LEGION-Marketplace).
