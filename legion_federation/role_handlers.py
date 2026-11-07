# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 Veraxis. Independently authored; contains no LEGION Core source.
"""HTTP endpoint logic for owner peers (buyer / factory / engineer). See owner_peer.py."""
import json
import os
import threading
import urllib.request

from . import crypto, policy, schemas
from .canonical import new_id, now, sha256_hex

COORD = "coordinator:hub"


def post(url, body, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def admin(o, path, body, server):
    if path == "/admin/trust":
        o.set_trust(body["keys"])
        o.endpoints.update(body.get("endpoints") or {})
        return {"ok": True}
    if path == "/admin/publish":
        env, grant = o.opportunity()
        r = post(body["marketplace"] + "/intents", {"envelope": env, "grant": grant})
        o.j.emit("INTENT_SUBMITTED", marketplace_response=r)
        return {"intent": env["payload"], "marketplace": r}
    if path == "/admin/event":
        ev = o.world.fire(body["event"])
        o.j.emit("ENV_EVENT", event=body["event"], fired=ev is not None)
        revoked = []
        if o.role == "factory" and ev is not None:
            # A supplier reprice invalidates our commitments to versions priced below the new list price.
            for chash, t in list(o.commit_terms.items()):
                newp = o.world.state["price"].get(t["design"], 0) + o.private["shipping_cents"]
                if chash in o.commitments and t["received_cents"] < newp:
                    o.revoke(chash)
                    revoked.append(chash)
            o.current_offers = {}
        return {"fired": ev is not None, "revoked_commitments": revoked}
    if path == "/admin/revoke":
        return o.revoke(body["contract_hash"])
    if path == "/admin/revoke_grant":
        o.dpolicy.revoke(body["grant_id"])
        o.j.emit("GRANT_REVOKED", grant_id=body["grant_id"], epoch=o.dpolicy.epoch)
        return {"epoch": o.dpolicy.epoch}
    if path == "/admin/issue_grant":
        g = o.key.sign(crypto.DOMAINS["grant"], {
            "schema": "lmf.disclosure-grant.v1", "grant_id": new_id("grant"), "grantor_owner_id": o.owner,
            "recipient": body["recipient"], "purpose": body["purpose"], "fields": body["fields"],
            "epoch": o.dpolicy.epoch, "issued_at": now(), "expires_at": now() + body.get("ttl", 600),
            "nonce": os.urandom(8).hex(), "policy_hash": o.dpolicy.policy_hash()})
        o.j.emit("GRANT_ISSUED", grant=g["payload"])
        return {"grant": g}
    if path == "/admin/kill":
        o.j.emit("PEER_KILLED", by="harness")
        os._exit(17)
    if path == "/admin/shutdown":
        threading.Thread(target=server.shutdown, daemon=True).start()
        return {"ok": True}
    return {"error": "unknown admin path"}


def public(o, path, body):
    if path == "/query":
        env = body["envelope"]
        try:
            p, who = o.verify_from(env, crypto.DOMAINS["request"])
            recipient = "peer:" + who.split(":", 1)[1]
        except crypto.VerifyError:
            p, recipient = env.get("payload") or {}, "peer:unverified"
        if not o.nonces.first_use(p.get("nonce")):
            o.disc.emit("DISCLOSURE_DECISION", field="*", recipient=recipient, purpose=p.get("purpose"), verdict="F",
                        reason="replayed query", released_sha256=None, private_class=False)
            return {"released": {}, "decisions": [{"field": "*", "verdict": "F", "reason": "replayed query"}]}
        fields = p.get("fields") or []
        if len(fields) > 12 or "*" in fields:
            o.disc.emit("DISCLOSURE_DECISION", field="*", recipient=recipient, purpose=p.get("purpose"), verdict="F",
                        reason="bulk query disallowed", released_sha256=None, private_class=True)
            return {"released": {}, "decisions": [{"field": "*", "verdict": "F", "reason": "bulk query disallowed"}]}
        if recipient == "peer:unverified":
            for f in fields:
                o.disc.emit("DISCLOSURE_DECISION", field=f, recipient=recipient, purpose=p.get("purpose"), verdict="F",
                            reason="unverified identity", released_sha256=None, private_class=f in o.private)
            return {"released": {}, "decisions": [{"field": f, "verdict": "F", "reason": "unverified identity"} for f in fields]}
        released, decisions = o.release(fields, recipient, p.get("purpose", "negotiation"), p.get("grant"))
        return {"released": released, "decisions": decisions}
    if path == "/propose":
        return o.evaluate_contract_env(body)
    if path == "/status":
        return {"status": o.commitment_status(body["contract_hash"])}
    if path == "/authorize":
        return o.authorize(body["contract"], body["commitments"], body["statuses"])
    if path == "/quote" and o.role == "factory":
        return factory_quote(o, body)
    if path == "/qualify" and o.role == "engineer":
        return engineer_qualify(o, body)
    if path == "/execute":
        return execute(o, body)
    if path == "/deliver" and o.role == "buyer":
        return buyer_deliver(o, body)
    return {"error": "unknown path"}


def factory_quote(o, body):
    req, _ = o.verify_from(body["envelope"], crypto.DOMAINS["request"], expect_owner=COORD)
    prices = o.world.state["price"]
    avail = {d: p for d, p in prices.items() if o.world.state["available"].get(d)}
    ctx = {"request": {k: req.get(k) for k in ("quantity", "spec_hash", "note")},
           "current_list_prices_cents_for_100_units": avail, "shipping_cents": o.private["shipping_cents"],
           "moq_units": o.private["moq_units"]}
    dec, rec = o.agent("Choose which designs to offer for this coalition order (you may not price below your floor).",
                       ctx, {"type": "object", "additionalProperties": False, "required": ["offer_designs", "rationale"],
                             "properties": {"offer_designs": {"type": "array", "items": {"enum": sorted(avail)},
                                                              "maxItems": 3},
                                            "rationale": {"type": "string", "maxLength": 300}}})
    chosen = [d for d in (dec or {}).get("offer_designs", []) if d in avail
              and avail[d] >= o.private["price_floor_cents"].get(d, 10**9)]
    o.offer_version += 1
    o.current_offers = {d: {"amount_cents": avail[d], "offer_version": o.offer_version} for d in chosen}
    offers = []
    for d in chosen:
        off = {"schema": "lmf.offer.v1", "offer_id": new_id("offer"), "from_owner": o.owner, "to": "coalition:" + req["coalition_id"],
               "basis": req.get("basis", [])[:20],
               "lines": [{"item": "sensor-module", "design_id": d, "quantity": req["quantity"], "amount_cents": avail[d]},
                         {"item": "shipping", "quantity": 1, "amount_cents": o.private["shipping_cents"]}],
               "conditions": [f"MOQ {o.private['moq_units']}", "design must carry engineer qualification certificate"],
               "epoch": o.epoch, "issued_at": now(), "expires_at": now() + 900, "offer_version": o.offer_version,
               "supersedes": None}
        schemas.validate("Offer", off)
        offers.append(o.key.sign(crypto.DOMAINS["offer"], off))
    o.j.emit("OFFERS_ISSUED", offer_version=o.offer_version, designs=chosen, model_response_id=rec.get("response_id"))
    return {"offers": offers, "rationale": (dec or {}).get("rationale"), "model_response_id": rec.get("response_id")}


def engineer_qualify(o, body):
    req, _ = o.verify_from(body["envelope"], crypto.DOMAINS["request"], expect_owner=COORD)
    ctx = {"designs_to_test": req["designs"], "spec_hash": req["spec_hash"], "fee_cents": o.private["fee_cents"],
           "note": req.get("note", "")}
    dec, rec = o.agent(f"A buyer coalition asks your lab to run fixture QF-7 on designs {', '.join(req['designs'])} for spec "
                       f"{req['spec_hash'][:12]} (your published service). Your fee of {o.private['fee_cents']} cents is paid only "
                       "if a contract is formed. Pass/fail comes from the fixture itself, never from your opinion. Answer run=true "
                       "to accept the engagement and run the fixture, or run=false to decline.", ctx,
                       {"type": "object", "additionalProperties": False, "required": ["run", "rationale"],
                        "properties": {"run": {"type": "boolean"}, "rationale": {"type": "string", "maxLength": 300}}})
    if not (dec or {}).get("run"):
        return {"certificates": [], "declined": True, "model_response_id": rec.get("response_id")}
    certs, results = [], {}
    for d in req["designs"]:
        if d not in o.world.state["designs"]:
            continue
        chk = [("spec_matches", req["spec_hash"] == o.cfg["spec_hash"]), ("design_known", True)]
        if o.admit("run_fixture", None, chk) != policy.T:
            continue
        cmd = f"fixture-{d}-{req['coalition_id']}"
        st, res = o.native(cmd, "engineer.run_fixture", f"fixture-{d}", {"design": d})
        passed = o.value(f"results.{d}.pass") is True
        results[d] = passed
        certs.append({"design_id": d, "engineer": o.owner, "pass": passed,
                      "certificate": o.receipt(sha256_hex({"coalition": req["coalition_id"], "design": d}),
                                               f"qualify-{d}" if passed else f"qualify-fail-{d}",
                                               "engineer.run_fixture", cmd, res)})
    fee = {"schema": "lmf.offer.v1", "offer_id": new_id("offer"), "from_owner": o.owner, "to": "coalition:" + req["coalition_id"],
           "basis": [], "lines": [{"item": "qualification", "quantity": 1, "amount_cents": o.private["fee_cents"]}],
           "epoch": o.epoch, "issued_at": now(), "expires_at": now() + 900, "offer_version": 1, "supersedes": None}
    o.j.emit("QUALIFICATION_RESULTS", results=results, model_response_id=rec.get("response_id"))
    return {"certificates": certs, "fee_offer": o.key.sign(crypto.DOMAINS["offer"], fee),
            "model_response_id": rec.get("response_id")}


def _contract(o, body):
    c, _ = o.verify_from(body["contract"], crypto.DOMAINS["contract"], expect_owner=COORD)
    return c, sha256_hex(c)


def execute(o, body):
    req, _ = o.verify_from(body["envelope"], crypto.DOMAINS["request"], expect_owner=COORD)
    c, chash = _contract(o, body)
    act = req["action"]
    base = [("request_bound_to_contract", req.get("contract_hash") == chash), ("my_permit_valid", o.permit_ok(chash)),
            ("fresh", now() - req.get("issued_at", 0) < 300)]
    if not o.nonces.first_use(req.get("nonce")):
        base.append(("nonce_unused", False))
    if o.role == "factory" and act == "manufacture":
        chk = base + [("quantity_is_contract_quantity", req["qty"] == c["quantity"]),
                      ("design_is_contract_design", req["design"] == c["design_id"])]
        if o.admit("manufacture", chash, chk) != policy.T:
            return {"verdict": "F", "checks": chk}
        cmd = f"mfg-{chash[:16]}"
        st, res = o.native(cmd, "factory.manufacture", f"lot-{req['design']}", {"design": req["design"], "qty": req["qty"]})
        if st not in (200,) and not (res or {}).get("duplicate"):
            return {"verdict": "native_refused", "status": str(st), "error": (res or {}).get("error")}
        return {"verdict": "T", "receipt": o.receipt(chash, f"ob-{o.owner}-manufacture", "factory.manufacture", cmd, res)}
    if o.role == "engineer" and act == "certify_lot":
        mr = req.get("manufacture_receipt") or {}
        try:
            m, who = o.verify_from(mr, crypto.DOMAINS["receipt"])
            mok = who == next(p["owner_id"] for p in c["parties"] if p["role"] == "factory") and \
                m["contract_version_hash"] == chash and m["action"] == "factory.manufacture"
        except (crypto.VerifyError, StopIteration, KeyError):
            mok = False
        chk = base + [("factory_manufacture_receipt_valid", mok), ("design_is_contract_design", req["design"] == c["design_id"])]
        if o.admit("certify_lot", chash, chk) != policy.T:
            return {"verdict": "F", "checks": chk}
        cmd = f"lot-{chash[:16]}"
        st, res = o.native(cmd, "engineer.certify_lot", f"lot-{req['design']}", {"design": req["design"], "qty": c["quantity"]})
        if st != 200 and not (res or {}).get("duplicate"):
            return {"verdict": "native_refused", "status": str(st), "error": (res or {}).get("error")}
        return {"verdict": "T", "receipt": o.receipt(chash, f"certify-lot-{req['design']}", "engineer.certify_lot", cmd, res)}
    if o.role == "factory" and act == "ship":
        buyer = req["buyer"]
        units = next((ob.get("quantity") for p in c["parties"] if p["owner_id"] == buyer
                      for ob in p["obligations"] if ob["kind"] == "receive_units"), None)
        lot = req.get("lot_certificate") or {}
        try:
            lc, who = o.verify_from(lot, crypto.DOMAINS["receipt"])
            lok = who == next(p["owner_id"] for p in c["parties"] if p["role"] == "engineer") and \
                lc["contract_version_hash"] == chash and lc["obligation_id"] == f"certify-lot-{c['design_id']}"
        except (crypto.VerifyError, StopIteration, KeyError):
            lok = False
        chk = base + [("buyer_is_party", units is not None), ("qty_matches_buyer_obligation", req["qty"] == units),
                      ("engineer_lot_certificate_valid", lok)]
        if o.admit("ship", chash, chk) != policy.T:
            return {"verdict": "F", "checks": chk}
        cmd = f"ship-{buyer.split(':')[1]}-{chash[:16]}"
        st, res = o.native(cmd, "factory.ship", f"ship-{buyer.split(':')[1]}",
                           {"buyer": buyer.split(":")[1], "design": c["design_id"], "qty": req["qty"]})
        if st != 200 and not (res or {}).get("duplicate"):
            return {"verdict": "native_refused", "status": str(st), "error": (res or {}).get("error")}
        ship_receipt = o.receipt(chash, f"ship-{buyer}", "factory.ship", cmd, res)
        shipment = o.key.sign(crypto.DOMAINS["request"], {
            "request_id": new_id("shipment"), "contract_hash": chash, "buyer": buyer, "qty": req["qty"],
            "design": c["design_id"], "lot_certificate": lot, "ship_receipt": ship_receipt, "issued_at": now(),
            "nonce": os.urandom(12).hex()})
        try:
            br = post(o.endpoints[buyer] + "/deliver", {"envelope": shipment, "contract": body["contract"]})
        except Exception as exc:  # buyer unreachable: shipment stays reconciling, no false success
            br = {"verdict": "Z", "error": f"buyer unreachable: {type(exc).__name__}"}
        o.j.emit("SHIPMENT", buyer=buyer, buyer_response_verdict=br.get("verdict"))
        return {"verdict": "T" if br.get("verdict") == "T" else "RECONCILING", "ship_receipt": ship_receipt,
                "buyer_receipt": br.get("receipt"), "buyer_response": {k: v for k, v in br.items() if k != "receipt"}}
    if o.role == "buyer" and act == "pay":
        line = sum(p["amount_cents"] for p in c["payments"] if p["payer"] == o.owner)
        chk = base + [("amount_is_contract_line", req["amount_cents"] == line),
                      ("within_owner_cap", req["amount_cents"] <= o.private["max_payment_cents"]),
                      ("units_received_first", o.value("units.received") == o.private["need_units"])]
        if o.admit("pay", chash, chk) != policy.T:
            return {"verdict": "F", "checks": chk}
        cmd = f"pay-{chash[:16]}"
        st, res = o.native(cmd, "buyer.pay", "settlement", {"amount_cents": req["amount_cents"]})
        if st != 200 and not (res or {}).get("duplicate"):
            return {"verdict": "native_refused", "status": str(st), "error": (res or {}).get("error")}
        return {"verdict": "T", "receipt": o.receipt(chash, f"pay-{o.owner}", "buyer.pay", cmd, res)}
    return {"verdict": "F", "error": f"action {act} not available to role {o.role}"}


def buyer_deliver(o, body):
    s, who = o.verify_from(body["envelope"], crypto.DOMAINS["request"])
    c, chash = _contract(o, body)
    factory = next(p["owner_id"] for p in c["parties"] if p["role"] == "factory")
    engineer = next(p["owner_id"] for p in c["parties"] if p["role"] == "engineer")
    try:
        lc, lw = o.verify_from(s["lot_certificate"], crypto.DOMAINS["receipt"])
        lok = lw == engineer and lc["contract_version_hash"] == chash and lc["obligation_id"] == f"certify-lot-{c['design_id']}"
    except (crypto.VerifyError, KeyError):
        lok = False
    chk = [("sender_is_contract_factory", who == factory), ("shipment_bound_to_contract", s.get("contract_hash") == chash),
           ("my_permit_valid", o.permit_ok(chash)), ("addressed_to_me", s.get("buyer") == o.owner),
           ("qty_is_my_need", s.get("qty") == o.private["need_units"]), ("design_is_contract_design", s.get("design") == c["design_id"]),
           ("engineer_lot_certificate_valid", lok), ("nonce_unused", o.nonces.first_use(s.get("nonce")))]
    if o.admit("receive", chash, chk) != policy.T:
        return {"verdict": "F", "checks": chk}
    cmd = f"recv-{chash[:16]}"
    st, res = o.native(cmd, "buyer.receive", "receipt", {"qty": s["qty"], "design": s["design"]})
    if st != 200 and not (res or {}).get("duplicate"):
        return {"verdict": "native_refused", "status": str(st), "error": (res or {}).get("error")}
    return {"verdict": "T", "receipt": o.receipt(chash, f"receive-{o.owner}", "buyer.receive", cmd, res)}
