# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 Veraxis. Independently authored; contains no LEGION Core source.
"""Federation negotiation coordinator (separate OS process).

The coordinator has its own key and NO owner authority: it can only carry signed messages, ask owners for
offers/qualification, assemble contract *versions* and collect each owner's own signed commitment. It
cannot sign for any owner, spend, or change any mission. A model-driven planner proposes the next contract
version when terms fail; every owner decides independently.

Contract state machine: DRAFT -> OFFERED -> PREPARED -> AUTHORIZED -> EXECUTING -> FULFILLED|FAILED|RECONCILING
(VERIFIED is set only by the independent Judge, never here). PREPARED is not settlement or atomic commit.
"""
import argparse
import json
import os
import sys
import time
import urllib.request

from . import crypto, nim, schemas
from .canonical import new_id, now, sha256_hex
from .journal import Journal

ME = "coordinator:hub"


def post(url, body, timeout=120):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def get(url, timeout=60):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


class Hub:
    def __init__(self, out, endpoints, env_hook=None):
        self.key = crypto.KeyPair()
        self.ep = endpoints
        self.env_hook = env_hook
        self.trace = Journal(os.path.join(out, "NEGOTIATION_TRACE.jsonl"), ME)
        self.versions = Journal(os.path.join(out, "CONTRACT_VERSIONS.jsonl"), ME)
        self.commits = Journal(os.path.join(out, "OWNER_COMMITMENTS.jsonl"), ME)
        self.permits = Journal(os.path.join(out, "ACTION_PERMITS.jsonl"), ME)
        self.receipts = Journal(os.path.join(out, "RECEIPTS.jsonl"), ME)
        self.models = Journal(os.path.join(out, "MODEL_DECISIONS.jsonl"), ME)
        self.model_calls = 0

    def req(self, **p):
        p.update(request_id=new_id("req"), issued_at=now(), nonce=os.urandom(12).hex())
        return self.key.sign(crypto.DOMAINS["request"], p)

    def state(self, chash, st, **kw):
        self.trace.emit("CONTRACT_STATE", contract_hash=chash, state=st, **kw)

    def planner(self, context):
        schema = {"type": "object", "additionalProperties": False, "required": ["design_id", "rationale"],
                  "properties": {"design_id": {"enum": sorted(context["options"]) + ["NONE"]},
                                 "rationale": {"type": "string", "maxLength": 400}}}
        msgs = [{"role": "system", "content": "You are a neutral federation negotiation planner. You hold no authority: "
                 "you only propose the next contract version; every company decides for itself. Each buyer needs exactly "
                 "its published units and will not pay more than its published cap. Only designs with a PASSING engineer "
                 "qualification certificate can be delivered. Reply only with JSON."},
                {"role": "user", "content": json.dumps(context, sort_keys=True)}]
        r = nim.chat(msgs, schema)
        self.model_calls += 0 if r.get("failed") else 1
        self.models.emit("MODEL_DECISION", task="choose next contract design", worker_id="hub/planner",
                         provider=r.get("provider"), model=r.get("model"), response_id=r.get("response_id"),
                         usage=r.get("usage"), latency_s=r.get("latency_s"), failed=bool(r.get("failed")),
                         decision=r.get("parsed"), context_sha256=sha256_hex(context), http_status=r.get("status"),
                         provider_errors=r.get("errors"))
        return r.get("parsed") or {"design_id": "NONE", "rationale": "planner unavailable"}, r.get("response_id")

    # ------------------------------------------------------------------ steps
    def discover(self, marketplace):
        m = get(marketplace + "/opportunities")
        self.trace.emit("DISCOVERY", proposals=len(m["proposals"]), oracle=m["oracle"], rejected=len(m["rejected"]))
        return m

    def quote(self, prop, coalition_id):
        f = prop["factory"]["owner_id"]
        r = post(self.ep[f] + "/quote", {"envelope": self.req(quantity=prop["quantity"], spec_hash=prop["spec_hash"],
                                                             coalition_id=coalition_id,
                                                             basis=[b["intent_id"] for b in prop["buyers"]])})
        offers = {}
        for env in r.get("offers", []):
            o = crypto.verify(env, crypto.DOMAINS["offer"])
            d = next(l for l in o["lines"] if l["item"] != "shipping")
            ship = next((l["amount_cents"] for l in o["lines"] if l["item"] == "shipping"), 0)
            offers[d["design_id"]] = {"amount_cents": d["amount_cents"], "shipping_cents": ship,
                                      "offer_version": o["offer_version"], "offer_id": o["offer_id"]}
        self.trace.emit("FACTORY_OFFERS", offers=offers, rationale=r.get("rationale"), model_response_id=r.get("model_response_id"))
        return offers

    def qualify(self, prop, coalition_id, designs):
        e = prop["engineer"]["owner_id"]
        r = post(self.ep[e] + "/qualify", {"envelope": self.req(designs=designs, spec_hash=prop["spec_hash"],
                                                               coalition_id=coalition_id)})
        certs = {c["design_id"]: c for c in r.get("certificates", [])}
        fee = None
        if r.get("fee_offer"):
            fee = crypto.verify(r["fee_offer"], crypto.DOMAINS["offer"])["lines"][0]["amount_cents"]
        self.trace.emit("QUALIFICATION", results={d: c["pass"] for d, c in certs.items()}, fee_cents=fee,
                        declined=r.get("declined", False), model_response_id=r.get("model_response_id"))
        return certs, fee

    def build(self, prop, version, prev, design, offer, fee, coalition_id):
        buyers = prop["buyers"]
        n = len(buyers)
        f, e = prop["factory"], prop["engineer"]
        to_f, to_e = (offer["amount_cents"] + offer["shipping_cents"]) // n, fee // n
        c = {"schema": "lmf.coalition-contract.v1", "contract_id": f"contract-{coalition_id}", "version": version,
             "prev_version_hash": prev, "mission_ids": [f"M-{b['owner_id'].split(':')[1].upper()}" for b in buyers] + ["M-F1", "M-E1"],
             "parties": [{"owner_id": b["owner_id"], "peer_id": b["peer_id"], "role": "buyer",
                          "obligations": [{"obligation_id": f"ob-{b['owner_id'].split(':')[1]}-pay", "kind": "pay", "amount_cents": to_f + to_e},
                                          {"obligation_id": f"ob-{b['owner_id'].split(':')[1]}-recv", "kind": "receive_units",
                                           "quantity": b["quantity"], "counterparty": f["owner_id"]}]} for b in buyers]
                        + [{"owner_id": f["owner_id"], "peer_id": f["peer_id"], "role": "factory",
                            "obligations": [{"obligation_id": "ob-f-mfg", "kind": "manufacture", "quantity": prop["quantity"]},
                                            {"obligation_id": "ob-f-ship", "kind": "ship", "quantity": prop["quantity"]}]},
                           {"owner_id": e["owner_id"], "peer_id": e["peer_id"], "role": "engineer",
                            "obligations": [{"obligation_id": "ob-e-qual", "kind": "qualify", "quantity": prop["quantity"]}]}],
             "payments": [x for b in buyers for x in (
                 {"payer": b["owner_id"], "payee": f["owner_id"], "amount_cents": to_f, "purpose": f"units+shipping {design}"},
                 {"payer": b["owner_id"], "payee": e["owner_id"], "amount_cents": to_e, "purpose": "qualification share"})],
             "quantity": prop["quantity"], "spec_hash": prop["spec_hash"], "design_id": design,
             "qualification": {"engineer": e["owner_id"], "fixture": "QF-7"},
             "deadline": now() + 3600, "partial_failure_policy": "No unit ships before the engineer certifies the lot; no buyer "
             "pays before receiving its 20 units; on any failure, holds remain and the contract goes to RECONCILING.",
             "currency": "USD", "created_at": now(),
             "price_basis": {"factory_cents": offer["amount_cents"], "shipping_cents": offer["shipping_cents"],
                             "qualification_cents": fee, "total_cents": offer["amount_cents"] + offer["shipping_cents"] + fee,
                             "per_buyer_cents": to_f + to_e, "factory_offer_id": offer["offer_id"]}}
        schemas.validate("CoalitionContract", c)
        env = self.key.sign(crypto.DOMAINS["contract"], c)
        chash = sha256_hex(c)
        self.versions.emit("CONTRACT_VERSION", version=version, contract_hash=chash, prev=prev, design=design,
                           price_basis=c["price_basis"], contract=c)
        self.state(chash, "DRAFT", version=version)
        return env, chash

    def offer_to_all(self, env, chash, parties, annex):
        self.state(chash, "OFFERED", version=env["payload"]["version"])
        out = {}
        for o in parties:
            r = post(self.ep[o] + "/propose", {"contract": env, "annex": annex})
            cm = r.get("commitment")
            out[o] = cm
            self.commits.emit("OWNER_COMMITMENT", owner=o, contract_hash=chash, decision=(cm or {}).get("payload", {}).get("decision"),
                              policy_verdict=r.get("policy_verdict"), agent_decision=r.get("agent_decision"),
                              rationale=(cm or {}).get("payload", {}).get("rationale"), commitment=cm)
        return out

    def run(self, marketplace=None, proposal=None, arm="A2"):
        coalition_id = new_id("coal")
        if proposal is None:
            m = self.discover(marketplace)
            if not m["proposals"]:
                self.trace.emit("NO_COALITION", reason="marketplace found no proposal")
                return {"outcome": "NO_DEAL"}
            proposal = m["proposals"][0]
        prop = proposal
        parties = [b["owner_id"] for b in prop["buyers"]] + [prop["factory"]["owner_id"], prop["engineer"]["owner_id"]]
        self.trace.emit("COALITION_PROPOSAL", arm=arm, proposal=prop, coalition_id=coalition_id)
        offers = self.quote(prop, coalition_id)
        certs, fee = self.qualify(prop, coalition_id, sorted(offers))
        prev, version, tried, final = None, 0, [], None
        cap = min(b["max_payment_cents"] or 0 for b in prop["buyers"])
        shocked = False
        for rnd in range(6):
            options = {d: {"factory_cents": o["amount_cents"], "shipping_cents": o["shipping_cents"],
                           "qualification_cents": fee, "per_buyer_cents": (o["amount_cents"] + o["shipping_cents"] + (fee or 0)) // len(prop["buyers"]),
                           "engineer_certificate": ("PASS" if certs.get(d, {}).get("pass") else
                                                    "FAIL" if d in certs else "NOT_TESTED")} for d, o in offers.items()}
            ctx = {"round": rnd, "options": options, "already_rejected": tried,
                   "buyers": [{"published_units": b["quantity"], "published_cap_cents": b["max_payment_cents"]} for b in prop["buyers"]]}
            pick, rid = self.planner(ctx)
            d = pick.get("design_id")
            self.trace.emit("PLANNER_CHOICE", round=rnd, design=d, rationale=pick.get("rationale"), model_response_id=rid,
                            options=options)
            if rnd == 0 and d == "NONE":
                break
            if d not in offers or d in [t["design"] for t in tried]:
                # planner gave nothing new: fall back to remaining options in order, still owner-decided
                rest = [x for x in offers if x not in [t["design"] for t in tried]]
                if not rest:
                    break
                d = rest[0]
                self.trace.emit("PLANNER_FALLBACK", design=d)
            if not certs.get(d, {}).get("pass"):
                tried.append({"design": d, "reason": f"incompatible engineering option: engineer fixture QF-7 result "
                                                    f"{options[d]['engineer_certificate']} (world readback)"})
                self.trace.emit("OPTION_REJECTED", design=d, reason=tried[-1]["reason"])
                continue
            version += 1
            env, chash = self.build(prop, version, prev, d, offers[d], fee, coalition_id)
            annex = {"qualification": {"engineer": prop["engineer"]["owner_id"], "design_id": d,
                                       "certificate": certs[d]["certificate"]},
                     "note": prop.get("note", "")}
            commits = self.offer_to_all(env, chash, parties, annex)
            accepted = [o for o, cm in commits.items() if cm and cm["payload"]["decision"] == "ACCEPT"]
            if not shocked and self.env_hook:
                shocked = True
                hook = post(self.env_hook, {"stage": "first_version_offered", "contract_hash": chash})
                self.trace.emit("ENVIRONMENT_EVENT_OBSERVED", hook=hook)
                if hook.get("shock_fired"):
                    # previously quoted prices may be stale: re-quote and re-qualify new options
                    statuses = {o: post(self.ep[o] + "/status", {"contract_hash": chash})["status"] for o in parties}
                    inactive = [o for o, s in statuses.items() if not s["payload"]["active"]]
                    self.state(chash, "FAILED", version=version, reason="supplier price shock invalidated commitments",
                               inactive=inactive)
                    tried.append({"design": d, "version": version, "reason": "invalidated by supplier price shock"})
                    prev = chash
                    offers = self.quote(prop, coalition_id)
                    new = [x for x in offers if x not in certs]
                    if new:
                        c2, _ = self.qualify(prop, coalition_id, new)
                        certs.update(c2)
                    # the incumbent design at its NEW price must be offered to owners again (they decide)
                    if d in offers:
                        version += 1
                        env2, ch2 = self.build(prop, version, prev, d, offers[d], fee, coalition_id)
                        commits2 = self.offer_to_all(env2, ch2, parties, dict(annex))
                        acc2 = [o for o, cm in commits2.items() if cm and cm["payload"]["decision"] == "ACCEPT"]
                        if len(acc2) == len(parties):
                            final = (env2, ch2, commits2)
                            break
                        self.state(ch2, "FAILED", version=version, reason="owners rejected repriced terms",
                                   rejected_by=sorted(set(parties) - set(acc2)))
                        tried.append({"design": d, "version": version, "reason": "owners rejected repriced terms: "
                                      + ",".join(sorted(set(parties) - set(acc2)))})
                        prev = ch2
                    continue
            if len(accepted) == len(parties):
                final = (env, chash, commits)
                break
            self.state(chash, "FAILED", version=version, rejected_by=sorted(set(parties) - set(accepted)))
            tried.append({"design": d, "version": version, "reason": "rejected by " + ",".join(sorted(set(parties) - set(accepted)))})
            prev = chash
        if not final:
            self.trace.emit("NO_DEAL", tried=tried)
            return {"outcome": "NO_DEAL", "tried": tried, "model_calls": self.model_calls}
        env, chash, commits = final
        self.state(chash, "PREPARED", version=env["payload"]["version"])
        return self.authorize_and_execute(env, chash, commits, prop, parties)

    def authorize_and_execute(self, env, chash, commits, prop, parties):
        c = env["payload"]
        statuses = [post(self.ep[o] + "/status", {"contract_hash": chash})["status"] for o in parties]
        cms = list(commits.values())
        permits = {}
        for o in parties:
            r = post(self.ep[o] + "/authorize", {"contract": env, "commitments": cms, "statuses": statuses})
            permits[o] = r.get("permit")
            self.permits.emit("OWNER_PERMIT", owner=o, contract_hash=chash, verdict=r.get("verdict"), permit=r.get("permit"),
                              missing=r.get("missing"), inactive=r.get("inactive"))
        if not all(permits.values()):
            self.state(chash, "FAILED", reason="authorization incomplete",
                       missing=[o for o, p in permits.items() if not p])
            return {"outcome": "AUTH_FAILED", "contract_hash": chash}
        self.state(chash, "AUTHORIZED")
        self.state(chash, "EXECUTING")
        f, e = prop["factory"]["owner_id"], prop["engineer"]["owner_id"]
        rec = {}

        def ex(owner, **kw):
            r = post(self.ep[owner] + "/execute", {"envelope": self.req(contract_hash=chash, **kw), "contract": env})
            self.receipts.emit("EXECUTION", owner=owner, action=kw.get("action"), target=kw.get("buyer"),
                               verdict=r.get("verdict"), response=r)
            return r

        m = ex(f, action="manufacture", design=c["design_id"], qty=c["quantity"])
        if m.get("verdict") != "T":
            self.state(chash, "RECONCILING", reason="manufacture refused", detail=m)
            return {"outcome": "EXEC_FAILED", "contract_hash": chash, "step": "manufacture"}
        lot = ex(e, action="certify_lot", design=c["design_id"], manufacture_receipt=m["receipt"])
        if lot.get("verdict") != "T":
            self.state(chash, "RECONCILING", reason="lot certification refused", detail=lot)
            return {"outcome": "EXEC_FAILED", "contract_hash": chash, "step": "certify_lot"}
        ok = True
        for b in prop["buyers"]:
            s = ex(f, action="ship", buyer=b["owner_id"], qty=b["quantity"], lot_certificate=lot["receipt"])
            ok = ok and s.get("verdict") == "T"
        for b in prop["buyers"]:
            amt = sum(p["amount_cents"] for p in c["payments"] if p["payer"] == b["owner_id"])
            pr = ex(b["owner_id"], action="pay", amount_cents=amt)
            ok = ok and pr.get("verdict") == "T"
        self.state(chash, "FULFILLED" if ok else "RECONCILING")
        return {"outcome": "FULFILLED" if ok else "RECONCILING", "contract_hash": chash, "version": c["version"],
                "design": c["design_id"], "per_buyer_cents": c["price_basis"]["per_buyer_cents"],
                "total_cents": c["price_basis"]["total_cents"], "model_calls": self.model_calls}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--endpoints", required=True)
    ap.add_argument("--marketplace", default=None)
    ap.add_argument("--proposal", default=None, help="A1: pre-known counterpart proposal JSON file (no discovery)")
    ap.add_argument("--env-hook", default=None)
    ap.add_argument("--arm", default="A2")
    a = ap.parse_args()
    hub = Hub(a.out, json.load(open(a.endpoints)), a.env_hook)
    print(json.dumps({"ready": True, "pub": hub.key.pub, "pid": os.getpid()}), flush=True)
    sys.stdin.readline()  # wait until the environment registered our public key with every owner
    prop = json.load(open(a.proposal)) if a.proposal else None
    res = hub.run(marketplace=a.marketplace, proposal=prop, arm=a.arm)
    res["hub_model_calls"] = hub.model_calls
    with open(os.path.join(a.out, "HUB_RESULT.json"), "w") as fh:
        json.dump(res, fh, indent=1, sort_keys=True)
    print(json.dumps(res), flush=True)


if __name__ == "__main__":
    main()
