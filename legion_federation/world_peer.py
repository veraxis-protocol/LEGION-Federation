# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 Veraxis. Independently authored; contains no LEGION Core source.
"""Operator-owner peer process that hosts ONE pinned LEGION world as its native system.

The world engine is imported at run time from the pinned, unmodified LEGION checkout
(``$LEGION_CORE/tests/legion_struct/world_engine.py``); nothing from it is copied here.
A requester owner (another OS process) can only act through signed peer requests that pass
Federation-edge admission (policy.admit_request) AND the Core world's native preconditions.

Run:  python -m legion_federation.world_peer --config cfg.json
Tokens (admin/reader) arrive via environment variables, never on the command line.
"""
import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import crypto, policy
from .canonical import canonical, new_id, now, sha256_hex
from .journal import Journal


def load_world_class(core_root):
    sys.path.insert(0, os.path.join(core_root, "tests", "legion_struct"))
    import world_engine  # noqa: E402  (pinned external LEGION Core, PolyForm NC, unmodified)
    return world_engine.World


class Case:
    def __init__(self, World, spec, contract, epoch):
        self.world = World(spec)
        self.contract = contract
        self.nonces = policy.NonceStore()
        self.drop_next = False
        self.epochs = dict(epoch)
        self.lock = threading.Lock()


class Peer:
    def __init__(self, cfg):
        self.cfg = cfg
        self.owner = cfg["owner"]
        self.key = crypto.KeyPair()
        self.World = load_world_class(cfg["core_root"])
        self.spec = json.load(open(cfg["world_file"], encoding="utf-8"))
        self.world_sha = sha256_hex(open(cfg["world_file"], "rb").read())
        self.registry = {"keys": {}, "owner_of": {}}
        for owner, pub in cfg["trusted"].items():
            kid = crypto.key_id(pub)
            self.registry["keys"][kid] = pub
            self.registry["owner_of"][kid] = owner
        self.cases = {}
        self.journal = Journal(os.path.join(cfg["state_dir"], "PEER_EVENTS.jsonl"), self.owner)
        self.policy_log = Journal(os.path.join(cfg["state_dir"], "POLICY_DECISIONS.jsonl"), self.owner)
        self.disclosure_log = Journal(os.path.join(cfg["state_dir"], "DISCLOSURE_DECISIONS.jsonl"), self.owner)
        self.public_paths = cfg["public"]
        self.private_paths = cfg["private"]
        self.dpolicy = policy.DisclosurePolicy(self.owner, public=[], grantable=list(self.public_paths),
                                               owner_key_id=self.key.key_id)

    # -- contract per case ------------------------------------------------------------
    def contract_terms(self, case_id, version=1):
        return {"world_id": self.spec.get("world_id"), "world_sha256": self.world_sha, "case_id": case_id,
                "operator": self.owner, "requester": self.cfg["requester"], "allowed": self.cfg["allowed"],
                "version": version}

    def new_case(self, case_id):
        terms = self.contract_terms(case_id)
        contract = {"hash": sha256_hex(terms), "allowed": self.cfg["allowed"], "terms": terms,
                    "parties": [self.cfg["requester"]],
                    "old_hash": sha256_hex(dict(terms, version=0, allowed=[]))}
        self.cases[case_id] = Case(self.World, self.spec, contract, {self.cfg["requester"]: 1})
        grant = self.key.sign(crypto.DOMAINS["grant"], {
            "schema": "lmf.disclosure-grant.v1", "grant_id": new_id("grant"), "grantor_owner_id": self.owner,
            "recipient": self.cfg["requester_peer"], "purpose": "negotiation", "fields": sorted(self.public_paths),
            "epoch": self.dpolicy.epoch, "issued_at": now(), "expires_at": now() + 900,
            "nonce": os.urandom(8).hex(), "policy_hash": self.dpolicy.policy_hash()})
        self.journal.emit("CASE_OPENED", case_id=case_id, contract_hash=contract["hash"], world_sha256=self.world_sha)
        return {"contract_hash": contract["hash"], "old_contract_hash": contract["old_hash"], "epoch": 1,
                "grant": grant, "operator_key": {"key_id": self.key.key_id, "pub": self.key.pub}}

    # -- requests ---------------------------------------------------------------------
    def handle_request(self, case_id, env):
        c = self.cases[case_id]
        with c.lock:
            verdict, reasons, p = policy.admit_request(env, self.owner, self.registry, c.epochs, c.contract, c.nonces)
            rid = (p or (env.get("payload") if isinstance(env.get("payload"), dict) else None) or {}).get("request_id")
            if verdict == policy.T:
                prior = [e for e in c.world.effect_ledger
                         if e["tool"] == p["tool"] and e["target"] == p["target"] and e["command_id"] != p["command_id"]]
                if prior:
                    verdict, reasons = policy.F, ["contracted one-shot obligation already effected by another command"]
            self.policy_log.emit("ADMISSION", case_id=case_id, request_id=rid, verdict=verdict, reasons=reasons,
                                 tool=(p or {}).get("tool"), target=(p or {}).get("target"),
                                 command_id=(p or {}).get("command_id"), layer="federation-edge(tested, not Lean-proved)")
            if verdict != policy.T:
                return {"status": "refused", "verdict": verdict, "reasons": reasons, "request_id": rid}, False
            status, result = c.world.call_write(p["command_id"], p["tool"], p["target"], p["args"])
            dup = isinstance(result, dict) and result.get("duplicate")
            self.policy_log.emit("CORE_NATIVE", case_id=case_id, request_id=rid, native_status=str(status),
                                 duplicate=bool(dup), command_id=p["command_id"],
                                 layer="LEGION world_engine native preconditions (pinned Core)")
            if dup:
                return {"status": "duplicate", "request_id": rid, "effect_id": result.get("effect_id")}, False
            if status == 409:
                return {"status": "native_refused", "request_id": rid, "error": result.get("error")}, False
            if status not in (200, "LOST_REPLY"):
                return {"status": "native_unavailable", "request_id": rid, "http": status,
                        "error": result.get("error")}, False
            entry = next(e for e in c.world.effect_ledger if e["command_id"] == p["command_id"])
            receipt = self.key.sign(crypto.DOMAINS["receipt"], {
                "schema": "lmf.evidence-receipt.v1", "receipt_id": new_id("rcpt"), "issuer_owner_id": self.owner,
                "contract_version_hash": c.contract["hash"], "obligation_id": f"ob-{p['tool']}-{p['target']}",
                "action": p["tool"], "command_id": p["command_id"], "effect_id": entry["effect_id"],
                "readback_sha256": sha256_hex({k: entry[k] for k in ("effect_id", "command_id", "tool", "target", "args")}),
                "mode": "SIMULATED", "issued_at": now()})
            self.journal.emit("NATIVE_EFFECT", case_id=case_id, request_id=rid, effect_id=entry["effect_id"],
                              command_id=p["command_id"], tool=p["tool"], target=p["target"], receipt=receipt)
            drop = status == "LOST_REPLY" or c.drop_next
            c.drop_next = False
            return {"status": "applied", "request_id": rid, "effect_id": entry["effect_id"], "receipt": receipt}, drop

    def handle_reconcile(self, case_id, env):
        c = self.cases[case_id]
        try:
            p = crypto.verify(env, crypto.DOMAINS["request"], trusted=self.registry["keys"])
        except crypto.VerifyError as exc:
            return {"status": "refused", "reasons": [str(exc)]}
        if self.registry["owner_of"].get(env["signer"]["key_id"]) not in c.contract["parties"]:
            return {"status": "refused", "reasons": ["not a party"]}
        e = c.world.reconcile(p["command_id"])
        self.journal.emit("RECONCILE", case_id=case_id, command_id=p["command_id"], found=e is not None)
        return {"status": "found" if e else "not_found", "effect_id": (e or {}).get("effect_id")}

    def handle_disclose(self, case_id, env):
        c = self.cases[case_id]
        try:
            p = crypto.verify(env, crypto.DOMAINS["request"])  # identity checked against registry below
        except crypto.VerifyError as exc:
            return {"verdict": "F", "reasons": [str(exc)]}
        kid = env["signer"]["key_id"]
        recipient_owner = self.registry["owner_of"].get(kid)
        recipient = self.cfg["requester_peer"] if recipient_owner == self.cfg["requester"] else "peer:unregistered"
        field = p.get("field")
        if field in self.private_paths:
            verdict, why = policy.F, "private field (never disclosed)"
        else:
            verdict, why = self.dpolicy.decide(field, recipient, p.get("purpose", "negotiation"), p.get("grant"),
                                               trusted={self.key.key_id: self.key.pub})
        value = None
        if verdict == policy.T:
            value = c.world.value_at(c.world.state, self.public_paths[field])
        self.disclosure_log.emit("DISCLOSURE_DECISION", case_id=case_id, field=field, recipient=recipient,
                                 purpose=p.get("purpose"), verdict=verdict, reason=why,
                                 released_sha256=sha256_hex(canonical(value)) if verdict == policy.T else None,
                                 private=field in self.private_paths)
        return {"verdict": verdict, "reason": why, "field": field, "value": value}


def make_handler(peer, admin_token, reader_token):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            body = json.dumps(obj, sort_keys=True).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth(self, token):
            return self.headers.get("X-Token") == token

        def do_GET(self):
            path, _, q = self.path.partition("?")
            args = dict(x.split("=", 1) for x in q.split("&") if "=" in x)
            if path == "/descriptor":
                return self._send(200, {"owner": peer.owner, "key_id": peer.key.key_id, "pub": peer.key.pub,
                                        "world_id": peer.spec.get("world_id"), "world_sha256": peer.world_sha})
            if path.startswith("/reader/"):
                if not self._auth(reader_token):
                    return self._send(403, {"error": "reader token required"})
                c = peer.cases.get(args.get("case_id"))
                if c is None:
                    return self._send(404, {"error": "unknown case"})
                if path == "/reader/state":
                    return self._send(200, {"state": c.world.get_state() if hasattr(c.world, "get_state") else c.world.state})
                if path == "/reader/effects":
                    return self._send(200, {"effects": c.world.effect_ledger})
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n) or b"{}")
            cid = body.get("case_id")
            if self.path.startswith("/admin/"):
                if not self._auth(admin_token):
                    return self._send(403, {"error": "admin token required"})
                if self.path == "/admin/new_case":
                    return self._send(200, peer.new_case(cid))
                if self.path == "/admin/fire":
                    ev = peer.cases[cid].world.fire(body["event"])
                    peer.journal.emit("ENV_EVENT", case_id=cid, event=body["event"], fired=ev is not None)
                    return self._send(200, {"fired": ev is not None})
                if self.path == "/admin/inject":
                    peer.cases[cid].drop_next = True
                    peer.journal.emit("FAULT_INJECTED", case_id=cid, fault="drop_next_reply")
                    return self._send(200, {"ok": True})
                if self.path == "/admin/shutdown":
                    self._send(200, {"ok": True})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
            if cid not in peer.cases:
                return self._send(404, {"error": "unknown case"})
            if self.path == "/request":
                resp, drop = peer.handle_request(cid, body.get("envelope") or {})
                if drop:
                    self.close_connection = True
                    return  # reply withheld: requester observes a lost reply / timeout
                return self._send(200, resp)
            if self.path == "/reconcile":
                return self._send(200, peer.handle_reconcile(cid, body.get("envelope") or {}))
            if self.path == "/disclose":
                return self._send(200, peer.handle_disclose(cid, body.get("envelope") or {}))
            if self.path == "/bulk":
                peer.disclosure_log.emit("DISCLOSURE_DECISION", case_id=cid, field="*", recipient="bulk",
                                         purpose="bulk", verdict="F", reason="bulk query disallowed", released_sha256=None,
                                         private=True)
                return self._send(200, {"verdict": "F", "reason": "bulk query disallowed"})
            return self._send(404, {"error": "not found"})
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    a = ap.parse_args()
    cfg = json.load(open(a.config, encoding="utf-8"))
    peer = Peer(cfg)
    srv = ThreadingHTTPServer(("127.0.0.1", cfg["port"]), make_handler(peer, os.environ["LMF_ADMIN_TOKEN"],
                                                                      os.environ["LMF_READER_TOKEN"]))
    peer.journal.emit("PEER_STARTED", pid=os.getpid(), port=cfg["port"], world=cfg["world_file"],
                      key_id=peer.key.key_id)
    print(json.dumps({"ready": True, "port": cfg["port"], "key_id": peer.key.key_id}), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
