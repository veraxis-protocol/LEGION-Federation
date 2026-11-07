# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""WO-LMF-005 harness: run the preregistered 13 x 4 federated world cases.

Per world, three OS processes: the operator owner peer (hosts the pinned LEGION world), this requester
owner process, and an independent read-only Judge process. Usage:
  python tools/run_world_cases.py --cases FED_WORLD_CASES.json --core <LEGION checkout> --out <dir> [--only SYN-...]
"""
import argparse
import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from legion_federation import crypto  # noqa: E402
from legion_federation.canonical import new_id, now  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Client:
    def __init__(self, port, admin):
        self.base, self.admin = f"http://127.0.0.1:{port}", admin

    def post(self, path, body, admin=False, timeout=6):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **({"X-Token": self.admin} if admin else {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except (http.client.RemoteDisconnected, ConnectionResetError, TimeoutError, socket.timeout) as exc:
            return {"status": "lost", "transport_error": type(exc).__name__}
        except urllib.error.URLError as exc:
            return {"status": "lost", "transport_error": f"URLError:{exc.reason}"}


def run_world(w, core, out, py):
    world = w["world"]
    wdir = out / "RAW_EVENTS" / world
    (wdir / "operator").mkdir(parents=True, exist_ok=True)
    requester = crypto.KeyPair()
    intruder = crypto.KeyPair()      # registered owner, but not a contract party
    outsider = crypto.KeyPair()      # never registered (forged / runaway peer)
    port = free_port()
    admin, reader = secrets.token_hex(16), secrets.token_hex(16)
    cfg = {"owner": w["operator"], "requester": w["requester"], "requester_peer": "peer:" + w["requester"].split(":")[1],
           "core_root": str(core), "world_file": str(core / "tests/legion_struct/worlds" / f"{world}.world.json"),
           "port": port, "state_dir": str(wdir / "operator"), "allowed": w["allowed"], "public": w["public"],
           "private": w["private"], "trusted": {w["requester"]: requester.pub, "owner:intruder": intruder.pub}}
    (wdir / "operator_config.json").write_text(json.dumps(cfg, indent=1))
    env = dict(os.environ, LMF_ADMIN_TOKEN=admin, LMF_READER_TOKEN=reader)
    proc = subprocess.Popen([py, "-m", "legion_federation.world_peer", "--config", str(wdir / "operator_config.json")],
                            cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=open(wdir / "operator_stderr.txt", "w"),
                            text=True)
    ready = json.loads(proc.stdout.readline())
    assert ready["ready"]
    cl = Client(port, admin)
    for k in "PNRA":
        case_id = f"FED-{world}-{k}"
        run_case(cl, w, k, case_id, requester, intruder, outsider, wdir)
    # Independent read-only Judge process for this world (operator still running, reader token only).
    jenv = dict(os.environ, LMF_READER_TOKEN=reader)
    jr = subprocess.run([py, str(ROOT / "tools" / "judge_world_cases.py"), "--world", world, "--port", str(port),
                         "--raw", str(wdir), "--cases", str(out / "FED_WORLD_CASES.json"), "--core", str(core)],
                        cwd=str(ROOT), env=jenv, capture_output=True, text=True, timeout=300)
    (wdir / "judge_stdout.txt").write_text(jr.stdout + jr.stderr)
    cl.post("/admin/shutdown", {}, admin=True)
    proc.wait(timeout=20)
    return json.loads(jr.stdout.strip().splitlines()[-1]) if jr.returncode == 0 else {"world": world, "error": jr.stderr[-2000:]}


def run_case(cl, w, kind, case_id, requester, intruder, outsider, wdir):
    spec = w["cases"][kind]
    info = cl.post("/admin/new_case", {"case_id": case_id}, admin=True)
    log = open(wdir / f"{case_id}.requester.jsonl", "w", encoding="utf-8", newline="\n")
    sent_nonces = {}

    def rec(kind_, **d):
        log.write(json.dumps({"t": time.time(), "case_id": case_id, "kind": kind_, **d}, sort_keys=True) + "\n")
        log.flush()

    rec("CASE_START", contract_hash=info["contract_hash"], operator_key=info["operator_key"], spec=spec)

    def request(step, mut=None, key=None, cmd=None, nonce=None):
        cmd = cmd or f"{case_id}:{step.get('cmd')}"
        p = {"request_id": new_id("req"), "from_owner": w["requester"], "to_owner": w["operator"],
             "contract_hash": info["contract_hash"], "epoch": info["epoch"], "issued_at": now(),
             "expires_at": now() + 120, "nonce": nonce or secrets.token_hex(12), "commitment_ref": f"commit-{case_id}",
             "tool": step["tool"], "target": step["target"], "args": step["args"], "command_id": cmd,
             "purpose": "execution"}
        k_ = key or requester
        if mut == "forge":
            k_ = outsider
        elif mut == "impostor":
            k_ = intruder
        elif mut == "wrong_recipient":
            p["to_owner"] = "owner:someone-else"
        elif mut == "expired":
            p["issued_at"], p["expires_at"] = now() - 1000, now() - 500
        elif mut == "no_commitment":
            p["commitment_ref"] = None
        elif mut == "old_contract":
            p["contract_hash"] = info["old_contract_hash"]
        return k_.sign(crypto.DOMAINS["request"], p), p

    def do_write(step):
        if step.get("lost_reply"):
            cl.post("/admin/inject", {"case_id": case_id}, admin=True)
        env, p = request(step, mut=step.get("mut"))
        t0 = time.perf_counter()
        r = cl.post("/request", {"case_id": case_id, "envelope": env})
        rec("REQUEST", request_id=p["request_id"], command_id=p["command_id"], mut=step.get("mut"), tool=step["tool"],
            target=step["target"], expect=step["expect"], observed=r.get("status"), response=r,
            latency_ms=round((time.perf_counter() - t0) * 1000, 2))
        return r

    for step in spec["steps"]:
        op = step["op"]
        if op == "write":
            r = do_write(step)
            if step["expect"] in ("native_lost",) and r.get("status") == "lost":
                pass
        elif op == "fire":
            r = cl.post("/admin/fire", {"case_id": case_id, "event": step["event"]}, admin=True)
            rec("ENV_EVENT_REQUESTED", event=step["event"], response=r)
        elif op == "reconcile":
            env, p = request({"tool": "-", "target": "-", "args": {}, "cmd": step["cmd"]})
            r = cl.post("/reconcile", {"case_id": case_id, "envelope": env})
            rec("RECONCILE", command_id=p["command_id"], expect=step["expect"], observed=r.get("status"), response=r)
        elif op in ("disclose", "concurrent_disclose"):
            def one(field=step["field"], grant=step.get("grant", True), recipient=step.get("recipient")):
                k_ = outsider if recipient == "peer:outsider" else requester
                p = {"request_id": new_id("req"), "field": field, "purpose": "negotiation",
                     "grant": info["grant"] if grant else None, "issued_at": now(), "nonce": secrets.token_hex(12)}
                t0 = time.perf_counter()
                r = cl.post("/disclose", {"case_id": case_id, "envelope": k_.sign(crypto.DOMAINS["request"], p)})
                return r, (time.perf_counter() - t0) * 1000
            if op == "disclose":
                r, ms = one()
                rec("DISCLOSE", field=step["field"], expect=step["expect"], observed=r.get("verdict"), response=r,
                    latency_ms=round(ms, 2))
            else:
                res = []
                ths = [threading.Thread(target=lambda: res.append(one())) for _ in range(step["n"])]
                [t.start() for t in ths]
                [t.join() for t in ths]
                lat = sorted(x[1] for x in res)
                p95 = lat[int(0.95 * (len(lat) - 1))]
                rec("CONCURRENT_DISCLOSE", n=step["n"], verdicts=sorted({x[0].get("verdict") for x in res}),
                    p95_ms=round(p95, 2), max_p95_ms=step["max_p95_ms"], expect="T",
                    observed="T" if all(x[0].get("verdict") == "T" for x in res) and p95 <= step["max_p95_ms"] else "F")
        elif op == "parallel_writes":
            res = []
            ths = [threading.Thread(target=lambda s=s: res.append((s, do_write(s)))) for s in step["writes"]]
            [t.start() for t in ths]
            [t.join() for t in ths]
        elif op == "flood":
            res = []

            def f():
                env, p = request(step, key=outsider, cmd=f"{case_id}:flood-{secrets.token_hex(4)}")
                res.append(cl.post("/request", {"case_id": case_id, "envelope": env}).get("status"))
            ths = [threading.Thread(target=f) for _ in range(step["n"])]
            [t.start() for t in ths]
            [t.join() for t in ths]
            rec("FLOOD", n=step["n"], expect="refused", observed="refused" if set(res) == {"refused"} else ",".join(sorted(set(map(str, res)))))
        elif op == "bulk_query":
            r = cl.post("/bulk", {"case_id": case_id})
            rec("BULK_QUERY", expect=step["expect"], observed=r.get("verdict"), response=r)
        elif op == "claim_done":
            rec("AGENT_DONE_CLAIM", claim=step["claim"], expect=step["expect"], observed="claimed",
                note="requester self-report; must not count as completion")
    rec("CASE_END")
    log.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--core", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default=None)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cases = json.load(open(a.cases, encoding="utf-8"))
    (out / "FED_WORLD_CASES.json").write_text(json.dumps(cases, indent=1, sort_keys=True))
    results = []
    for w in cases["worlds"]:
        if a.only and w["world"] != a.only:
            continue
        t0 = time.time()
        r = run_world(w, Path(a.core), out, sys.executable)
        r["wall_s"] = round(time.time() - t0, 2)
        results.append(r)
        print(json.dumps({"world": w["world"], "summary": r.get("summary"), "error": r.get("error")}), flush=True)
    (out / "WORLD_RESULTS.json").write_text(json.dumps(results, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
