# SPDX-License-Identifier: Apache-2.0
"""Independent, read-only Judge for the federated world cases (separate OS process).

It never writes to the world. Inputs: the preregistered case file, the operator's read-only reader
endpoint (state + effect ledger), the operator's own hash-chained logs and the requester's raw log.
Goal predicates are evaluated with the pinned LEGION reference Judge's ``predicate`` (imported at run
time from the unmodified Core checkout). Prints one JSON line per world on stdout.
"""
import argparse
import copy
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from legion_federation import crypto  # noqa: E402
from legion_federation.canonical import canonical, sha256_hex  # noqa: E402
from legion_federation.journal import verify_chain  # noqa: E402

OK_FOR = {"applied": {"applied"}, "refused": {"refused"}, "duplicate": {"duplicate"}, "lost": {"lost"},
          "native_refused": {"native_refused"}, "native_unavailable": {"native_unavailable"},
          "native_lost": {"lost"}, "found": {"found"}, "T": {"T"}, "F": {"F"}, "judge_rejects": {"claimed"}}


def get(port, path, token):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"X-Token": token})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def jl(path):
    return [json.loads(x) for x in open(path, encoding="utf-8")] if os.path.exists(path) else []


def judge_case(case_id, kind, spec, state, effects, req_log, adm, disc, op_key, private_paths, predicate,
               at_path, tamper=False):
    checks = []

    def add(name, ok, **kw):
        checks.append(dict({"check": name, "pass": bool(ok)}, **kw))

    # J1 goals on the independent readback
    for g in spec["goals"]:
        add("J1_goal", predicate(state, g), predicate=g)
    # J2 exact effect counts (no double effect, no out-of-contract effect)
    counts = {}
    for e in effects:
        counts[f"{e['tool']}|{e['target']}"] = counts.get(f"{e['tool']}|{e['target']}", 0) + 1
    exp = spec["effects"]
    for key, n in exp.items():
        add("J2_effect_count", counts.get(key, 0) == n, key=key, expected=n, observed=counts.get(key, 0))
    unexpected = {k: v for k, v in counts.items() if k not in exp}
    add("J2_no_unexpected_effects", not unexpected, unexpected=unexpected)
    # J3 every step observed as preregistered, and requester observation agrees with operator admission log
    adm_by_req = {}
    for r in adm:
        if r["data"].get("case_id") == case_id:
            adm_by_req.setdefault(r["data"]["request_id"], []).append(r)
    steps = [r for r in req_log if r["kind"] in ("REQUEST", "RECONCILE", "DISCLOSE", "CONCURRENT_DISCLOSE", "FLOOD",
                                                  "BULK_QUERY", "AGENT_DONE_CLAIM")]
    for s in steps:
        expect = s["expect"] if isinstance(s["expect"], list) else [s["expect"]]
        allowed = set().union(*[OK_FOR.get(x, {x}) for x in expect])
        add("J3_step_outcome", s["observed"] in allowed, step=s["kind"], expect=expect, observed=s["observed"])
        if s["kind"] == "REQUEST" and s["observed"] in ("applied", "refused", "duplicate", "native_refused"):
            recs = adm_by_req.get(s["request_id"], [])
            verdicts = [r["data"]["verdict"] for r in recs if r["kind"] == "ADMISSION"]
            consistent = bool(verdicts) and ((verdicts[0] == "T") == (s["observed"] != "refused"))
            add("J3_operator_log_agrees", consistent, request_id=s["request_id"], operator_verdicts=verdicts)
    # J4 zero private disclosure: operator never released a private field, and no private value appears in
    # anything the requester received
    leaks = [d for d in disc if d["data"].get("case_id") == case_id and d["data"].get("private")
             and d["data"].get("verdict") == "T"]
    add("J4_no_private_release_logged", not leaks, leaks=len(leaks))
    blob = canonical([s.get("response") for s in req_log]).decode()
    hits = []
    for name, path in private_paths.items():
        v = at_path(state, path)
        if isinstance(v, (dict, list)) and v:
            sv = canonical(v).decode()
            if sv in blob:
                hits.append(name)
    add("J4_no_private_value_in_requester_inbox", not hits, hits=hits)
    # J5 receipts: signed by the operator key, bound to an effect actually in the ledger
    ledger = {e["effect_id"]: e for e in effects}
    for s in req_log:
        rc = (s.get("response") or {}).get("receipt")
        if not rc:
            continue
        if tamper:
            rc = copy.deepcopy(rc)
            rc["payload"]["effect_id"] = "eff-forged000000"
        try:
            p = crypto.verify(rc, crypto.DOMAINS["receipt"], trusted={op_key["key_id"]: op_key["pub"]})
            e = ledger.get(p["effect_id"])
            ok = e is not None and p["readback_sha256"] == sha256_hex(
                {k: e[k] for k in ("effect_id", "command_id", "tool", "target", "args")})
        except crypto.VerifyError:
            ok = False
        add("J5_receipt_bound_to_readback", ok, command_id=s.get("command_id"))
    # J6 a self-reported DONE never counts: if claimed, the goal it asserts must be independently true
    for s in req_log:
        if s["kind"] == "AGENT_DONE_CLAIM":
            add("J6_false_done_rejected", not all(predicate(state, g) for g in spec.get("claim_goals", [
                {"path": "services.payment.reachable", "op": "eq", "value": True}])), claim=s["claim"])
    verdict = "PASS" if all(c["pass"] for c in checks) else "FAIL"
    return {"case_id": case_id, "kind": kind, "verdict": verdict, "checks": checks}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--core", required=True)
    a = ap.parse_args()
    sys.path.insert(0, os.path.join(a.core, "judge", "components", "judge_s1"))
    from legion_judge.core import at_path, predicate  # pinned LEGION reference Judge (PolyForm NC, unmodified)

    token = os.environ["LMF_READER_TOKEN"]
    cases = json.load(open(a.cases, encoding="utf-8"))
    w = next(x for x in cases["worlds"] if x["world"] == a.world)
    raw = Path(a.raw)
    op_dir = raw / "operator"
    chains = {n: verify_chain(op_dir / n) for n in ("PEER_EVENTS.jsonl", "POLICY_DECISIONS.jsonl", "DISCLOSURE_DECISIONS.jsonl")
              if (op_dir / n).exists()}
    adm, disc = jl(op_dir / "POLICY_DECISIONS.jsonl"), jl(op_dir / "DISCLOSURE_DECISIONS.jsonl")
    results, mutants = [], []
    for k in "PNRA":
        cid = f"FED-{a.world}-{k}"
        req_log = jl(raw / f"{cid}.requester.jsonl")
        op_key = req_log[0]["operator_key"]
        state = get(a.port, f"/reader/state?case_id={cid}", token)["state"]
        effects = get(a.port, f"/reader/effects?case_id={cid}", token)["effects"]
        r = judge_case(cid, k, w["cases"][k], state, effects, req_log, adm, disc, op_key, w["private"], predicate, at_path)
        r["chains_valid"] = all(v[0] for v in chains.values())
        if not r["chains_valid"]:
            r["verdict"] = "FAIL"
        r["readback_sha256"] = sha256_hex({"state": state, "effects": effects})
        results.append(r)
        if k == "P":  # manual tamper mutant: one forged receipt must flip the verdict
            m = judge_case(cid, k, w["cases"][k], state, effects, req_log, adm, disc, op_key, w["private"], predicate,
                           at_path, tamper=True)
            mutants.append({"case_id": cid, "mutant": "receipt.effect_id forged", "mutant_verdict": m["verdict"],
                            "detected": m["verdict"] == "FAIL"})
    out = {"world": a.world, "judge_pid": os.getpid(), "chains": {k: list(v) for k, v in chains.items()},
           "results": results, "tamper_mutants": mutants,
           "summary": {r["kind"]: r["verdict"] for r in results}}
    (raw / "JUDGE_WORLD.json").write_text(json.dumps(out, indent=1, sort_keys=True))
    print(json.dumps({"world": a.world, "summary": out["summary"],
                      "mutants_detected": all(m["detected"] for m in mutants)}))


if __name__ == "__main__":
    main()
