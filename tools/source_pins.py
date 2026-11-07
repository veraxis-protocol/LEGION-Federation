# SPDX-License-Identifier: Apache-2.0
"""Generate SOURCE_PINS.json from local read-only checkouts of the external (non-Apache) sources.

Usage: python tools/source_pins.py <LEGION checkout> <LEGION-Formal-Core checkout> <LEGION-Commerce checkout> <out>
Nothing is copied: only revisions and SHA-256 of files this overlay reads or calls at runtime.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from legion_federation.canonical import file_sha256  # noqa: E402


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


def pin(repo, url, files, expected=None, license_file="LICENSE"):
    repo = Path(repo)
    head = git(repo, "rev-parse", "HEAD")
    out = {"url": url, "revision": head, "expected_revision": expected,
           "revision_matches_expected": (expected is None or head == expected),
           "license_first_line": (repo / license_file).read_text(encoding="utf-8").splitlines()[0].strip("# ").strip(),
           "files": {}}
    for f in files:
        p = repo / f
        out["files"][f] = {"sha256": file_sha256(p), "git_blob": git(repo, "rev-parse", f"HEAD:{f}")} if p.exists() \
            else {"sha256": None, "status": "MISSING"}
    return out


def main(legion, formal, commerce, out):
    worlds = sorted(p.name for p in (Path(legion) / "tests/legion_struct/worlds").glob("SYN-*.world.json"))
    legion_files = (["LICENSE", "tests/legion_struct/worlds/INDEX.json", "tests/legion_struct/world_engine.py",
                     "tests/legion_struct/struct_controller.py", "tests/legion_struct/struct_plugin.py",
                     "tests/legion_struct/WORLD_DSL.md", "judge/components/struct_adapter.py",
                     "judge/components/judge_s1/legion_judge/core.py"]
                    + [f"tests/legion_struct/worlds/{w}" for w in worlds])
    pins = {
        "schema": "lmf.source-pins.v1",
        "generated_at": time.time(),
        "policy": "External sources are read or invoked at runtime from these pinned checkouts. No PolyForm "
                  "Noncommercial source is copied into this Apache-2.0 repository.",
        "sources": {
            "LEGION": pin(legion, "https://github.com/veraxis-protocol/LEGION", legion_files,
                          expected="d083c44af2526e38068e0220891cd0bb5fce52af"),
            "LEGION-Formal-Core": pin(formal, "https://github.com/veraxis-protocol/LEGION-Formal-Core",
                                      ["LICENSE", "PROOF_MANIFEST.json", "README.md"],
                                      expected="f5ea79ca438749e2e7282727a75fd891df0bd371"),
            "LEGION-Commerce": pin(commerce, "https://github.com/veraxis-protocol/LEGION-Commerce",
                                   ["commerce_adapter/gateway.py", "commerce_adapter/paypal.py",
                                    "commerce_adapter/readback.py", "commerce_adapter/approval.py",
                                    "commerce_bridge/__init__.py"], license_file="README.md"),
        },
        "notes": {
            "LEGION-Formal-Core": "tag v1.0.0 (annotated tag object 1fb85527a4f25a5930feccb75a8b6808d34d5797) peels "
                                  "to f5ea79c. Its README names the qualified LEGION runtime "
                                  "d9d38cd6fd9e93e002b0b5d5135377ce1d33d8c8 (branch formal-core-r2, not on the public "
                                  "LEGION main).",
            "LEGION-Commerce": "Authority branch claude/wo-com-authority-005 remote tip 228899ab5b27881a324123a371336177992b1bd4 "
                               "(unchanged since last inspection). The local checkout pinned here may be a later local "
                               "branch; see revision field.",
        },
        "worlds": worlds,
    }
    Path(out).write_text(json.dumps(pins, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: (v["revision"], v["revision_matches_expected"]) for k, v in pins["sources"].items()}))


if __name__ == "__main__":
    main(*sys.argv[1:5])
