# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 Veraxis. Independently authored.
"""Minimal NVIDIA NIM chat client. The key is read per call from a local file named by LMF_NIM_KEY_FILE
and is never logged, returned or written anywhere."""
import json
import os
import time
import urllib.error
import urllib.request

ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
MODEL = os.environ.get("LMF_NIM_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")


def chat(messages, schema, temperature=0.3, max_tokens=900, timeout=90, retries=2):
    body = {"model": MODEL, "messages": messages, "max_tokens": max_tokens, "temperature": temperature,
            "chat_template_kwargs": {"enable_thinking": False},
            "response_format": {"type": "json_schema", "json_schema": {"name": "decision", "schema": schema}}}
    last = None
    for attempt in range(retries + 1):
        key_file = os.environ.get("LMF_NIM_KEY_FILE")
        if not key_file or not os.path.exists(key_file):
            return {"failed": True, "error": "NIM key file not configured"}
        key = open(key_file, encoding="utf-8").read().strip()
        req = urllib.request.Request(ENDPOINT, data=json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        key = None
        t = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                r = json.load(resp)
            content = r["choices"][0]["message"].get("content") or ""
            return {"provider": "NVIDIA_NIM", "model": r.get("model", MODEL), "response_id": r.get("id"),
                    "content": content, "parsed": json.loads(content), "usage": r.get("usage"),
                    "finish_reason": r["choices"][0].get("finish_reason"), "latency_s": round(time.time() - t, 2),
                    "attempt": attempt}
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as e:
            last = {"error": type(e).__name__, "status": getattr(e, "code", None), "attempt": attempt}
            time.sleep(1.5 * (attempt + 1))
    return {"provider": "NVIDIA_NIM", "model": MODEL, "failed": True, **(last or {})}
