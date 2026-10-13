#!/usr/bin/env python3
"""Phase 1 benchmark: logical agent counts vs. measured memory and throughput.

Each configuration runs in a fresh subprocess so peak RSS (VmHWM) is per run.

    python scripts/bench.py --backend mock --agents 2 3 10 100
    python scripts/bench.py --backend anthropic --agents 2 3 10 100 --tasks 6   # real API calls, costs money
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEXTS = [
    "The deployment went well and latency improved.",
    "The outage caused slow responses and angry customers.",
    "The meeting is scheduled for Tuesday at noon.",
    "Revenue growth was excellent this quarter.",
]


def run_one(args) -> dict:
    from blockswarm.config import load_config
    from blockswarm.governor import peak_rss_bytes, read_meminfo, rss_bytes
    from blockswarm.swarm import Swarm

    mem0 = read_meminfo()
    rss0 = rss_bytes()
    with tempfile.TemporaryDirectory() as home:
        inf = {"backend": args.backend, "max_output_tokens_per_request": args.max_tokens}
        if args.model:
            inf["model"] = args.model
        cfg = load_config(home=home, inference=inf, security={"sandbox_backend": args.sandbox},
                          governor={"maximum_active_agents": args.max_active,
                                    "default_active_agents": min(2, args.max_active)})
        t_load = time.perf_counter()
        swarm = Swarm(cfg)
        load_s = time.perf_counter() - t_load
        rss_model = rss_bytes()
        swarm.create_agents(1, ["worker", "calculator"])
        swarm.create_agents(args.agents - 1, ["worker"])
        rss_agents = rss_bytes()
        for i in range(args.tasks):
            if i % 3 == 2:
                swarm.submit("arithmetic", {"expression": f"({i} + 7) * 3"})
            else:
                swarm.submit("classify_sentiment", {"text": TEXTS[i % len(TEXTS)]})
        samples = {"rss_max": 0, "avail_min": mem0["MemAvailable"]}

        async def sampler():
            while True:
                samples["rss_max"] = max(samples["rss_max"], rss_bytes())
                samples["avail_min"] = min(samples["avail_min"], read_meminfo()["MemAvailable"])
                await asyncio.sleep(0.05)

        async def main():
            task = asyncio.ensure_future(sampler())
            t0 = time.perf_counter()
            status = await swarm.run(timeout=args.timeout)
            elapsed = time.perf_counter() - t0
            task.cancel()
            return status, elapsed

        status, elapsed = asyncio.run(main())
        agents_used = len({r["agent_id"] for r in
                           swarm.db.all("SELECT agent_id FROM results")})
        out = {
            "backend": args.backend, "sandbox": args.sandbox,
            "logical_agents": args.agents, "tasks": args.tasks,
            "guest_peak_rss_mib": round(swarm.guest_peak_rss / 2**20, 1) or None,
            "ms_per_task": round(1000 * elapsed / args.tasks, 1),
            "tasks_status": status["tasks"], "agents_used": agents_used,
            "max_active_seen": status["max_active_seen"],
            "allowed_active_seen": sorted(swarm.allowed_seen),
            "max_concurrent_inference": status["inference"]["max_concurrent"],
            "inference_requests": status["inference"]["requests"],
            "model_load_s": round(load_s, 2), "run_s": round(elapsed, 2),
            "rss_mib": {"baseline": round(rss0 / 2**20, 1), "after_init": round(rss_model / 2**20, 1),
                        "after_agents": round(rss_agents / 2**20, 1),
                        "max_during_run": round(samples["rss_max"] / 2**20, 1),
                        "peak_hwm": round(peak_rss_bytes() / 2**20, 1)},
            "host": {"total_mib": round(mem0["MemTotal"] / 2**20),
                     "available_before_mib": round(mem0["MemAvailable"] / 2**20),
                     "available_min_mib": round(samples["avail_min"] / 2**20)},
            "db_size_kib": round(sum(os.path.getsize(p) for p in
                                     (str(cfg.db_path), f"{cfg.db_path}-wal")
                                     if os.path.exists(p)) / 1024),
        }
        asyncio.run(swarm.shutdown())
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="mock")
    ap.add_argument("--model")
    ap.add_argument("--agents", type=int, nargs="+", default=[2, 3, 10, 100])
    ap.add_argument("--tasks", type=int, default=12)
    ap.add_argument("--max-active", type=int, default=3)
    ap.add_argument("--max-tokens", type=int, default=1024)
    ap.add_argument("--sandbox", default="inprocess", choices=["inprocess", "process", "firecracker"])
    ap.add_argument("--timeout", type=float, default=1800)
    ap.add_argument("--child", action="store_true")
    args = ap.parse_args()
    if args.child:
        args.agents = args.agents[0]
        print(json.dumps(run_one(args)))
        return
    results = []
    for n in args.agents:
        cmd = [sys.executable, os.path.abspath(__file__), "--child", "--backend", args.backend,
               "--agents", str(n), "--tasks", str(args.tasks), "--max-active", str(args.max_active),
               "--max-tokens", str(args.max_tokens), "--sandbox", args.sandbox,
               "--timeout", str(args.timeout)]
        if args.model:
            cmd += ["--model", args.model]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stderr[-2000:], file=sys.stderr)
            raise SystemExit(proc.returncode)
        res = json.loads(proc.stdout.strip().splitlines()[-1])
        results.append(res)
        print(json.dumps(res), flush=True)


if __name__ == "__main__":
    main()
