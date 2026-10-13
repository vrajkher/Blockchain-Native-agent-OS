"""Command line entry point: python -m blockswarm <command>."""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
import time

from .config import load_config
from .governor import peak_rss_bytes, read_meminfo, rss_bytes


def _cfg(args):
    overrides = {"home": args.home}
    inf = {}
    if getattr(args, "backend", None):
        inf["backend"] = args.backend
    if getattr(args, "model", None):
        inf["model"] = args.model
    if getattr(args, "effort", None):
        inf["effort"] = args.effort
    if inf:
        overrides["inference"] = inf
    return load_config(args.config, **overrides)


def _swarm(cfg, preflight: bool = False):
    from .inference import InferenceError
    from .swarm import Swarm
    swarm = Swarm(cfg)
    if preflight:
        try:
            swarm.backend.preflight()
        except InferenceError as exc:
            raise SystemExit(f"inference backend not ready: {exc}")
    return swarm


def _ensure_agents(swarm, n: int) -> None:
    have = swarm.registry.count()
    if have < n:
        # One calculator-capable agent; the rest are plain workers.
        if not any("calculator" in a.roles for a in swarm.registry.list()):
            swarm.create_agents(1, ["worker", "calculator"])
            have += 1
        if have < n:
            swarm.create_agents(n - have, ["worker"])


def cmd_init(args) -> int:
    cfg = _cfg(args)
    swarm = _swarm(cfg)
    _ensure_agents(swarm, args.agents)
    from .api import load_or_create_token
    load_or_create_token(cfg.home_path)
    print(json.dumps({"home": str(cfg.home_path), "agents": swarm.registry.count(),
                      "host_pubkey": swarm.host_pubkey}, indent=2))
    asyncio.run(swarm.shutdown())
    return 0


def cmd_demo(args) -> int:
    cfg = _cfg(args)
    if args.fresh and cfg.home_path.exists():
        shutil.rmtree(cfg.home_path)
    rss0 = rss_bytes()
    t0 = time.perf_counter()
    swarm = _swarm(cfg, preflight=True)
    rss_loaded = rss_bytes()
    _ensure_agents(swarm, args.agents)
    from .demo import submit_demo_graph

    async def main():
        ids = submit_demo_graph(swarm)
        status = await swarm.run(timeout=args.timeout)
        return ids, status

    ids, status = asyncio.run(main())
    elapsed = time.perf_counter() - t0
    model = "" if swarm.backend.is_mock else f" model={cfg.inference.model} effort={cfg.inference.effort}"
    print(f"backend={swarm.backend.name}{model} mock={swarm.backend.is_mock} "
          f"isolation={swarm.sandboxes.isolation}")
    print(f"ledger={status['ledger']['backend']} finality={status['ledger']['finality']}")
    ok = True
    for name, tid in ids.items():
        task = swarm.queue.get(tid)
        res = swarm.result(tid)
        if res is None:
            ok = False
            print(f"\n[{name}] {tid} status={task.status} error={task.error}")
            continue
        receipt_ok = swarm.chain.verify_receipt(res["receipt"]) if res["receipt"] else False
        ok &= receipt_ok
        print(f"\n[{name}] {tid} status={task.status} agent={res['agent_id'][:14]} "
              f"verified={res['verification']['ok']} proves_correctness="
              f"{res['verification']['proves_correctness']} receipt_valid={receipt_ok} "
              f"block={res['receipt']['block_height']}")
        print("  output:", json.dumps(res["output"], ensure_ascii=False)[:400])
    agents_used = {swarm.result(t)["agent_id"] for t in ids.values() if swarm.result(t)}
    print("\nsummary:", json.dumps({
        "tasks": status["tasks"], "distinct_agents_used": len(agents_used),
        "max_active_agents_seen": status["max_active_seen"],
        "max_concurrent_inference": status["inference"]["max_concurrent"],
        "inference_requests": status["inference"]["requests"],
        "ledger_height": status["ledger"]["height"], "chain_valid": swarm.chain.ledger.verify_chain(),
        "elapsed_s": round(elapsed, 2),
        "rss_mib": {"start": round(rss0 / 2**20, 1), "after_init": round(rss_loaded / 2**20, 1),
                    "end": round(rss_bytes() / 2**20, 1), "peak": round(peak_rss_bytes() / 2**20, 1)},
        "host_mem_available_mib": round(read_meminfo()["MemAvailable"] / 2**20),
    }, indent=2))
    asyncio.run(swarm.shutdown())
    return 0 if ok and status["tasks"].get("done", 0) == len(ids) else 1


def cmd_status(args) -> int:
    swarm = _swarm(_cfg(args))
    swarm.governor.sample()
    print(json.dumps(swarm.status(), indent=2))
    asyncio.run(swarm.shutdown())
    return 0


def cmd_revoke(args) -> int:
    swarm = _swarm(_cfg(args))
    print(json.dumps(swarm.revoke_agent(args.agent_id, args.reason), indent=2))
    asyncio.run(swarm.shutdown())
    return 0


def cmd_serve(args) -> int:
    from .api import ApiServer, load_or_create_token
    cfg = _cfg(args)
    swarm = _swarm(cfg, preflight=True)
    _ensure_agents(swarm, args.agents)
    token = load_or_create_token(cfg.home_path)

    async def main():
        server = await ApiServer(swarm, token).start()
        addr = server.sockets[0].getsockname()
        print(f"API listening on http://{addr[0]}:{addr[1]} (token in {cfg.home_path / 'api_token'})")
        async with server:
            await swarm.run(until_idle=False)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="blockswarm", description="BlockSwarm AI Lite")
    p.add_argument("--home", default=".blockswarm")
    p.add_argument("--config", default=None, help="TOML config file")
    sub = p.add_subparsers(dest="cmd", required=True)

    def backend_args(sp):
        sp.add_argument("--backend", choices=["anthropic", "mock"])
        sp.add_argument("--model", help="Claude model ID (default claude-opus-5-5)")
        sp.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"])

    sp = sub.add_parser("init")
    sp.add_argument("--agents", type=int, default=2)
    sp.set_defaults(fn=cmd_init)
    sp = sub.add_parser("demo")
    sp.add_argument("--agents", type=int, default=2)
    sp.add_argument("--fresh", action="store_true", help="delete the swarm home first")
    sp.add_argument("--timeout", type=float, default=1800)
    backend_args(sp)
    sp.set_defaults(fn=cmd_demo)
    sp = sub.add_parser("status")
    sp.set_defaults(fn=cmd_status)
    sp = sub.add_parser("revoke")
    sp.add_argument("agent_id")
    sp.add_argument("--reason", default="operator")
    sp.set_defaults(fn=cmd_revoke)
    sp = sub.add_parser("serve")
    sp.add_argument("--agents", type=int, default=2)
    backend_args(sp)
    sp.set_defaults(fn=cmd_serve)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
