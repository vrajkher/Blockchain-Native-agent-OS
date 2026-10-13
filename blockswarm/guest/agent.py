"""Guest agent: runs the AgentHarness inside a sandbox, talking only to the host broker.

Holds no keys, no capabilities and no database. Everything it needs comes
from the host over one channel; everything it does goes back over it.

    python -m blockswarm.guest.agent --vsock 2:5000   # inside a Firecracker microVM
    python -m blockswarm.guest.agent --fd 3           # dev process sandbox
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import socket
import sys
from typing import Any

from .. import rpc
from ..harness import AgentContext, AgentHarness
from ..inference import Completion


class HostError(Exception):
    pass


class _Channel:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer
        self._ids = itertools.count(1)
        self._lock = asyncio.Lock()

    async def call(self, op: str, **args: Any) -> Any:
        async with self._lock:  # one request in flight; replies arrive in order
            call_id = next(self._ids)
            await rpc.send(self.writer, {"t": "call", "id": call_id, "op": op, "args": args})
            reply = await rpc.recv(self.reader)
        if reply.get("t") != "reply" or reply.get("id") != call_id:
            raise HostError("protocol error")
        if not reply.get("ok"):
            raise HostError(str(reply.get("error")))
        return reply.get("value")


class _RemoteMemory:
    def __init__(self, ch: _Channel):
        self.ch = ch

    async def get(self, key: str):
        return await self.ch.call("mem.get", key=key)

    async def recent(self, n: int = 3):
        return [tuple(x) for x in await self.ch.call("mem.recent", n=n)]

    async def put(self, key: str, value: str):
        return await self.ch.call("mem.put", key=key, value=value)


async def run_guest(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    ch = _Channel(reader, writer)
    task = await rpc.recv(reader)
    if task.get("t") != "task":
        raise HostError("expected a task")

    async def infer(messages, schema):
        v = await ch.call("infer", messages=messages, schema=schema)
        return Completion(v["text"], v["prompt_tokens"], v["completion_tokens"], "host", v["mock"], 0.0)

    async def call_tool(name, args):
        return await ch.call("tool", name=name, args=args)

    ctx = AgentContext(agent_id=task["agent_id"], host_pubkey=task["host_pubkey"],
                       memory=_RemoteMemory(ch), infer=infer, call_tool=call_tool)
    try:
        result = await AgentHarness(ctx).run(task["envelope"], task["payload"])
        await rpc.send(writer, {"t": "result", "output": result.output})
    except Exception as exc:
        await rpc.send(writer, {"t": "fail", "error": f"{type(exc).__name__}: {exc}"[:500]})


def _connect(args) -> socket.socket:
    if args.fd is not None:
        return socket.socket(fileno=args.fd)
    if args.vsock:
        cid, port = (int(x) for x in args.vsock.split(":"))
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((cid, port))
        return s
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(args.unix)
    return s


async def _main(args) -> int:
    sock = _connect(args)
    reader, writer = await asyncio.open_connection(sock=sock)
    try:
        await run_guest(reader, writer)
    finally:
        writer.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="blockswarm-guest")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--vsock", help="CID:PORT of the host broker (Firecracker: 2:5000)")
    g.add_argument("--fd", type=int, help="inherited, already-connected socket fd")
    g.add_argument("--unix", help="Unix socket path")
    return asyncio.run(_main(ap.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
