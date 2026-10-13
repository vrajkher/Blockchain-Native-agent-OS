"""A hostile guest used by the sandbox tests. It speaks the broker protocol but
tries to escape or cheat; the attack is chosen by payload["text"] == "ATTACK:<name>".
It reports what it observed in its result output."""

import asyncio
import os
import socket
import sys

from blockswarm import rpc


async def attack(name, reader, writer, task):
    obs = {"uid": os.getuid(), "pid": os.getpid()}
    call_id = 0

    async def call(op, **args):
        nonlocal call_id
        call_id += 1
        await rpc.send(writer, {"t": "call", "id": call_id, "op": op, "args": args})
        return await rpc.recv(reader)

    if name == "env":
        obs["env_keys"] = sorted(os.environ)
    elif name == "network":
        for host, port in (("1.1.1.1", 443), ("127.0.0.1", int(task["payload"].get("port", 1)))):
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect((host, port))
                obs[f"{host}:{port}"] = "connected"
            except OSError as exc:
                obs[f"{host}:{port}"] = type(exc).__name__ + ":" + str(exc.errno)
            finally:
                s.close()
    elif name == "filesystem":
        for path in (task["payload"]["keystore"], "/etc/shadow"):
            try:
                open(path, "rb").read(1)
                obs["read:" + path] = "ok"
            except OSError as exc:
                obs["read:" + path] = type(exc).__name__
        for path in ("/tmp/bs-escape-test", task["payload"]["writable_dir"] + "/bs-escape-test"):
            try:
                with open(path, "w") as fh:
                    fh.write("x" * 100)
                obs["write:" + path] = "ok"
            except OSError as exc:
                obs["write:" + path] = type(exc).__name__
    elif name == "privileges":
        obs["tool"] = await call("tool", name="calculator", args={"expression": "1+1"})
        obs["unknown_op"] = await call("shell", cmd="id")
        obs["other_memory"] = await call("mem.get", key=task["payload"]["victim_key"])
        obs["task_has_capability"] = "capability" in task or "cap" in task
    elif name == "forge":
        # claim tool calls that never happened; the broker must ignore this
        await rpc.send(writer, {"t": "result", "output": {"label": "neutral", "confidence": 1},
                                "tool_calls": [{"tool": "calculator", "args": {}}]})
        return
    elif name == "flood":
        for _ in range(1000):
            await call("mem.recent", n=1)
    elif name == "oversize":
        writer.write(rpc._HDR.pack(rpc.MAX_FRAME + 1) + b"x" * 64)
        await writer.drain()
        await asyncio.sleep(5)
    elif name == "hang":
        while True:
            await asyncio.sleep(1)
    await rpc.send(writer, {"t": "result", "output": {"observations": obs}})


async def _main(fd):
    sock = socket.socket(fileno=fd)
    reader, writer = await asyncio.open_connection(sock=sock)
    task = await rpc.recv(reader)
    await attack(task["payload"]["text"].split(":", 1)[1], reader, writer, task)
    writer.close()


def main(argv):
    asyncio.run(_main(int(argv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
