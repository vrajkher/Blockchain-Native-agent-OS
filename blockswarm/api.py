"""Minimal authenticated HTTP/1.1 API on asyncio streams (no framework).

Admin endpoints require ``Authorization: Bearer <token>`` (token file is
created 0600 in the swarm home). ``POST /v1/inference`` is the agent-facing
inference gateway and is authenticated by a host-signed capability instead.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import secrets
from pathlib import Path

from .capabilities import Capability, CapabilityError
from .inference import InferenceError
from .swarm import Swarm

MAX_HEADER = 8192


def load_or_create_token(home: Path) -> str:
    path = home / "api_token"
    if path.exists():
        return path.read_text().strip()
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token)
    return token


class ApiServer:
    def __init__(self, swarm: Swarm, token: str):
        self.swarm = swarm
        self.token = token
        self.max_body = swarm.cfg.api.max_body_bytes

    async def start(self, host: str | None = None, port: int | None = None) -> asyncio.base_events.Server:
        return await asyncio.start_server(self._handle, host or self.swarm.cfg.api.host,
                                          port if port is not None else self.swarm.cfg.api.port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            status, body = await asyncio.wait_for(self._request(reader), timeout=30)
        except asyncio.TimeoutError:
            status, body = 408, {"error": "request timeout"}
        except Exception as exc:  # never leak a traceback to the client
            status, body = 400, {"error": f"bad request: {type(exc).__name__}"}
        data = json.dumps(body, default=str).encode()
        writer.write(f"HTTP/1.1 {status} {'OK' if status < 400 else 'ERR'}\r\n"
                     f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n"
                     "Connection: close\r\n\r\n".encode() + data)
        try:
            await writer.drain()
        finally:
            writer.close()

    async def _request(self, reader: asyncio.StreamReader) -> tuple[int, dict]:
        head = await reader.readuntil(b"\r\n\r\n")
        if len(head) > MAX_HEADER:
            return 431, {"error": "headers too large"}
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0"))
        if length < 0 or length > self.max_body:
            return 413, {"error": "body too large"}
        raw = await reader.readexactly(length) if length else b""
        body = json.loads(raw) if raw else {}

        if method == "GET" and path == "/health":
            return 200, {"ok": True}
        if method == "POST" and path == "/v1/inference":
            return await self._inference(body)
        auth = headers.get("authorization", "")
        if not (auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].encode(), self.token.encode())):
            return 401, {"error": "unauthorized"}
        return self._admin(method, path, body)

    async def _inference(self, body: dict) -> tuple[int, dict]:
        try:
            cap = Capability(body["capability"]["body"], body["capability"]["signature"])
            out = await self.swarm.inference.infer(cap, body["agent_id"], body["messages"],
                                                   body.get("max_tokens"), body.get("json_schema"))
        except (CapabilityError, PermissionError) as exc:
            return 403, {"error": str(exc)}
        except (InferenceError, KeyError, TypeError) as exc:
            return 400, {"error": str(exc)}
        return 200, {"text": out.text, "prompt_tokens": out.prompt_tokens,
                     "completion_tokens": out.completion_tokens, "mock": out.mock}

    def _admin(self, method: str, path: str, body: dict) -> tuple[int, dict]:
        s = self.swarm
        parts = [p for p in path.split("/") if p]
        if method == "GET" and parts == ["v1", "status"]:
            return 200, s.status()
        if method == "POST" and parts == ["v1", "tasks"]:
            try:
                tid = s.submit(body["kind"], body["input"], deps=body.get("deps"),
                               priority=int(body.get("priority", 0)),
                               irreversible=bool(body.get("irreversible", False)))
            except (ValueError, KeyError) as exc:
                return 400, {"error": str(exc)}
            return 201, {"task_id": tid}
        if method == "GET" and len(parts) == 3 and parts[:2] == ["v1", "tasks"]:
            task = s.queue.get(parts[2])
            if task is None:
                return 404, {"error": "not found"}
            return 200, {"task": task.__dict__, "result": s.result(parts[2])}
        if method == "POST" and len(parts) == 4 and parts[:2] == ["v1", "agents"] and parts[3] == "revoke":
            if s.registry.get(parts[2]) is None:
                return 404, {"error": "not found"}
            return 200, {"receipt": s.revoke_agent(parts[2], body.get("reason", "api"))}
        return 404, {"error": "not found"}
