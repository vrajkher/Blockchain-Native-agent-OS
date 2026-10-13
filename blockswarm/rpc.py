"""Length-prefixed JSON framing for the host <-> sandbox channel.

Frame = 4-byte big-endian length + UTF-8 JSON object. The same framing is
used over a socketpair (in-process / process sandboxes), Firecracker vsock
(host side: a Unix socket) and the external gateway's Unix socket.
"""

from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

MAX_FRAME = 256 * 1024
_HDR = struct.Struct(">I")


class ProtocolError(Exception):
    pass


def encode(msg: dict) -> bytes:
    data = json.dumps(msg, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if len(data) > MAX_FRAME:
        raise ProtocolError(f"frame too large ({len(data)} bytes)")
    return _HDR.pack(len(data)) + data


async def send(writer: asyncio.StreamWriter, msg: dict) -> None:
    writer.write(encode(msg))
    await writer.drain()


async def recv(reader: asyncio.StreamReader, max_frame: int = MAX_FRAME) -> dict:
    try:
        hdr = await reader.readexactly(_HDR.size)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError("channel closed") from exc
    (length,) = _HDR.unpack(hdr)
    if length > max_frame:
        raise ProtocolError(f"frame too large ({length} bytes)")
    try:
        data = await reader.readexactly(length)
        msg: Any = json.loads(data)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError("truncated frame") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("malformed frame") from exc
    if not isinstance(msg, dict):
        raise ProtocolError("frame is not an object")
    return msg
