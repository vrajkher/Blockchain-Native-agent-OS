"""External tool authorization gateway.

Agents never call tools directly. Every call goes through this gateway,
which verifies a scoped capability, enforces per-agent limits, executes the
tool on the host side, and records an audit entry. Fail closed.
"""

from __future__ import annotations

import ast
import asyncio
import operator
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .capabilities import Capability, CapabilityAuthority, CapabilityError
from .db import Database


class ToolError(Exception):
    pass


_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
        ast.Pow: operator.pow}
_UN = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def safe_eval(expression: str) -> float | int:
    """Evaluate a bounded arithmetic expression without eval()."""
    if not isinstance(expression, str) or len(expression) > 256:
        raise ToolError("expression too long")
    tree = ast.parse(expression, mode="eval")

    def ev(node: ast.AST) -> float | int:
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UN:
            return _UN[type(node.op)](ev(node.operand))
        if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
            left, right = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Pow) and (abs(right) > 64 or abs(left) > 10**6):
                raise ToolError("exponent out of bounds")
            result = _BIN[type(node.op)](left, right)
            if isinstance(result, (int, float)) and abs(result) > 1e300:
                raise ToolError("result out of bounds")
            return result
        raise ToolError(f"disallowed syntax: {type(node).__name__}")

    try:
        return ev(tree)
    except ZeroDivisionError as exc:
        raise ToolError("division by zero") from exc


@dataclass
class Tool:
    name: str
    fn: Callable[[dict], Awaitable[Any] | Any]
    max_calls_per_minute: int = 60
    timeout: float = 5.0


@dataclass
class _Usage:
    calls: list[float] = field(default_factory=list)


class ToolGateway:
    def __init__(self, authority: CapabilityAuthority, db: Database):
        self.authority = authority
        self.db = db
        self.tools: dict[str, Tool] = {}
        self._usage: dict[tuple[str, str], _Usage] = {}
        self.register(Tool("calculator", lambda args: {"value": safe_eval(args["expression"])}))

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    async def call(self, cap: Capability, agent_id: str, name: str, args: dict) -> Any:
        tool = self.tools.get(name)
        try:
            if tool is None:
                raise ToolError(f"unknown tool: {name}")
            self.authority.check(cap, agent_id, f"tool:{name}")
            usage = self._usage.setdefault((agent_id, name), _Usage())
            now = time.time()
            usage.calls = [t for t in usage.calls if now - t < 60]
            if len(usage.calls) >= tool.max_calls_per_minute:
                raise ToolError("tool rate limit exceeded")
            usage.calls.append(now)
            if not isinstance(args, dict):
                raise ToolError("tool args must be an object")
            result = tool.fn(args)
            if asyncio.iscoroutine(result):
                result = await asyncio.wait_for(result, tool.timeout)
            self.db.audit("tool_call", agent_id, cap.body.get("task_id"), tool=name, ok=True)
            return result
        except (CapabilityError, ToolError) as exc:
            self.db.audit("tool_denied", agent_id, None, tool=name, reason=str(exc))
            raise
        except Exception as exc:
            self.db.audit("tool_error", agent_id, None, tool=name, reason=repr(exc))
            raise ToolError(f"tool failed: {exc!r}") from exc
