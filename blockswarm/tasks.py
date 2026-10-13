"""Task kinds: instructions, I/O schemas and deterministic checkers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .tools import ToolError, safe_eval

TEXT = {"type": "string", "minLength": 1, "maxLength": 8000}


@dataclass(frozen=True)
class TaskKind:
    name: str
    instructions: str
    input_schema: dict
    output_schema: dict
    required_caps: tuple[str, ...] = ("inference",)
    uses_llm: bool = True
    # Deterministic check: returns a list of problems (empty == pass).
    checker: Callable[[dict, dict], list[str]] | None = None
    deterministic: bool = False  # True when the checker fully proves correctness
    example: dict = field(default_factory=dict)


def _check_arithmetic(inp: dict, out: dict) -> list[str]:
    try:
        expected = safe_eval(inp["expression"])
    except ToolError as exc:
        return [f"expression not evaluable: {exc}"]
    if abs(float(out["answer"]) - float(expected)) > 1e-9 * max(1.0, abs(float(expected))):
        return [f"answer {out['answer']} != {expected}"]
    return []


def _check_summary(inp: dict, out: dict) -> list[str]:
    if len(inp["text"]) > 400 and len(out["summary"]) >= len(inp["text"]):
        return ["summary is not shorter than the source text"]
    return []


def _check_report(inp: dict, out: dict) -> list[str]:
    return [] if out["report"].strip() else ["empty report"]


KINDS: dict[str, TaskKind] = {}


def register(kind: TaskKind) -> TaskKind:
    KINDS[kind.name] = kind
    return kind


register(TaskKind(
    name="summarize",
    instructions="Summarize the text in at most three sentences and list up to five key points.",
    input_schema={"type": "object", "required": ["text"], "properties": {"text": TEXT},
                  "additionalProperties": False},
    output_schema={
        "type": "object", "required": ["summary", "key_points"], "additionalProperties": False,
        "properties": {
            "summary": {"type": "string", "minLength": 1, "maxLength": 1200},
            "key_points": {"type": "array", "maxItems": 5,
                           "items": {"type": "string", "maxLength": 300}},
        },
    },
    checker=_check_summary,
    example={"summary": "One short summary.", "key_points": ["point one", "point two"]},
))

register(TaskKind(
    name="classify_sentiment",
    instructions="Classify the overall sentiment of the text as positive, negative or neutral.",
    input_schema={"type": "object", "required": ["text"], "properties": {"text": TEXT},
                  "additionalProperties": False},
    output_schema={
        "type": "object", "required": ["label", "confidence"], "additionalProperties": False,
        "properties": {
            "label": {"type": "string", "enum": ["positive", "negative", "neutral"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
    },
    example={"label": "neutral", "confidence": 0.5},
))

register(TaskKind(
    name="arithmetic",
    instructions="Evaluate the arithmetic expression using the calculator tool.",
    input_schema={"type": "object", "required": ["expression"], "additionalProperties": False,
                  "properties": {"expression": {"type": "string", "minLength": 1, "maxLength": 256}}},
    output_schema={"type": "object", "required": ["answer"], "additionalProperties": False,
                   "properties": {"answer": {"type": "number"}}},
    required_caps=("tool:calculator",),
    uses_llm=False,
    checker=_check_arithmetic,
    deterministic=True,
))

register(TaskKind(
    name="report",
    instructions=("Write a short plain-text report (at most 120 words) that combines the "
                  "dependency results provided in the input."),
    input_schema={"type": "object", "required": ["title"],
                  "properties": {"title": {"type": "string", "maxLength": 200},
                                 "dependencies": {"type": "object"}}},
    output_schema={"type": "object", "required": ["report"], "additionalProperties": False,
                   "properties": {"report": {"type": "string", "minLength": 1, "maxLength": 3000}}},
    checker=_check_report,
    example={"report": "Short combined report."},
))


# ---------------------------------------------------------------------------
# Deterministic MOCK responses. Used only by MockBackend; outputs are labelled
# as mock everywhere they surface. They exist so the runtime can be tested
# without model weights; they are not AI output.
# ---------------------------------------------------------------------------

_POS = {"good", "great", "excellent", "improved", "success", "growth", "happy", "secure", "fast"}
_NEG = {"bad", "poor", "failure", "failed", "outage", "slow", "loss", "breach", "angry"}


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]


def mock_response(kind: str, data: dict) -> dict:
    if kind == "summarize":
        sents = _sentences(data["text"]) or [data["text"]]
        return {"summary": " ".join(sents[:2])[:600],
                "key_points": [" ".join(s.split()[:8]) for s in sents[:3]]}
    if kind == "classify_sentiment":
        words = set(re.findall(r"[a-z]+", data["text"].lower()))
        pos, neg = len(words & _POS), len(words & _NEG)
        label = "positive" if pos > neg else "negative" if neg > pos else "neutral"
        return {"label": label, "confidence": round(0.5 + 0.1 * min(abs(pos - neg), 4), 2)}
    if kind == "report":
        parts = [data.get("title", "Report")]
        for tid, dep in sorted((data.get("dependencies") or {}).items()):
            out = dep.get("output", {})
            parts.append(f"{tid}: " + "; ".join(f"{k}={v}" for k, v in sorted(out.items())
                                               if not isinstance(v, list)))
        return {"report": "\n".join(parts)[:3000]}
    raise ValueError(f"mock has no response for kind {kind}")
