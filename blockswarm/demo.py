"""Demo task graph used by ``blockswarm demo`` and the tests."""

from __future__ import annotations

from .swarm import Swarm

DOC_A = ("The new release improved query latency by forty percent and the migration was a success. "
         "Operators reported fast rollouts and excellent stability. "
         "One minor issue remains in the reporting dashboard.")
DOC_B = ("Last night's outage was caused by a failed certificate rotation. "
         "Error rates were high for twenty minutes and some customers saw slow responses. "
         "The team rolled back and is adding automated expiry checks.")


def submit_demo_graph(swarm: Swarm) -> dict[str, str]:
    """Independent tasks run in parallel; the report depends on all of them."""
    t = {
        "summary_a": swarm.submit("summarize", {"text": DOC_A}),
        "summary_b": swarm.submit("summarize", {"text": DOC_B}),
        "sentiment_a": swarm.submit("classify_sentiment", {"text": DOC_A}),
        "sentiment_b": swarm.submit("classify_sentiment", {"text": DOC_B}),
        "arithmetic": swarm.submit("arithmetic", {"expression": "(40 + 20) * 3 / 4"}),
    }
    t["report"] = swarm.submit("report", {"title": "Weekly operations digest"}, deps=list(t.values()))
    return t
