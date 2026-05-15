"""
graph/pipeline.py
──────────────────
Defines the LangGraph StateGraph that wires all agents together.

Graph topology:
  START
    │
    ▼
  supervisor          ← validates & decomposes
    │
    ▼
  scout               ← gathers raw evidence
    │
    ▼
  analyst             ← enriches & scores confidence
    │
    ├─── confidence < threshold AND loops < 3  ──► scout  (cyclic loop)
    │
    └─── confidence OK  ──────────────────────────► reporter
                                                       │
                                                      END

The edge function `route_after_analyst` implements the autonomy loop
described in the PDF: "if the Analyst isn't sure, it loops back to Scout."
"""

from __future__ import annotations
from langgraph.graph import StateGraph, END

from backend.core.state import SentinelState, JobStatus
from backend.agents import supervisor_node, scout_node, analyst_node, reporter_node


CONFIDENCE_THRESHOLD = 0.6
MAX_LOOPS = 3


def route_after_analyst(state: SentinelState) -> str:
    """
    Conditional edge: decides whether to loop back to Scout or proceed to Reporter.
    Called by LangGraph after every `analyst` node execution.
    """
    context    = state.get("context", {})
    loop_count = state.get("loop_count", 0)
    confidence = context.get("confidence", 1.0)
    status     = state.get("job_status")

    # Hard stop conditions
    if status == JobStatus.FAILED:
        return "reporter"   # Let Reporter write an error fact sheet

    if confidence < CONFIDENCE_THRESHOLD and loop_count < MAX_LOOPS:
        return "scout"      # Loop: gather more evidence

    return "reporter"       # Proceed to final report


def build_graph() -> StateGraph:
    """
    Constructs and compiles the Sentinel-Ops LangGraph pipeline.
    Returns a compiled graph ready for .invoke() or .stream().
    """
    graph = StateGraph(SentinelState)

    # ── Register nodes ────────────────────────────────────────────────────
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("scout",      scout_node)
    graph.add_node("analyst",    analyst_node)
    graph.add_node("reporter",   reporter_node)

    # ── Wire edges ────────────────────────────────────────────────────────
    graph.set_entry_point("supervisor")
    graph.add_edge("supervisor", "scout")
    graph.add_edge("scout",      "analyst")

    # Conditional edge: analyst → scout (loop) OR analyst → reporter
    graph.add_conditional_edges(
        "analyst",
        route_after_analyst,
        {
            "scout":    "scout",
            "reporter": "reporter",
        },
    )

    graph.add_edge("reporter", END)

    return graph.compile()


# Module-level compiled graph (import and call .invoke())
sentinel_graph = build_graph()
