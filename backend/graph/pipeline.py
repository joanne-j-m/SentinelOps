"""
graph/pipeline.py
──────────────────
Defines the LangGraph StateGraph that wires all agents together.
Omium SDK is initialized here via init_omium() so it instruments
LangGraph before the graph is compiled.

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
"""

from __future__ import annotations
from langgraph.graph import StateGraph, END

from backend.core.state import SentinelState, JobStatus
from backend.agents import supervisor_node, scout_node, analyst_node, reporter_node
from backend.core.omium import init_omium

# Initialize Omium once — instruments LangGraph before graph compiles
init_omium()

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

    if status == JobStatus.FAILED:
        return "reporter"

    if confidence < CONFIDENCE_THRESHOLD and loop_count < MAX_LOOPS:
        return "scout"

    return "reporter"


def build_graph() -> StateGraph:
    """
    Constructs and compiles the Sentinel-Ops LangGraph pipeline.
    Omium auto-instruments all nodes via instrument_langgraph() called
    in init_omium() above.
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