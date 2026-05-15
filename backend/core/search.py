"""
core/search.py
───────────────
Tavily web search wrapper used by the Analyst agent for IP/CVE enrichment.

Graceful degradation:
  - If TAVILY_API_KEY is not set → returns empty results (no crash)
  - If Tavily call fails          → logs warning, returns empty results
  - Tests always pass regardless of key availability

Usage:
    from backend.core.search import search_threat_intel

    snippets = search_threat_intel(["192.168.1.42", "CVE-2024-1234"])
    # Returns list of strings: ["IP 192.x observed in...", ...]
"""

from __future__ import annotations
import os
import logging
from typing import List

logger = logging.getLogger(__name__)


def search_threat_intel(queries: List[str], max_results: int = 3) -> List[str]:
    """
    Run Tavily searches for each query term and return combined snippets.

    Args:
        queries:     List of search terms (IPs, CVEs, domains, hashes)
        max_results: Results per query

    Returns:
        List of text snippets from search results.
        Returns empty list if no API key or search fails.
    """
    api_key = os.getenv("TAVILY_API_KEY", "").strip()

    if not api_key:
        logger.warning("TAVILY_API_KEY not set — skipping threat intel search.")
        return []

    try:
        from tavily import TavilyClient  # type: ignore
        client = TavilyClient(api_key=api_key)
    except ImportError:
        logger.warning("tavily-python not installed — skipping search.")
        return []

    snippets: List[str] = []

    for query in queries:
        try:
            full_query = f"threat intelligence cybersecurity {query}"
            result = client.search(
                query=full_query,
                max_results=max_results,
                search_depth="basic",
            )
            for item in result.get("results", []):
                content = item.get("content", "").strip()
                url     = item.get("url", "")
                if content:
                    snippets.append(f"[{query}] {content[:300]} (source: {url})")
        except Exception as exc:
            logger.warning(f"Tavily search failed for '{query}': {exc}")
            continue

    return snippets
