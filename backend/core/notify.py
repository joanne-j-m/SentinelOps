"""
core/notify.py
───────────────
Webhook notification dispatcher used by the Reporter agent.

Supports:
  - Discord webhooks
  - Slack webhooks

Graceful degradation:
  - If webhook URL not set → skips silently, no crash
  - If webhook call fails  → logs warning, continues

Usage:
    from backend.core.notify import send_notifications
    send_notifications(fact_sheet, job_id)
"""

from __future__ import annotations
import os
import logging
import httpx
from typing import Dict, Any

logger = logging.getLogger(__name__)

SEVERITY_COLOURS = {
    "CRITICAL": 0xFF0000,   # Red
    "HIGH":     0xFF6600,   # Orange
    "MEDIUM":   0xFFCC00,   # Yellow
    "LOW":      0x00CC44,   # Green
}

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


def _send_discord(fact_sheet: Dict[str, Any], job_id: str) -> None:
    url = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    if not url:
        logger.info("DISCORD_WEBHOOK_URL not set — skipping Discord notification.")
        return

    severity    = fact_sheet.get("severity", "UNKNOWN")
    summary     = fact_sheet.get("summary", "No summary available.")
    mitre       = fact_sheet.get("mitre_tactics", [])
    recs        = fact_sheet.get("recommendations", [])
    colour      = SEVERITY_COLOURS.get(severity, 0x888888)
    emoji       = SEVERITY_EMOJI.get(severity, "⚠️")

    rec_text = "\n".join(f"{i+1}. {r}" for i, r in enumerate(recs[:3]))
    mitre_text = ", ".join(mitre) if mitre else "Unknown"

    payload = {
        "username": "Sentinel-Ops",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2716/2716652.png",
        "embeds": [
            {
                "title": f"{emoji} Threat Detected — {severity}",
                "description": summary[:1000],
                "color": colour,
                "fields": [
                    {"name": "Job ID",         "value": f"`{job_id}`",  "inline": True},
                    {"name": "MITRE ATT&CK",   "value": mitre_text,     "inline": True},
                    {"name": "Recommendations","value": rec_text or "See full report.", "inline": False},
                ],
                "footer": {"text": "Sentinel-Ops v0.3 · Powered by Llama 3 via Groq"},
            }
        ],
    }

    try:
        resp = httpx.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"Discord notification sent for job {job_id}.")
    except Exception as exc:
        logger.warning(f"Discord webhook failed for job {job_id}: {exc}")


def _send_slack(fact_sheet: Dict[str, Any], job_id: str) -> None:
    url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not url:
        logger.info("SLACK_WEBHOOK_URL not set — skipping Slack notification.")
        return

    severity = fact_sheet.get("severity", "UNKNOWN")
    summary  = fact_sheet.get("summary", "No summary available.")
    emoji    = SEVERITY_EMOJI.get(severity, "⚠️")
    recs     = fact_sheet.get("recommendations", [])
    rec_text = "\n".join(f"• {r}" for r in recs[:3])

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Sentinel-Ops Alert — {severity}",
                }
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary[:500]},
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Job ID:*\n`{job_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top Recommendations:*\n{rec_text}"},
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "Sentinel-Ops v0.3 · Powered by Llama 3 via Groq"}
                ],
            },
        ]
    }

    try:
        resp = httpx.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"Slack notification sent for job {job_id}.")
    except Exception as exc:
        logger.warning(f"Slack webhook failed for job {job_id}: {exc}")


def send_notifications(fact_sheet: Dict[str, Any], job_id: str) -> None:
    """
    Send notifications to all configured channels.
    Safe to call even if no webhooks are configured.
    """
    _send_discord(fact_sheet, job_id)
    _send_slack(fact_sheet, job_id)
