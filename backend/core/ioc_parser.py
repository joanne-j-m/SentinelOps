"""
core/ioc_parser.py
───────────────────
Regex-based Indicator of Compromise (IOC) extractor.

The Scout agent uses this to extract structured IOCs from:
  - Raw problem statements
  - Log lines
  - Webhook payloads

Extracts:
  - IPv4 addresses (filters out private/loopback ranges optionally)
  - MD5 / SHA1 / SHA256 file hashes
  - Domain names
  - CVE identifiers
  - URLs

Design assumption: no ML, pure regex — fast and dependency-free.
Phase 3 can layer a lightweight NLP model on top for entity recognition.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any


# ── Regex patterns ─────────────────────────────────────────────────────────
_IPV4    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_MD5     = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1    = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256  = re.compile(r'\b[a-fA-F0-9]{64}\b')
_CVE     = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
_DOMAIN  = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|co|uk|ru|cn|de|fr|nl|xyz|info|biz|online)\b'
)
_URL     = re.compile(r'https?://[^\s<>"\']+')

# Private / non-routable IP ranges to optionally filter
_PRIVATE_RANGES = [
    re.compile(r'^127\.'),
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^0\.0\.0\.0$'),
    re.compile(r'^255\.255\.255\.255$'),
]


def _is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in _PRIVATE_RANGES)


def extract_iocs(text: str, include_private_ips: bool = True) -> Dict[str, Any]:
    """
    Extract all IOCs from a text blob.

    Args:
        text: Raw text (problem statement, log lines, webhook payload)
        include_private_ips: If False, filters RFC1918 addresses.
                             For internal threat hunting, keep True.

    Returns:
        Dict with keys: ips, hashes, domains, cves, urls
    """
    ips = list(dict.fromkeys(_IPV4.findall(text)))  # dedupe, preserve order
    if not include_private_ips:
        ips = [ip for ip in ips if not _is_private_ip(ip)]

    # Hash extraction: longest match wins (SHA256 > SHA1 > MD5)
    sha256 = list(dict.fromkeys(_SHA256.findall(text)))
    # Remove SHA256 matches from shorter hash searches to avoid double-counting
    remaining = text
    for h in sha256:
        remaining = remaining.replace(h, "")
    sha1 = list(dict.fromkeys(_SHA1.findall(remaining)))
    for h in sha1:
        remaining = remaining.replace(h, "")
    md5 = list(dict.fromkeys(_MD5.findall(remaining)))

    all_hashes = sha256 + sha1 + md5

    domains = list(dict.fromkeys(_DOMAIN.findall(text)))
    cves    = list(dict.fromkeys(_CVE.findall(text)))
    urls    = list(dict.fromkeys(_URL.findall(text)))

    # Remove domains that are just substrings of URLs
    url_hosts = set()
    for url in urls:
        parts = url.split("/")
        if len(parts) >= 3:
            url_hosts.add(parts[2])
    domains = [d for d in domains if d not in url_hosts]

    return {
        "ips":     ips,
        "hashes":  all_hashes,
        "domains": domains,
        "cves":    cves,
        "urls":    urls,
    }


def compute_anomaly_score(iocs: Dict[str, Any], log_lines: List[str]) -> float:
    """
    Heuristic anomaly score based on IOC richness and log volume.
    Range: 0.0 – 1.0

    Scoring logic:
      - Each IP:     +0.15
      - Each hash:   +0.20
      - Each CVE:    +0.25
      - Each domain: +0.10
      - Log lines:   +0.05 per line (capped at 0.20)
    Max before cap: theoretically > 1.0, so we clamp.
    """
    score = 0.0
    score += min(len(iocs.get("ips",     [])) * 0.15, 0.45)
    score += min(len(iocs.get("hashes",  [])) * 0.20, 0.40)
    score += min(len(iocs.get("cves",    [])) * 0.25, 0.50)
    score += min(len(iocs.get("domains", [])) * 0.10, 0.30)
    score += min(len(log_lines) * 0.05,               0.20)

    return round(min(score, 1.0), 3)
