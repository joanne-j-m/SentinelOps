"""
core/ip_classifier.py
──────────────────────
Classifies IPs as attacker vs victim based on context.

Priority order (most specific wins):
  1. IP mentioned as "host X" / "server X" / "workstation X" → VICTIM
  2. IP mentioned in a "to <IP>" pattern (destination of attack) → ATTACKER (C2)
  3. IP mentioned in a "from <IP>" pattern AND is external/public → ATTACKER
  4. IP is private/RFC1918 → VICTIM (internal infrastructure)
  5. IP is external/public with no context → ATTACKER
"""

from __future__ import annotations
import re
from typing import List, Tuple

_PRIVATE = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)'
)


def classify_ips(
    ips: List[str],
    problem: str,
) -> Tuple[List[str], List[str]]:
    """
    Returns (attacker_ips, victim_ips).
    """
    attacker_ips: List[str] = []
    victim_ips:   List[str] = []

    # Look for "host <IP>" / "server <IP>" / "workstation <IP>" — strongest victim signal
    host_pattern = re.findall(
        r'\b(?:host|server|workstation|on)\s+([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\b',
        problem, re.I
    )
    host_set = set(host_pattern)

    # Look for "to <IP>" — destination of malicious traffic → attacker C2
    to_pattern = re.findall(
        r'\bto\s+([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\b',
        problem, re.I
    )
    to_set = set(to_pattern)

    # Look for "from <IP>" — source of attack
    from_pattern = re.findall(
        r'\bfrom\s+([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\b',
        problem, re.I
    )
    from_set = set(from_pattern)

    for ip in ips:
        is_private = bool(_PRIVATE.match(ip))

        # Priority 1: explicitly called "host/server/workstation" → victim
        if ip in host_set:
            victim_ips.append(ip)
        # Priority 2: destination of malicious traffic → attacker C2
        elif ip in to_set:
            attacker_ips.append(ip)
        # Priority 3: "from <IP>" AND public → attacker
        elif ip in from_set and not is_private:
            attacker_ips.append(ip)
        # Priority 4: private IP with no other strong context → victim
        elif is_private:
            victim_ips.append(ip)
        # Priority 5: public IP, no context → attacker
        else:
            attacker_ips.append(ip)

    return attacker_ips, victim_ips