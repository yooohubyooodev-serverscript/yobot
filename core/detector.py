"""Conservative signature detection.

Only reports high-confidence patterns. Generic words such as "vm",
"luau", "veil" alone are never treated as confirmed hits.
"""

from __future__ import annotations

import re


def detect(source: str) -> list[dict]:
    """
    Return a list of detection dicts:
        {"name": "...", "confidence": "heuristic"|"high", "note": "..."}
    """
    text = source
    lower = source.lower()
    results = []

    # High-confidence Luraph markers
    if re.search(r"LPH[_$]|Luraph|initv4|lph[_$]", text, re.I):
        results.append({
            "name": "Luraph-like",
            "confidence": "heuristic",
            "note": "Found Luraph-style identifiers; not confirmed",
        })

    # MoonSec
    if re.search(r"MoonSec|Moon.?Sec|MS_V3", text, re.I):
        results.append({
            "name": "MoonSec-like",
            "confidence": "heuristic",
            "note": "Found MoonSec-style markers; not confirmed",
        })

    # IronBrew
    if "IronBrew" in text or re.search(r"IB_\d+", text):
        results.append({
            "name": "IronBrew-like",
            "confidence": "heuristic",
            "note": "Found IronBrew-style markers; not confirmed",
        })

    # Luarmor
    if "luarmor" in lower or "script_key" in lower:
        results.append({
            "name": "Luarmor-like",
            "confidence": "heuristic",
            "note": "Found Luarmor-style markers; not confirmed",
        })

    # Heavy use of string.char / large base64 may indicate packing
    if lower.count("string.char") > 5 or len(re.findall(r"[A-Za-z0-9+/]{40,}", text)) > 3:
        results.append({
            "name": "Packed/encoded strings",
            "confidence": "heuristic",
            "note": "Many encoded string constructs detected",
        })

    return results
