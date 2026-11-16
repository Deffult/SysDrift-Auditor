"""Minimal, dependency-free parser for sshd_config (including Include and Match)."""

from __future__ import annotations

import glob
import os
import re
from typing import Any, Dict, List, Set

_KEY_VALUE = re.compile(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$")
_MAX_INCLUDE_DEPTH = 8


def parse_sshd_config(path: str) -> Dict[str, Any]:
    """Parse *path* and every file it includes.

    Returns a dict with:
      ``settings``     global keywords -> ordered list of values (lower-case keys)
      ``match_blocks`` list of ``{"criteria": str, "settings": {...}}``
      ``files``        every config file visited, main file first
      ``parsed``       ``True`` when the main file was readable
      ``errors``       human-readable problems met while parsing
    """
    state: Dict[str, Any] = {
        "settings": {},
        "match_blocks": [],
        "files": [path],
        "parsed": False,
        "errors": [],
    }
    context = {"target": state["settings"]}
    base_dir = os.path.dirname(path) or "."
    state["parsed"] = _parse_file(path, state, context, base_dir, 0, set())
    return state


def _parse_file(
    path: str,
    state: Dict[str, Any],
    context: Dict[str, Any],
    base_dir: str,
    depth: int,
    seen: Set[str],
) -> bool:
    if depth > _MAX_INCLUDE_DEPTH:
        state["errors"].append("%s: Include nesting too deep" % path)
        return False
    real = os.path.realpath(path)
    if real in seen:
        state["errors"].append("%s: Include loop detected" % path)
        return False
    seen = seen | {real}
    try:
        with open(path, "r", encoding="utf-8", errors="surrogateescape") as handle:
            text = handle.read()
    except OSError as exc:
        state["errors"].append("%s: %s" % (path, exc.strerror or exc))
        return False

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        matched = _KEY_VALUE.match(line)
        if matched:
            keyword, value = matched.group(1).lower(), " ".join(matched.group(2).split())
        else:
            keyword, value = line.lower(), ""
        if keyword == "include":
            for pattern in value.split():
                if not os.path.isabs(pattern):
                    pattern = os.path.join(base_dir, pattern)
                for included in sorted(glob.glob(pattern)):
                    if not os.path.isfile(included):
                        continue
                    if included not in state["files"]:
                        state["files"].append(included)
                    _parse_file(included, state, context, base_dir, depth + 1, seen)
        elif keyword == "match":
            block: Dict[str, Any] = {"criteria": value, "settings": {}}
            state["match_blocks"].append(block)
            context["target"] = block["settings"]
        else:
            context["target"].setdefault(keyword, []).append(value)
    return True
