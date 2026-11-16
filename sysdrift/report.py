"""Rendering of audit results as text, JSON or YAML."""

from __future__ import annotations

import json
from typing import Any, Dict

import yaml

from . import TOOL_NAME, __alias__, __author__, __version__
from .auditor import SEVERITIES, AuditResult
from .utils import utc_now_iso

FORMATS = ("text", "json", "yaml")
_COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def build_report(result: AuditResult, baseline_path: str, min_severity: str = "info") -> Dict[str, Any]:
    """Assemble the structured report document."""
    meta = result.baseline_meta
    return {
        "tool": {"name": TOOL_NAME, "version": __version__, "author": "%s (%s)" % (__author__, __alias__)},
        "generated_utc": utc_now_iso(),
        "baseline": {
            "path": baseline_path,
            "created_utc": meta.get("created_utc"),
            "host": meta.get("host"),
            "integrity": result.integrity,
        },
        "live_host": result.live_host,
        "audit": {"started_utc": result.started_utc, "finished_utc": result.finished_utc},
        "summary": result.summary(),
        "min_severity_shown": min_severity,
        "findings": [f.to_dict() for f in result.filtered(min_severity)],
    }


def _safe(text: Any) -> str:
    return str(text).encode("utf-8", "backslashreplace").decode("utf-8")


def render_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True)


def render_yaml(report: Dict[str, Any]) -> str:
    return yaml.safe_dump(report, sort_keys=False, allow_unicode=False, default_flow_style=False)


def render_text(report: Dict[str, Any], color: bool = False) -> str:
    def paint(text: str, severity: str) -> str:
        return "\033[%sm%s\033[0m" % (_COLORS[severity], text) if color else text

    tool, base = report["tool"], report["baseline"]
    counts = report["summary"]["by_severity"]
    host = (base.get("host") or {}).get("hostname", "?")
    out = [
        "%s v%s  |  %s" % (tool["name"], tool["version"], tool["author"]),
        "Baseline : %s (captured %s on %s)" % (_safe(base["path"]), base.get("created_utc"), host),
        "Integrity: %s" % base["integrity"],
        "Audited  : %s (%s)" % (report["live_host"].get("hostname"), report["live_host"].get("os") or "linux"),
        "",
    ]
    total = report["summary"]["total"]
    if total == 0:
        out.append("No drift detected: the live system matches the golden baseline.")
        return "\n".join(out) + "\n"
    parts = ["%d %s" % (counts[s], s) for s in reversed(SEVERITIES) if counts[s]]
    out.append("DRIFT DETECTED: %d finding(s) - %s" % (total, ", ".join(parts)))
    shown = len(report["findings"])
    if shown != total:
        out.append("(showing %d at or above '%s')" % (shown, report["min_severity_shown"]))
    out.append("")
    for f in report["findings"]:
        out.append("%s %s  %s" % (paint("[%s]" % f["severity"].upper(), f["severity"]), f["id"], f["category"]))
        out.append("  Title : %s" % _safe(f["title"]))
        if f["path"]:
            out.append("  Path  : %s" % _safe(f["path"]))
        if f["detail"]:
            first, *rest = _safe(f["detail"]).split("\n")
            out.append("  Detail: %s" % first)
            out.extend("  " + line for line in rest)
        if f["recommendation"]:
            out.append("  Fix   : %s" % f["recommendation"])
        out.append("")
    return "\n".join(out)


def render(report: Dict[str, Any], fmt: str, color: bool = False) -> str:
    if fmt == "json":
        return render_json(report) + "\n"
    if fmt == "yaml":
        return render_yaml(report)
    return render_text(report, color)
