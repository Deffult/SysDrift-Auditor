"""Drift Detection Engine: compares a golden baseline with the live system."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .baseline import ScanConfig, collect_state, host_info
from .errors import BaselineError, ConfigError
from .utils import mode_int, utc_now_iso

SEVERITIES = ("info", "low", "medium", "high", "critical")
_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def severity_rank(severity: str) -> int:
    return _RANK[severity]


def _max_severity(a: str, b: str) -> str:
    return a if _RANK[a] >= _RANK[b] else b


_RECOMMENDATIONS = {
    "ACCOUNT_ADDED": "Verify the account is expected; lock it (usermod -L) and investigate if not.",
    "ACCOUNT_MODIFIED": "Confirm the change was authorised; review auth logs for the account.",
    "ACCOUNT_UID0_EXTRA": "Only 'root' should have UID 0. Remove or renumber the extra account.",
    "SUID_ADDED": "Identify the file's origin (dpkg -S / rpm -qf). Remove the SUID bit if unowned: chmod u-s,g-s FILE.",
    "SUID_MODIFIED": "Compare against the package version (dpkg -V / rpm -V). Reinstall the package if unexpected.",
    "SSH_SETTING_CHANGED": "Review /etc/ssh/sshd_config and sshd_config.d; revert unauthorised changes and reload sshd.",
    "SSH_MATCH_BLOCK_CHANGED": "Match blocks override global settings; verify every criterion and override.",
    "SUDOERS_RULE_ADDED": "Inspect with visudo -c and review who made the change. Remove unauthorised rules.",
    "CRON_JOB_ADDED": "Inspect the command and its owner. Persistence via cron is a common post-exploitation step.",
    "PERMISSIONS_CHANGED": "Restore the expected mode/owner with chmod/chown after confirming the change.",
    "INSECURE_PERMISSIONS": "Fix permissions immediately; sensitive files must not be writable by group/others.",
    "MODIFIED": "If the change is unexpected, restore from a trusted source and investigate. If legitimate, re-run 'sysdrift init'.",
    "REMOVED": "Confirm the removal was intended; restore from backup if not.",
    "ADDED": "Confirm the new file is expected and inspect its contents.",
}

_AREA_PREFIX = {
    "core": "FILE",
    "sudoers": "SUDOERS_FILE",
    "ssh": "SSH_FILE",
    "cron": "CRON_FILE",
    "extra": "FILE",
    "suid": "SUID",
}
_AREA_SEVERITY = {
    "core": {"modified": "high", "removed": "high", "added": "high"},
    "sudoers": {"modified": "critical", "removed": "high", "added": "critical"},
    "ssh": {"modified": "high", "removed": "high", "added": "high"},
    "cron": {"modified": "high", "removed": "medium", "added": "high"},
    "extra": {"modified": "high", "removed": "high", "added": "high"},
}

_SUDOERS_DANGEROUS = re.compile(
    r"NOPASSWD|!authenticate|SETENV|=\s*(\([^)]*\)\s*)?(\w+:\s*)*ALL\s*$", re.IGNORECASE
)
_CRON_SUSPICIOUS = re.compile(
    r"/dev/tcp/|\bnc\b.*\s-e\b|\bncat\b|bash\s+-i|curl[^|;&]*\|\s*(ba|z)?sh|wget[^|;&]*\|\s*(ba|z)?sh"
    r"|base64\s+(-d|--decode)|\bmkfifo\b|chmod\s+[ugoa]*\+s|chmod\s+[24][0-7]{3}\b|python\d?\s+-c|perl\s+-e",
    re.IGNORECASE,
)

# --- sshd knowledge ---------------------------------------------------------
_SSH_SENSITIVE = [
    "PermitRootLogin", "PasswordAuthentication", "PermitEmptyPasswords", "PubkeyAuthentication",
    "UsePAM", "PermitUserEnvironment", "AuthorizedKeysFile", "AuthorizedKeysCommand",
    "AuthorizedKeysCommandUser", "AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups", "Port",
    "ListenAddress", "HostbasedAuthentication", "KbdInteractiveAuthentication",
    "ChallengeResponseAuthentication", "GatewayPorts", "PermitTunnel", "ForceCommand", "Subsystem",
    "LogLevel", "Ciphers", "MACs", "KexAlgorithms", "HostKeyAlgorithms", "PubkeyAcceptedAlgorithms",
    "TrustedUserCAKeys", "AuthorizedPrincipalsFile", "AllowTcpForwarding", "X11Forwarding",
    "MaxAuthTries", "Protocol", "HostKey", "PermitOpen", "PermitListen", "ChrootDirectory",
    "AuthenticationMethods", "RevokedKeys",
]
_SSH_BENIGN = [
    "Banner", "ClientAliveInterval", "ClientAliveCountMax", "PrintMotd", "PrintLastLog",
    "TCPKeepAlive", "UseDNS", "AcceptEnv", "LoginGraceTime", "MaxStartups", "MaxSessions",
]
_SSH_CANON = {name.lower(): name for name in _SSH_SENSITIVE + _SSH_BENIGN}
_SSH_BENIGN_KEYS = {name.lower() for name in _SSH_BENIGN}
_SSH_DEFAULTS = {
    "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
    "permitemptypasswords": "no", "permituserenvironment": "no", "hostbasedauthentication": "no",
    "kbdinteractiveauthentication": "yes", "challengeresponseauthentication": "yes",
    "x11forwarding": "no", "gatewayports": "no", "pubkeyauthentication": "yes",
}
_SSH_ROOT_RANK = {"no": 0, "forced-commands-only": 1, "prohibit-password": 2, "without-password": 2, "yes": 3}
_SSH_YES_IS_WEAKER = {
    "passwordauthentication", "permitemptypasswords", "permituserenvironment",
    "hostbasedauthentication", "kbdinteractiveauthentication", "challengeresponseauthentication",
    "x11forwarding", "gatewayports",
}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    path: Optional[str] = None
    detail: str = ""
    baseline: Any = None
    live: Any = None
    recommendation: str = ""
    id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "path": self.path,
            "detail": self.detail,
            "baseline": self.baseline,
            "live": self.live,
            "recommendation": self.recommendation,
        }


@dataclass
class AuditResult:
    findings: List[Finding]
    started_utc: str
    finished_utc: str
    baseline_meta: Dict[str, Any]
    live_host: Dict[str, Any]
    integrity: str = ""

    def summary(self) -> Dict[str, Any]:
        counts = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {"total": len(self.findings), "by_severity": counts}

    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)

    def exceeds(self, threshold: str) -> bool:
        """True if any finding is at or above *threshold* (``"none"`` never trips)."""
        if threshold == "none":
            return False
        return any(severity_rank(f.severity) >= severity_rank(threshold) for f in self.findings)

    def filtered(self, min_severity: str) -> List[Finding]:
        return [f for f in self.findings if severity_rank(f.severity) >= severity_rank(min_severity)]


def _multiset_diff(new: List[str], old: List[str]) -> List[str]:
    """Items of *new* not matched one-for-one by *old*, preserving order."""
    pool: Dict[str, int] = {}
    for item in old:
        pool[item] = pool.get(item, 0) + 1
    out: List[str] = []
    for item in new:
        if pool.get(item, 0) > 0:
            pool[item] -= 1
        else:
            out.append(item)
    return out


def _lines(items: List[str], limit: int = 8, width: int = 200) -> str:
    shown = ["    " + (i if len(i) <= width else i[: width - 1] + "…") for i in items[:limit]]
    if len(items) > limit:
        shown.append("    … and %d more" % (len(items) - limit))
    return "\n".join(shown)


def _is_nologin(shell: str) -> bool:
    return shell == "" or os.path.basename(shell) in ("nologin", "false")


class Auditor:
    """Runs delta analysis between a loaded baseline document and the live system."""

    def __init__(
        self,
        baseline: Dict[str, Any],
        integrity_status: str = "not verified",
        live_state: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            self.baseline_meta = baseline["meta"]
            self._base = baseline["state"]
            self.config = ScanConfig.from_dict(self.baseline_meta["scan_config"])
        except (KeyError, TypeError, ConfigError) as exc:
            raise BaselineError("baseline is malformed: %s" % exc)
        self.integrity_status = integrity_status
        self._live_override = live_state
        self._findings: List[Finding] = []
        self._skip_dirs: set = set()
        self._critical_core = {self.config.passwd, self.config.shadow}

    # ------------------------------------------------------------------ API
    def run(self) -> AuditResult:
        started = utc_now_iso()
        live = self._live_override if self._live_override is not None else collect_state(self.config)
        self._findings = []
        base_err = self._base.get("listing_errors") or {}
        live_err = live.get("listing_errors") or {}
        self._skip_dirs = set(base_err) | set(live_err)

        self._check_context(live, base_err, live_err)
        self._diff_files("core", self._base.get("core_files"), live.get("core_files"))
        self._diff_accounts(self._base.get("accounts"), live.get("accounts"))
        self._diff_files(
            "sudoers", self._base.get("sudoers"), live.get("sudoers"), on_modified=self._sudoers_modified
        )
        self._diff_ssh(self._base.get("ssh") or {}, live.get("ssh") or {})
        self._diff_files(
            "cron", self._base.get("cron"), live.get("cron"),
            on_modified=self._cron_modified, on_added=self._cron_added,
        )
        self._diff_suid(self._base.get("suid_sgid"), live.get("suid_sgid"))
        self._diff_files("extra", self._base.get("extra_files"), live.get("extra_files"))

        self._findings.sort(key=lambda f: (-severity_rank(f.severity), f.category, f.path or ""))
        for index, finding in enumerate(self._findings, start=1):
            finding.id = "SD-%04d" % index
        return AuditResult(
            findings=self._findings,
            started_utc=started,
            finished_utc=utc_now_iso(),
            baseline_meta=self.baseline_meta,
            live_host=host_info(),
            integrity=self.integrity_status,
        )

    # -------------------------------------------------------------- helpers
    def _add(self, severity: str, category: str, title: str, path: Optional[str] = None,
             detail: str = "", baseline: Any = None, live: Any = None) -> None:
        recommendation = _RECOMMENDATIONS.get(category) or _RECOMMENDATIONS.get(category.rsplit("_", 1)[-1], "")
        self._findings.append(Finding(severity, category, title, path, detail, baseline, live, recommendation))

    def _sev(self, area: str, kind: str, path: str) -> str:
        if area == "core" and path in self._critical_core and kind in ("modified", "removed"):
            return "critical"
        return _AREA_SEVERITY[area][kind]

    def _visible(self, records: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {p: r for p, r in (records or {}).items() if os.path.dirname(p) not in self._skip_dirs}

    def _check_context(self, live: Dict[str, Any], base_err: Dict[str, str], live_err: Dict[str, str]) -> None:
        base_host = (self.baseline_meta.get("host") or {})
        live_host = host_info()
        if base_host.get("hostname") and base_host.get("hostname") != live_host["hostname"]:
            self._add("low", "BASELINE_CONTEXT", "Baseline was captured on a different host",
                      detail="baseline host=%s, this host=%s" % (base_host.get("hostname"), live_host["hostname"]))
        if base_host.get("euid") is not None and base_host.get("euid") != live_host["euid"]:
            self._add("info", "BASELINE_CONTEXT", "Baseline and audit ran with different privileges",
                      detail="baseline euid=%s, audit euid=%s; unreadable files may produce partial results"
                      % (base_host.get("euid"), live_host["euid"]))
        for directory, error in sorted(live_err.items()):
            self._add("medium", "DIRECTORY_UNREADABLE", "Cannot list directory on live system", directory, error)
        for directory in sorted(set(base_err) - set(live_err)):
            self._add("info", "BASELINE_CONTEXT", "Directory was unreadable when the baseline was captured",
                      directory, base_err[directory])
        if self._base.get("suid_scan_error_count") or live.get("suid_scan_error_count"):
            self._add("low", "BASELINE_CONTEXT", "SUID/SGID scan was incomplete",
                      detail="unreadable locations: baseline=%s, live=%s; run as root for full coverage"
                      % (self._base.get("suid_scan_error_count", 0), live.get("suid_scan_error_count", 0)))

    # ------------------------------------------------------- file comparison
    def _diff_files(self, area: str, base_map: Optional[Dict[str, Any]], live_map: Optional[Dict[str, Any]],
                    on_modified: Optional[Callable[[str, Dict, Dict], bool]] = None,
                    on_added: Optional[Callable[[str, Dict], bool]] = None) -> None:
        base_map, live_map = self._visible(base_map), self._visible(live_map)
        prefix = _AREA_PREFIX[area]
        for path in sorted(set(base_map) | set(live_map)):
            b = base_map.get(path) or {"exists": False}
            l = live_map.get(path) or {"exists": False}
            b_ex, l_ex = b.get("exists"), l.get("exists")
            if l_ex is None:
                if b_ex is not None:
                    self._add("medium", prefix + "_UNREADABLE", "Cannot inspect file on live system",
                              path, l.get("error", ""))
                continue
            if b_ex is None or (not b_ex and not l_ex):
                continue
            if not b_ex:
                if on_added and on_added(path, l):
                    continue
                self._add(self._sev(area, "added", path), prefix + "_ADDED", "New file appeared", path,
                          "mode %s, owner uid=%s gid=%s" % (l.get("mode"), l.get("uid"), l.get("gid")),
                          live={"sha256": l.get("sha256")})
                continue
            if not l_ex:
                self._add(self._sev(area, "removed", path), prefix + "_REMOVED", "File was removed", path,
                          "present in baseline, missing on live system", baseline={"sha256": b.get("sha256")})
                continue
            self._compare_existing(area, prefix, path, b, l, on_modified)

    def _compare_existing(self, area: str, prefix: str, path: str, b: Dict, l: Dict,
                          on_modified: Optional[Callable[[str, Dict, Dict], bool]]) -> None:
        old_kind = (b.get("type"), bool(b.get("symlink")), b.get("link_target"))
        new_kind = (l.get("type"), bool(l.get("symlink")), l.get("link_target"))
        if old_kind != new_kind:
            self._add("critical" if area in ("core", "sudoers") else "high", prefix + "_TYPE_CHANGED",
                      "File type or symlink target changed", path,
                      "%s -> %s" % (old_kind, new_kind), baseline=old_kind, live=new_kind)
            return
        old_hash, new_hash = b.get("sha256"), l.get("sha256")
        if old_hash and not new_hash and l.get("hash_error"):
            self._add("medium", prefix + "_UNREADABLE", "Cannot read file content to verify its hash",
                      path, l["hash_error"])
        elif old_hash and new_hash and old_hash != new_hash:
            if not (on_modified and on_modified(path, b, l)):
                self._add(self._sev(area, "modified", path), prefix + "_MODIFIED",
                          "File content modified (SHA-256 mismatch)", path,
                          "%s… -> %s…" % (old_hash[:16], new_hash[:16]),
                          baseline={"sha256": old_hash}, live={"sha256": new_hash})
        self._check_permissions(area, prefix, path, b, l)

    def _check_permissions(self, area: str, prefix: str, path: str, b: Dict, l: Dict) -> None:
        bm, lm = mode_int(b), mode_int(l)
        if bm is None or lm is None:
            return
        changes: List[str] = []
        severity = "low"
        if bm != lm:
            changes.append("mode %s -> %s" % (b["mode"], l["mode"]))
            added = lm & ~bm
            if added:
                severity = "high"
            if area in ("core", "sudoers") and added & 0o007:
                severity = "critical"
            if lm & stat.S_IWOTH:
                severity = "critical"
            if lm & (stat.S_ISUID | stat.S_ISGID) and not bm & (stat.S_ISUID | stat.S_ISGID) and area != "suid":
                severity = "critical"
        if (b.get("uid"), b.get("gid")) != (l.get("uid"), l.get("gid")):
            changes.append("owner uid:gid %s:%s -> %s:%s" % (b.get("uid"), b.get("gid"), l.get("uid"), l.get("gid")))
            owner_sev = "critical" if area in ("core", "sudoers") and l.get("uid") != 0 else "high"
            severity = _max_severity(severity, owner_sev)
        if changes:
            self._add(severity, "PERMISSIONS_CHANGED", "Permissions or ownership changed", path,
                      "; ".join(changes), baseline={"mode": b.get("mode"), "uid": b.get("uid"), "gid": b.get("gid")},
                      live={"mode": l.get("mode"), "uid": l.get("uid"), "gid": l.get("gid")})
            return
        insecure = self._insecure_mode(area, path, lm)
        if insecure:
            self._add(insecure[0], "INSECURE_PERMISSIONS", insecure[1], path,
                      "mode %s (unchanged since baseline, but unsafe)" % l["mode"], live={"mode": l["mode"]})

    def _insecure_mode(self, area: str, path: str, mode: int) -> Optional[tuple]:
        if area == "suid":
            return ("critical", "SUID/SGID binary is world-writable") if mode & 0o002 else None
        if area == "core":
            if path == self.config.shadow:
                if mode & 0o027:
                    return ("critical", "Password hash file readable by others or writable by group")
            elif mode & 0o022:
                return ("critical", "Identity file writable by group/others")
        elif area == "sudoers" and mode & 0o022:
            return ("critical", "sudoers file writable by group/others")
        elif area in ("ssh", "cron") and mode & 0o022:
            return ("high", "Configuration file writable by group/others")
        elif area == "extra" and mode & 0o002:
            return ("high", "File is world-writable")
        return None

    # ------------------------------------------------------------- accounts
    def _diff_accounts(self, base: Optional[Dict], live: Optional[Dict]) -> None:
        if base is None or live is None:
            return
        for name in sorted(set(base) | set(live)):
            b, l = base.get(name), live.get(name)
            if l and not b:
                if l["uid"] == 0:
                    severity = "critical"
                elif _is_nologin(l["shell"]):
                    severity = "medium"
                else:
                    severity = "high"
                self._add(severity, "ACCOUNT_ADDED", "New account in /etc/passwd", self.config.passwd,
                          "%s uid=%s gid=%s home=%s shell=%s" % (name, l["uid"], l["gid"], l["home"], l["shell"]),
                          live=l)
            elif b and not l:
                self._add("medium", "ACCOUNT_REMOVED", "Account removed from /etc/passwd", self.config.passwd,
                          name, baseline=b)
            else:
                changes, severity = [], "low"
                if b["uid"] != l["uid"]:
                    changes.append("uid %s -> %s" % (b["uid"], l["uid"]))
                    severity = "critical" if l["uid"] == 0 else "high"
                if b["gid"] != l["gid"]:
                    changes.append("gid %s -> %s" % (b["gid"], l["gid"]))
                    severity = _max_severity(severity, "medium")
                if b["shell"] != l["shell"]:
                    changes.append("shell %s -> %s" % (b["shell"], l["shell"]))
                    gained = _is_nologin(b["shell"]) and not _is_nologin(l["shell"])
                    severity = _max_severity(severity, "high" if gained else "medium")
                if b["home"] != l["home"]:
                    changes.append("home %s -> %s" % (b["home"], l["home"]))
                    severity = _max_severity(severity, "medium")
                if changes:
                    self._add(severity, "ACCOUNT_MODIFIED", "Account attributes changed", self.config.passwd,
                              "%s: %s" % (name, "; ".join(changes)), baseline=b, live=l)
            if l and b and l["uid"] == 0 and b["uid"] == 0 and name.split("#")[0] != "root":
                self._add("high", "ACCOUNT_UID0_EXTRA", "Non-root account with UID 0", self.config.passwd, name, live=l)

    # -------------------------------------------------------------- sudoers
    def _sudoers_modified(self, path: str, b: Dict, l: Dict) -> bool:
        old, new = b.get("active_lines"), l.get("active_lines")
        if old is None or new is None:
            return False
        added, removed = _multiset_diff(new, old), _multiset_diff(old, new)
        if added:
            severity = "critical" if any(_SUDOERS_DANGEROUS.search(x) for x in added) else "high"
            self._add(severity, "SUDOERS_RULE_ADDED", "sudoers rule(s) added or changed", path, _lines(added),
                      live=added)
        if removed:
            self._add("medium", "SUDOERS_RULE_REMOVED", "sudoers rule(s) removed", path, _lines(removed),
                      baseline=removed)
        if not added and not removed:
            if old != new:
                self._add("medium", "SUDOERS_RULE_REORDERED",
                          "sudoers rules reordered (order is significant: last match wins)", path)
            else:
                self._add("low", "SUDOERS_FILE_MODIFIED", "File changed (comments/whitespace only)", path)
        return True

    # ----------------------------------------------------------------- cron
    def _cron_modified(self, path: str, b: Dict, l: Dict) -> bool:
        if (l.get("kind") or b.get("kind")) != "crontab":
            return False
        old, new = b.get("active_jobs"), l.get("active_jobs")
        if old is None or new is None:
            return False
        added, removed = _multiset_diff(new, old), _multiset_diff(old, new)
        if added:
            suspicious = any(_CRON_SUSPICIOUS.search(x) for x in added)
            self._add("critical" if suspicious else "high", "CRON_JOB_ADDED",
                      "Suspicious cron job added" if suspicious else "Cron job added or changed", path,
                      _lines(added), live=added)
        if removed:
            self._add("medium", "CRON_JOB_REMOVED", "Cron job removed or changed", path, _lines(removed),
                      baseline=removed)
        if not added and not removed:
            self._add("low", "CRON_FILE_MODIFIED", "Cron file changed (comments/whitespace only)", path)
        return True

    def _cron_added(self, path: str, l: Dict) -> bool:
        jobs = l.get("active_jobs") or []
        suspicious = any(_CRON_SUSPICIOUS.search(x) for x in jobs)
        what = "script" if l.get("kind") == "script" else "cron file"
        self._add("critical" if suspicious else "high", "CRON_FILE_ADDED", "New %s appeared" % what, path,
                  _lines(jobs) if jobs else "mode %s" % l.get("mode"), live={"sha256": l.get("sha256")})
        return True

    # ----------------------------------------------------------------- SUID
    def _diff_suid(self, base: Optional[Dict], live: Optional[Dict]) -> None:
        if base is None or live is None:
            return
        for path in sorted(set(base) | set(live)):
            b, l = base.get(path), live.get(path)
            if l and not b:
                bits = "/".join(x for x, on in (("SUID", l.get("suid")), ("SGID", l.get("sgid"))) if on)
                self._add("critical", "SUID_ADDED", "New %s binary appeared" % bits, path,
                          "mode %s uid=%s gid=%s sha256=%s" % (l["mode"], l["uid"], l["gid"],
                                                              (l.get("sha256") or "unreadable")[:16]),
                          live=l)
            elif b and not l:
                self._add("info", "SUID_REMOVED", "SUID/SGID binary gone or no longer privileged", path,
                          "was mode %s" % b["mode"], baseline=b)
            else:
                if b.get("sha256") and l.get("sha256") and b["sha256"] != l["sha256"]:
                    self._add("critical", "SUID_MODIFIED", "SUID/SGID binary content changed", path,
                              "%s… -> %s… (may be a legitimate package update)" % (b["sha256"][:16], l["sha256"][:16]),
                              baseline={"sha256": b["sha256"]}, live={"sha256": l["sha256"]})
                self._check_permissions("suid", "SUID", path, b, l)

    # ------------------------------------------------------------------ SSH
    def _diff_ssh(self, base: Dict[str, Any], live: Dict[str, Any]) -> None:
        self._diff_files("ssh", base.get("files"), live.get("files"))
        if not base.get("parsed") or not live.get("parsed"):
            return
        path = self.config.sshd_config
        bset, lset = base.get("settings") or {}, live.get("settings") or {}
        for key in sorted(set(bset) | set(lset)):
            old, new = bset.get(key), lset.get(key)
            if old == new:
                continue
            kind = "added" if old is None else "removed" if new is None else "changed"
            name = _SSH_CANON.get(key, key)
            self._add(self._ssh_severity(key, old, new), "SSH_SETTING_CHANGED",
                      "sshd setting '%s' %s" % (name, kind), path,
                      "%s: %s -> %s" % (name, old if old is not None else "(unset)",
                                         new if new is not None else "(unset, reverts to default)"),
                      baseline=old, live=new)
        self._diff_match_blocks(path, base.get("match_blocks") or [], live.get("match_blocks") or [])

    @staticmethod
    def _ssh_severity(key: str, old: Optional[List[str]], new: Optional[List[str]]) -> str:
        def effective(values: Optional[List[str]]) -> Optional[str]:
            return values[0].lower() if values else _SSH_DEFAULTS.get(key)

        old_eff, new_eff = effective(old), effective(new)
        if key in _SSH_DEFAULTS and old_eff == new_eff:
            return "low"  # explicit/implicit forms of the same effective value
        if key == "permitrootlogin":
            if _SSH_ROOT_RANK.get(new_eff, 2) > _SSH_ROOT_RANK.get(old_eff, 2):
                return "critical" if new_eff == "yes" else "high"
            return "medium"
        if key in _SSH_YES_IS_WEAKER:
            if new_eff == "yes" and old_eff != "yes":
                return "critical" if key == "permitemptypasswords" else "high"
            return "medium"
        if key == "pubkeyauthentication" and new_eff == "no":
            return "high"
        if key == "loglevel" and new_eff in ("quiet", "fatal", "error"):
            return "high"
        return "low" if key in _SSH_BENIGN_KEYS else "high" if key in _SSH_CANON else "medium"

    def _diff_match_blocks(self, path: str, base: List[Dict], live: List[Dict]) -> None:
        def group(blocks: List[Dict]) -> Dict[str, List[Dict]]:
            out: Dict[str, List[Dict]] = {}
            for block in blocks:
                out.setdefault(block["criteria"], []).append(block["settings"])
            return out

        bgroup, lgroup = group(base), group(live)
        for criteria in sorted(set(bgroup) | set(lgroup)):
            old, new = bgroup.get(criteria), lgroup.get(criteria)
            if old == new:
                continue
            if old is None:
                self._add("high", "SSH_MATCH_BLOCK_CHANGED", "sshd Match block added", path,
                          "Match %s -> %s" % (criteria, new), live=new)
            elif new is None:
                self._add("medium", "SSH_MATCH_BLOCK_CHANGED", "sshd Match block removed", path,
                          "Match %s" % criteria, baseline=old)
            else:
                self._add("high", "SSH_MATCH_BLOCK_CHANGED", "sshd Match block overrides changed", path,
                          "Match %s: %s -> %s" % (criteria, old, new), baseline=old, live=new)
