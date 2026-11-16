"""Golden Baseline engine: capture, sign, save and load system state snapshots."""

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import json
import logging
import os
import platform
import socket
import stat
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List, Optional, Tuple

import yaml
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as c_hmac

from . import TOOL_NAME, __version__
from .errors import BaselineError, ConfigError, IntegrityError
from .sshd import parse_sshd_config
from .utils import (
    decode_bytes,
    inspect_path,
    list_directory_files,
    parse_active_lines,
    parse_passwd,
    scan_suid_sgid,
    utc_now_iso,
)

LOG = logging.getLogger("sysdrift")
SCHEMA_VERSION = 1
KEY_ENV_VAR = "SYSDRIFT_KEY"
MIN_KEY_BYTES = 16

DEFAULT_SUID_EXCLUDES = ["/proc", "/sys", "/dev", "/run"]


@dataclass
class ScanConfig:
    """Which targets are captured. Stored inside the baseline so audits match."""

    passwd: str = "/etc/passwd"
    group: str = "/etc/group"
    shadow: str = "/etc/shadow"
    sudoers: str = "/etc/sudoers"
    sudoers_dir: str = "/etc/sudoers.d"
    sshd_config: str = "/etc/ssh/sshd_config"
    cron_files: List[str] = field(default_factory=lambda: ["/etc/crontab", "/etc/anacrontab"])
    cron_policy_files: List[str] = field(
        default_factory=lambda: ["/etc/cron.allow", "/etc/cron.deny", "/etc/at.allow", "/etc/at.deny"]
    )
    cron_tab_dirs: List[str] = field(
        default_factory=lambda: ["/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"]
    )
    cron_script_dirs: List[str] = field(
        default_factory=lambda: ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]
    )
    scan_suid: bool = True
    suid_roots: List[str] = field(default_factory=lambda: ["/"])
    suid_exclude: List[str] = field(default_factory=lambda: list(DEFAULT_SUID_EXCLUDES))
    extra_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Any) -> "ScanConfig":
        if not isinstance(data, dict):
            raise ConfigError("scan configuration must be a mapping")
        known = {f.name: f for f in fields(cls)}
        unknown = sorted(set(data) - set(known))
        if unknown:
            raise ConfigError("unknown configuration key(s): %s" % ", ".join(unknown))
        for name, value in data.items():
            if name == "scan_suid":
                if not isinstance(value, bool):
                    raise ConfigError("'scan_suid' must be true or false")
            elif name in ("passwd", "group", "shadow", "sudoers", "sudoers_dir", "sshd_config"):
                if not isinstance(value, str) or not value:
                    raise ConfigError("'%s' must be a non-empty string" % name)
            else:
                if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                    raise ConfigError("'%s' must be a list of non-empty strings" % name)
        return cls(**data)

    @classmethod
    def from_yaml(cls, path: str) -> "ScanConfig":
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        except OSError as exc:
            raise ConfigError("cannot read config %s: %s" % (path, exc.strerror or exc))
        except yaml.YAMLError as exc:
            raise ConfigError("invalid YAML in %s: %s" % (path, exc))
        return cls.from_dict(data or {})


def host_info() -> Dict[str, Any]:
    """Describe the machine and the privilege level of the current run."""
    os_name = ""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:
        pass
    return {
        "hostname": socket.gethostname(),
        "os": os_name,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
    }


def _record_warnings(label: str, records: Dict[str, Dict[str, Any]], out: List[str]) -> None:
    for path, rec in records.items():
        if rec.get("exists") is None:
            out.append("%s: cannot access %s (%s)" % (label, path, rec.get("error", "unknown error")))
        elif rec.get("hash_error"):
            out.append("%s: cannot read %s (%s)" % (label, path, rec["hash_error"]))


def collect_state(config: ScanConfig) -> Dict[str, Any]:
    """Capture the current state of every target described by *config*."""
    warnings: List[str] = []
    listing_errors: Dict[str, str] = {}

    # --- core identity files -------------------------------------------------
    core: Dict[str, Dict[str, Any]] = {}
    passwd_rec, passwd_data = inspect_path(config.passwd, True, True)
    core[config.passwd] = passwd_rec
    accounts = parse_passwd(decode_bytes(passwd_data)) if passwd_data is not None else None
    core[config.group] = inspect_path(config.group)[0]
    # /etc/shadow: existence and permissions only; its content is never read.
    core[config.shadow] = inspect_path(config.shadow, hash_content=False)[0]
    _record_warnings("core", core, warnings)

    # --- sudoers -------------------------------------------------------------
    sudoers: Dict[str, Dict[str, Any]] = {}
    drop_ins, err = list_directory_files(config.sudoers_dir)
    if err:
        listing_errors[config.sudoers_dir] = err
        warnings.append("sudoers: " + err)
    for path in [config.sudoers] + drop_ins:
        rec, data = inspect_path(path, True, True)
        if data is not None:
            rec["active_lines"] = parse_active_lines(decode_bytes(data), sudoers=True)
        sudoers[path] = rec
    _record_warnings("sudoers", sudoers, warnings)

    # --- sshd ----------------------------------------------------------------
    parsed = parse_sshd_config(config.sshd_config)
    ssh_files = {p: inspect_path(p)[0] for p in parsed["files"]}
    _record_warnings("ssh", ssh_files, warnings)
    ssh = {
        "files": ssh_files,
        "settings": parsed["settings"],
        "match_blocks": parsed["match_blocks"],
        "parsed": parsed["parsed"],
        "errors": parsed["errors"],
    }

    # --- cron ----------------------------------------------------------------
    cron: Dict[str, Dict[str, Any]] = {}

    def add_cron(path: str, kind: str) -> None:
        rec, data = inspect_path(path, True, kind == "crontab")
        rec["kind"] = kind
        if kind == "crontab" and data is not None:
            rec["active_jobs"] = parse_active_lines(decode_bytes(data))
        cron[path] = rec

    for path in config.cron_files:
        add_cron(path, "crontab")
    for path in config.cron_policy_files:
        add_cron(path, "policy")
    for directory, kind in [(d, "crontab") for d in config.cron_tab_dirs] + [
        (d, "script") for d in config.cron_script_dirs
    ]:
        entries, err = list_directory_files(directory)
        if err:
            listing_errors[directory] = err
            warnings.append("cron: " + err)
        for path in entries:
            add_cron(path, kind)
    _record_warnings("cron", cron, warnings)

    # --- SUID / SGID ---------------------------------------------------------
    suid: Optional[Dict[str, Dict[str, Any]]] = None
    suid_error_count = 0
    suid_samples: List[str] = []
    if config.scan_suid:
        suid, suid_error_count, suid_samples = scan_suid_sgid(config.suid_roots, config.suid_exclude)
        if suid_error_count:
            warnings.append("suid: %d unreadable location(s) during scan" % suid_error_count)

    # --- user supplied extras ------------------------------------------------
    extra = {p: inspect_path(p)[0] for p in config.extra_files}
    _record_warnings("extra", extra, warnings)

    return {
        "core_files": core,
        "accounts": accounts,
        "sudoers": sudoers,
        "ssh": ssh,
        "cron": cron,
        "suid_sgid": suid,
        "extra_files": extra,
        "listing_errors": listing_errors,
        "suid_scan_error_count": suid_error_count,
        "suid_scan_error_samples": suid_samples,
        "warnings": warnings,
    }


# --------------------------------------------------------------------------- #
# Integrity: HMAC-SHA256 when a key is supplied, plain SHA-256 otherwise.
# --------------------------------------------------------------------------- #
def _canonical(meta: Dict[str, Any], state: Dict[str, Any]) -> bytes:
    return json.dumps({"meta": meta, "state": state}, sort_keys=True, separators=(",", ":")).encode("ascii")


def _compute_integrity(meta: Dict[str, Any], state: Dict[str, Any], key: Optional[bytes]) -> Dict[str, Any]:
    payload = _canonical(meta, state)
    if key is None:
        return {
            "algorithm": "SHA-256",
            "authenticated": False,
            "digest": hashlib.sha256(payload).hexdigest(),
        }
    mac = c_hmac.HMAC(key, hashes.SHA256())
    mac.update(payload)
    return {"algorithm": "HMAC-SHA256", "authenticated": True, "digest": mac.finalize().hex()}


def load_key(key_file: Optional[str] = None) -> Optional[bytes]:
    """Load the signing key from *key_file* or ``$SYSDRIFT_KEY`` (``None`` if neither)."""
    material: Optional[bytes] = None
    if key_file:
        try:
            st = os.stat(key_file)
            with open(key_file, "rb") as handle:
                material = handle.read().strip()
        except OSError as exc:
            raise BaselineError("cannot read key file %s: %s" % (key_file, exc.strerror or exc))
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            LOG.warning("key file %s is accessible by group/others; run: chmod 600 %s", key_file, key_file)
    elif os.environ.get(KEY_ENV_VAR):
        material = os.environ[KEY_ENV_VAR].strip().encode("utf-8")
    if material is None:
        return None
    if len(material) < MIN_KEY_BYTES:
        raise BaselineError("signing key must be at least %d bytes long" % MIN_KEY_BYTES)
    return material


def build_baseline(config: ScanConfig, key: Optional[bytes] = None) -> Dict[str, Any]:
    """Capture the system now and return the complete, signed baseline document."""
    state = collect_state(config)
    meta = {
        "tool": TOOL_NAME,
        "tool_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "created_utc": utc_now_iso(),
        "host": host_info(),
        "scan_config": config.to_dict(),
    }
    return {"meta": meta, "state": state, "integrity": _compute_integrity(meta, state, key)}


def save_baseline(document: Dict[str, Any], path: str, force: bool = False) -> None:
    """Atomically write *document* to *path* with mode 0600."""
    if os.path.lexists(path) and not force:
        raise BaselineError("%s already exists (use --force to overwrite)" % path)
    directory = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        tmp = os.path.join(directory, ".%s.tmp.%d" % (os.path.basename(path), os.getpid()))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                json.dump(document, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise BaselineError("cannot write baseline %s: %s" % (path, exc.strerror or exc))


def load_baseline(path: str, key: Optional[bytes] = None) -> Tuple[Dict[str, Any], str]:
    """Load and verify a baseline. Returns ``(document, integrity_description)``."""
    try:
        st = os.stat(path)
        with open(path, "r", encoding="ascii") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        raise BaselineError("baseline not found: %s" % path)
    except OSError as exc:
        raise BaselineError("cannot read baseline %s: %s" % (path, exc.strerror or exc))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BaselineError("baseline %s is not valid JSON: %s" % (path, exc))
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        LOG.warning("baseline %s is writable by group/others", path)

    if not isinstance(document, dict) or not all(k in document for k in ("meta", "state", "integrity")):
        raise BaselineError("baseline %s is missing required sections" % path)
    meta, state, integrity = document["meta"], document["state"], document["integrity"]
    if not isinstance(meta, dict) or meta.get("tool") != TOOL_NAME:
        raise BaselineError("%s is not a %s baseline" % (path, TOOL_NAME))
    version = meta.get("schema_version")
    if not isinstance(version, int) or version > SCHEMA_VERSION:
        raise BaselineError("unsupported baseline schema version: %r" % (version,))
    if not isinstance(state, dict) or not isinstance(integrity, dict):
        raise BaselineError("baseline %s is malformed" % path)

    authenticated = bool(integrity.get("authenticated"))
    if authenticated and key is None:
        raise IntegrityError("baseline is HMAC-signed: supply --key-file or $%s" % KEY_ENV_VAR)
    if not authenticated and key is not None:
        raise IntegrityError(
            "a key was supplied but the baseline is NOT signed; it may have been replaced by an attacker"
        )
    expected = _compute_integrity(meta, state, key if authenticated else None)
    if not stdlib_hmac.compare_digest(str(integrity.get("digest", "")), expected["digest"]):
        if authenticated:
            raise IntegrityError("baseline signature mismatch: file was tampered with or the key is wrong")
        raise IntegrityError("baseline checksum mismatch: file was modified after creation")
    if authenticated:
        return document, "verified (HMAC-SHA256, authenticated)"
    return document, "checksum verified (unsigned SHA-256: detects corruption only, not forgery)"
