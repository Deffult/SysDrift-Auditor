"""Command line interface: sysdrift init | audit | report | keygen."""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import sys
from typing import List, Optional

from . import __alias__, __author__, __version__
from .auditor import SEVERITIES, Auditor
from .baseline import (
    ScanConfig,
    build_baseline,
    load_baseline,
    load_key,
    save_baseline,
)
from .errors import BaselineError, IntegrityError, SysDriftError
from .report import FORMATS, build_report, render

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2
EXIT_INTEGRITY = 3


def _warn_unprivileged() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "warning: not running as root; protected files (e.g. /etc/sudoers) and some "
            "directories cannot be read, so results will be incomplete.",
            file=sys.stderr,
        )


def _write_output(text: str, path: Optional[str]) -> None:
    if not path:
        sys.stdout.write(text)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace") as handle:
        handle.write(text)
    print("Report written to %s" % path, file=sys.stderr)


def cmd_init(args: argparse.Namespace) -> int:
    config = ScanConfig.from_yaml(args.config) if args.config else ScanConfig()
    if args.no_suid_scan:
        config.scan_suid = False
    key = load_key(args.key_file)
    _warn_unprivileged()
    document = build_baseline(config, key)
    save_baseline(document, args.output, force=args.force)

    state = document["state"]
    tracked = (
        len(state["core_files"]) + len(state["sudoers"]) + len(state["ssh"]["files"])
        + len(state["cron"]) + len(state["extra_files"])
    )
    print("Golden baseline created: %s" % args.output)
    print("  Host           : %s" % document["meta"]["host"]["hostname"])
    print("  Tracked files  : %d" % tracked)
    print("  Accounts       : %s" % (len(state["accounts"]) if state["accounts"] is not None else "n/a"))
    print("  SUID/SGID bins : %s" % (len(state["suid_sgid"]) if state["suid_sgid"] is not None else "not scanned"))
    print("  Integrity      : %s" % document["integrity"]["algorithm"])
    if not document["integrity"]["authenticated"]:
        print("  note: baseline is unsigned. Use --key-file (see 'sysdrift keygen') to prevent forgery.")
    for warning in state["warnings"][:10]:
        print("  warning: %s" % warning, file=sys.stderr)
    if len(state["warnings"]) > 10:
        print("  warning: ... %d more" % (len(state["warnings"]) - 10), file=sys.stderr)
    return EXIT_OK


def _run_audit(args: argparse.Namespace, default_format: str, default_fail_on: str) -> int:
    fmt = args.format or default_format
    fail_on = args.fail_on or default_fail_on
    key = load_key(args.key_file)
    document, integrity = load_baseline(args.baseline, key)
    _warn_unprivileged()
    result = Auditor(document, integrity_status=integrity).run()
    report = build_report(result, args.baseline, args.min_severity)
    color = fmt == "text" and not args.output and not args.no_color and sys.stdout.isatty() \
        and "NO_COLOR" not in os.environ
    _write_output(render(report, fmt, color), args.output)
    return EXIT_DRIFT if result.exceeds(fail_on) else EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    return _run_audit(args, "text", "low")


def cmd_report(args: argparse.Namespace) -> int:
    return _run_audit(args, "json", "none")


def cmd_keygen(args: argparse.Namespace) -> int:
    if os.path.lexists(args.output) and not args.force:
        raise BaselineError("%s already exists (use --force to overwrite)" % args.output)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(args.output, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(secrets.token_hex(32) + "\n")
    os.chmod(args.output, 0o600)
    print("Signing key written to %s (mode 0600). Keep it OFF the audited host." % args.output)
    return EXIT_OK


def _add_audit_options(sub: argparse.ArgumentParser, default_format: str, default_fail: str) -> None:
    sub.add_argument("-b", "--baseline", default="baseline.json", help="baseline file (default: baseline.json)")
    sub.add_argument("-k", "--key-file", help="HMAC key file (or set $SYSDRIFT_KEY)")
    sub.add_argument("-f", "--format", choices=FORMATS, help="output format (default: %s)" % default_format)
    sub.add_argument("-o", "--output", help="write the report to this file (mode 0600) instead of stdout")
    sub.add_argument("--min-severity", choices=SEVERITIES, default="info",
                     help="only show findings at or above this severity")
    sub.add_argument("--fail-on", choices=SEVERITIES + ("none",),
                     help="exit 1 if a finding at/above this severity exists (default: %s)" % default_fail)
    sub.add_argument("--no-color", action="store_true", help="disable ANSI colours")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sysdrift",
        description="SysDrift Auditor - golden-baseline configuration drift detection for Linux. "
        "By %s (%s)." % (__author__, __alias__),
        epilog="Exit codes: 0 clean, 1 drift found, 2 error, 3 baseline integrity failure.",
    )
    parser.add_argument("--version", action="version", version="sysdrift-auditor %s" % __version__)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase log verbosity")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    init = sub.add_parser("init", help="capture the golden baseline of this system")
    init.add_argument("-o", "--output", default="baseline.json", help="baseline file to create")
    init.add_argument("-c", "--config", help="YAML file customising scan targets")
    init.add_argument("-k", "--key-file", help="HMAC key file used to sign the baseline (or $SYSDRIFT_KEY)")
    init.add_argument("--force", action="store_true", help="overwrite an existing baseline")
    init.add_argument("--no-suid-scan", action="store_true", help="skip the (slow) SUID/SGID filesystem scan")
    init.set_defaults(func=cmd_init)

    audit = sub.add_parser("audit", help="compare the live system against the baseline")
    _add_audit_options(audit, "text", "low")
    audit.set_defaults(func=cmd_audit)

    report = sub.add_parser("report", help="produce a structured drift report")
    _add_audit_options(report, "json", "none")
    report.set_defaults(func=cmd_report)

    keygen = sub.add_parser("keygen", help="generate a random signing key")
    keygen.add_argument("-o", "--output", required=True, help="key file to create")
    keygen.add_argument("--force", action="store_true", help="overwrite an existing file")
    keygen.set_defaults(func=cmd_keygen)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose > 1 else logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return args.func(args)
    except IntegrityError as exc:
        print("INTEGRITY FAILURE: %s" % exc, file=sys.stderr)
        return EXIT_INTEGRITY
    except SysDriftError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
