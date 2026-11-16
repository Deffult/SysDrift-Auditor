# SysDrift Auditor

Golden-baseline configuration drift detection for Linux.
Author: **Ahmed A. Ahmed** (Mr. Deffult) | Contact: mrdffult@gmail.com - License: MIT

```bash
pip install .                       # or: pip install -r requirements.txt
sudo sysdrift keygen -o /root/sysdrift.key
sudo sysdrift init   --output baseline.json --key-file /root/sysdrift.key
sudo sysdrift audit  --baseline baseline.json --key-file /root/sysdrift.key
sudo sysdrift report --baseline baseline.json --key-file /root/sysdrift.key --format json
```

Exit codes: `0` clean, `1` drift found, `2` error, `3` baseline integrity failure.

Tracked: `/etc/passwd`, `/etc/group`, `/etc/shadow` (existence/permissions only, content never read),
`/etc/sudoers` + `sudoers.d`, `sshd_config` (+ Includes, parsed per directive and Match block),
SUID/SGID binaries, cron files and active jobs.

Full Arabic technical manual: [`docs/MANUAL_AR.md`](docs/MANUAL_AR.md).
Run tests: `python -m unittest discover -s tests -v`
