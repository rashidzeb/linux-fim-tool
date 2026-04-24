# linux-fim-tool
User-space FIM tool for Linux web servers — SHA-256 baseline hashing, command output monitoring, and tamper-evident logs. Lighter than Tripwire and OSSEC. Root-free by design; system-level monitored commands may need sudo.

A lightweight, user-space file integrity monitoring tool for Linux web servers, built as part of MSc Computing research at Bangor University.

---

## What it does

Most file integrity monitoring tools — Tripwire, OSSEC, AIDE — were designed for enterprise environments. They work, but they come with real costs: complex policy files, root or kernel-level access requirements, and alert output that takes genuine expertise to interpret. For a lot of sysadmins managing a single server or a small fleet, that overhead isn't worth it.

This tool takes a different approach. You tell it what to watch, it hashes those files and stores a baseline, and on subsequent runs it tells you what changed. That's it. No daemons, no kernel modules, no elevated privileges — it runs entirely in user space.

Three types of changes are detected and classified:
- **Added** — files that exist now but weren't in the baseline
- **Deleted** — files present at baseline time that have since disappeared  
- **Modified** — files present in both but with mismatched SHA-256 hashes

Beyond file system paths, the tool can also monitor the output of arbitrary shell commands, which turns out to be useful for tracking configuration state — things like `iptables -L`, `crontab -l`, or `ss -tuln` that don't map neatly to a file path.

---

## Design decisions worth knowing about

**SHA-256 over MD5/SHA-1** — MD5 and SHA-1 have known collision weaknesses. SHA-256 is the conservative, well-audited choice. BLAKE3 is faster but hasn't been widely adopted in security tooling yet — deferred to a future version.

**On-demand scanning, not a real-time daemon** — event-driven monitoring with inotify or similar requires persistent processes and tends to generate noise under normal server activity. On-demand scanning is predictable, schedulable via cron, and doesn't sit in memory between runs. The trade-off is intentional.

**User space only, no root required** — kernel-level hooks offer stronger guarantees but they also mean you're modifying the OS to monitor the OS, which introduces its own risks. Everything here runs as a normal user process.

**Atomic writes for baseline files** — baselines are written via a temp file and `os.replace()` to prevent partial writes corrupting the stored state. The baseline file also gets a separate SHA-256 hash file so the tool can verify its own reference data hasn't been tampered with before running a scan.

**Tamper-evident run log** — every baseline save event is appended to a `.jsonl` log with a timestamp and hash. It's not cryptographically signed (that's a future enhancement), but it gives you an audit trail of when baselines were created or updated.

---

## Architecture

The tool is structured as six loosely coupled classes, each handling one thing:

```
ConfigManager       — parses and validates config.yaml
FileSystemMonitor   — walks file system paths, collects hashes and metadata
CommandOutputMonitor — runs commands safely, hashes stdout
BaselineManager     — stores/loads baselines with integrity verification
Comparator          — diffs baseline against current state
ReportManager       — writes JSON report + prints console summary
Orchestrator        — coordinates the above based on CLI command
```

This structure was chosen because it makes individual components testable in isolation and makes it straightforward to extend — for example, swapping in a different hashing algorithm or adding a new output format without touching unrelated code.

---

## Requirements

- Python 3.8+
- PyYAML (`pip install pyyaml`)
- Linux (tested on Fedora 42; should work on any standard distro)
- No root access required

---

## Installation

```bash
git clone https://github.com/rashidzeb/linux-fim-tool.git
cd linux-fim-tool
pip install pyyaml
```

---

## Usage

**Step 1 — write a config file**

```yaml
monitoring_jobs:
  - id: webroot
    type: file_system
    target: /var/www/html
    recursive: true
    ignore_patterns:
      - "*.log"
      - "*.tmp"

  - id: nginx_config
    type: file_system
    target: /etc/nginx/nginx.conf

  - id: open_ports
    type: command_output
    target: "ss -tuln"
    timeout: 10
```

**Step 2 — create a baseline**

```bash
python3 fim_tool.py init --config config.yaml
```

This scans all configured targets and stores the current state as the reference baseline.

**Step 3 — run a scan**

```bash
python3 fim_tool.py scan --config config.yaml
```

Output on the console looks like:

```
Changes detected:
- [new_item_detected] job=webroot obj=/var/www/html/shell.php
- [hash_mismatch]     job=nginx_config obj=/etc/nginx/nginx.conf
- [hash_mismatch]     job=open_ports obj=open_ports
```

A full JSON report is also written to `~/.change_detect/report.json` for integration with other tooling or log shipping.

**Exit codes** follow a scriptable convention:
- `0` — no changes detected
- `1` — changes found
- `2` — operational error (config problem, baseline integrity failure, etc.)

This makes it straightforward to wire into cron jobs or CI/CD pipelines.

---

## Automating with cron

To run a scan every hour and log output:

```bash
0 * * * * python3 /path/to/fim_tool.py scan --config /path/to/config.yaml >> /var/log/fim.log 2>&1
```

---

## Compared to Tripwire and OSSEC

| | linux-fim-tool | Tripwire | OSSEC |
|---|---|---|---|
| Root required | No | Yes | Yes |
| Setup time | ~2 min | ~10 min | ~15 min |
| Config complexity | Low (YAML) | High (policy files) | High (agent config) |
| Real-time monitoring | No | No | Yes |
| Command output monitoring | Yes | No | No |
| User space only | Yes | No | No |

The missing row is real-time monitoring — that's a deliberate scope decision for this version, not an oversight. Continuous monitoring with acceptable resource overhead on production systems is an open problem, and solving it properly (likely with adaptive scheduling and lightweight ML-based anomaly classification) is where this work points next.

---

## Known limitations

- Single-threaded — scanning very large file systems is slower than it could be with parallel hashing
- No remote baseline storage — the baseline lives locally, so an attacker with write access to the state directory could tamper with it. GPG signing and remote storage are the obvious next steps.
- Permission change detection accuracy degrades slightly in edge cases involving symlinks and special file types
- No real-time / inotify-based monitoring in this version

---

## Research context

This tool was developed as an MSc individual project at Bangor University (2025-26), supervised by Dr Cameron Gray. The research question was whether a user-centric, user-space approach to file integrity monitoring is practically viable for Linux web server environments — the answer, based on comparative testing against Tripwire and OSSEC, is yes, with the trade-offs documented above.

The work identified two open research problems that this prototype deliberately doesn't solve: real-time continuous monitoring under resource constraints, and intelligent classification of whether a detected change is suspicious or routine. Those are the directions this project is heading.

---

## Future work

- Adaptive or scheduled scanning based on file sensitivity classification
- inotify integration for near-real-time detection with resource budgeting
- ML-based anomaly classification to distinguish routine changes from suspicious ones
- GPG-signed baselines and remote baseline storage
- Container and Kubernetes pod monitoring extension
- Multi-host deployment with centralised reporting

---

## License

MIT
