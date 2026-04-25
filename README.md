# linux-fim-tool

A lightweight, user-space file integrity monitoring tool for Linux web servers, written in Python. No root required for the tool itself, no daemons, no kernel modules.

This started as my MSc individual project at Bangor University and turned into something I think is genuinely useful beyond the academic context. The motivation was simple: existing FIM tools like Tripwire and OSSEC are powerful but carry a lot of operational weight that doesn't make sense for smaller deployments.

---

## The problem

Most sysadmins managing a Linux web server don't need an enterprise-grade intrusion detection suite. They need to know: did anything change? Was it supposed to? Tripwire answers that question, but it takes the better part of an hour to configure, requires root, and produces reports that take real expertise to read. OSSEC is even heavier.

This tool does the same core job with a YAML config file and two commands. You tell it what to watch, it hashes everything and stores a baseline, and on the next run it tells you exactly what changed.

---

## What gets detected

Three change types are classified:

- **Added** - something present now that wasn't in the baseline
- **Deleted** - something in the baseline that's no longer there
- **Modified** - content that exists in both but the SHA-256 hash no longer matches

Beyond file system paths, the tool supports monitoring command outputs directly. If you want to know whether your open ports changed, or whether someone modified the crontab, you configure `ss -tuln` or `crontab -l` as a monitored target and it'll flag any difference from the baseline output. This turned out to be one of the more useful features in practice, since a lot of meaningful system state doesn't live in a single file.

---

## Design decisions

**SHA-256 over MD5 or SHA-1**: MD5 has been broken since 2004 and SHA-1 had its first practical collision in 2017. SHA-256 is secure, FIPS-approved, and supported natively in Python's standard library without extra dependencies. BLAKE3 is faster and looks promising, but hasn't been widely adopted in security tooling yet and lacks the audit history that matters in a security context. It's the obvious candidate for a future version.

**On-demand scanning instead of a real-time daemon**: Event-driven approaches using inotify require a persistent process and tend to generate noise under normal server load. On-demand scanning is predictable, easy to schedule via cron, and has zero overhead between runs. The trade-off is deliberate. Continuous monitoring with acceptable resource overhead on production systems is actually an unsolved problem at scale, and it's one of the main directions this project is heading.

**User space only**: Kernel-level monitoring frameworks like IMA offer stronger guarantees, but they require kernel modifications and elevated privileges, which introduces risks that often outweigh the benefits in standard web server deployments. Everything here runs as a normal user process.

**Atomic baseline writes**: The baseline is written via a temporary file and `os.replace()` rather than writing directly to the target path. This means a crash or interruption mid-write can't leave a partially written baseline that silently corrupts future scans.

**Self-verifying baseline**: A separate SHA-256 hash file is maintained for the baseline itself. Before any scan, the tool verifies the baseline hasn't been tampered with. Every baseline save is also appended to an append-only run log in JSONL format, giving you an audit trail of when baselines were created or updated.

**Command sandboxing**: Commands configured for output monitoring are run with a restricted PATH and configurable timeout. stdout is captured and hashed; non-zero exit codes and timeouts are reported as job errors rather than silently failing.

---

## Architecture

The tool is structured around six classes, each with a single responsibility:

```
ConfigManager        - parses and validates config.yaml at startup
FileSystemMonitor    - walks configured paths, records hashes and metadata
CommandOutputMonitor - runs commands safely, hashes stdout
BaselineManager      - handles baseline persistence and integrity verification
Comparator           - diffs current state against the stored baseline
ReportManager        - writes JSON report and prints the console summary
Orchestrator         - coordinates everything based on the CLI command
```

The modular structure makes components independently testable and means future extensions (different hash algorithms, new output formats, remote baseline storage) don't require touching unrelated code.

---

## Requirements

- Python 3.8+
- PyYAML: `pip install pyyaml`
- Linux (developed on Fedora 42, should work on any standard distro)
- No root needed for the tool itself; some commands you choose to monitor may require sudo

---

## Installation

```bash
git clone https://github.com/rashidzeb/linux-fim-tool.git
cd linux-fim-tool
pip install pyyaml
```

---

## Usage

Write a config file:

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

Create a baseline:

```bash
python3 fim_tool.py init --config config.yaml
```

Run a scan:

```bash
python3 fim_tool.py scan --config config.yaml
```

Console output:

```
Changes detected:
- [new_item_detected] job=webroot obj=/var/www/html/shell.php
- [hash_mismatch]     job=nginx_config obj=/etc/nginx/nginx.conf
- [hash_mismatch]     job=open_ports obj=open_ports
```

A full JSON report is written to `~/.change_detect/report.json` for downstream processing or log shipping to a SIEM.

Exit codes follow a scriptable convention:

- `0` - no changes detected
- `1` - changes found
- `2` - operational error (bad config, baseline integrity failure, etc.)

---

## Scheduling with cron

```bash
0 * * * * python3 /path/to/fim_tool.py scan --config /path/to/config.yaml >> /var/log/fim.log 2>&1
```

---

## Comparison with Tripwire and OSSEC

| | linux-fim-tool | Tripwire | OSSEC |
|---|---|---|---|
| Root required | No* | Yes | Yes |
| Setup time | ~2 min | ~10 min | ~15 min |
| Config complexity | Low (YAML) | High (policy files) | High (agent config) |
| Real-time monitoring | No | No | Yes |
| Command output monitoring | Yes | No | No |
| User space only | Yes | No | No |

*The tool itself doesn't need root. Commands you configure it to monitor might.

---

## Known limitations

- Single-threaded hashing means performance on very large file systems is bounded. Parallel hashing is a straightforward future extension.
- The baseline is stored locally. An attacker with write access to the state directory could tamper with it. GPG-signed baselines and remote storage are the obvious next steps.
- Permission change detection has minor accuracy issues in edge cases around symlinks and special file types.
- No real-time monitoring in this version.

---

## What's next

The two open problems this prototype deliberately doesn't solve are the main directions for future work:

- **Continuous monitoring under resource constraints**: inotify-based detection with adaptive resource budgeting, so the tool can run on production systems without degrading performance
- **Intelligent change classification**: lightweight ML-based anomaly detection to distinguish suspicious changes from routine administrative activity, rather than leaving all triage to the sysadmin
- GPG-signed baselines and remote baseline storage
- Multi-host deployment with centralised reporting
- Container and Kubernetes pod monitoring

---

## Research context

Built as an MSc individual project at Bangor University (2025-26), supervised by Dr Cameron Gray. The dissertation benchmarked this tool against Tripwire and OSSEC across three scale scenarios (100, 5,000, and 50,000 files) and evaluated detection accuracy, resource usage, and usability. The core finding was that a user-space, on-demand approach is practically viable for Linux web server environments, and that the two unsolved problems above are the right targets for follow-on research.

---

## License

MIT
