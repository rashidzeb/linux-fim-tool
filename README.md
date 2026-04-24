# linux-fim-tool

A lightweight file integrity monitoring tool for Linux web servers. Built in Python, runs entirely in user space, no root needed for the tool itself.

This started as my MSc individual project at Bangor University and grew into something I think is actually useful for anyone running a small Linux server who doesn't want the overhead of Tripwire or OSSEC.

---

## The problem it solves

If you've ever managed a Linux web server, you've probably wondered at some point whether a config file changed, whether something got added to a directory it shouldn't have, or whether a cron job is still outputting what it used to. Existing tools like Tripwire and OSSEC can answer those questions, but they're built for enterprise environments. Getting Tripwire running properly takes the better part of an hour and requires root. OSSEC is even heavier.

This tool does the same core job with a simple YAML config file and two commands. You point it at the files and directories you care about, it hashes them and saves a baseline, and on the next run it tells you what changed.

---

## What gets detected

Three change types are tracked:

- **Added** - something that wasn't there before
- **Deleted** - something that was there and isn't anymore
- **Modified** - something that's still there but the content changed (detected via SHA-256 hash mismatch)

There's also support for monitoring command outputs, not just files. So if you want to know whether your open ports changed, or whether someone touched the crontab, you can monitor `ss -tuln` or `crontab -l` directly and it'll alert if the output differs from the baseline.

---

## Why on-demand and not real-time

The short answer is production servers. Running a persistent daemon that watches for filesystem events via inotify works fine on a development machine, but on a loaded web server it adds constant overhead and generates a lot of noise from normal activity. On-demand scanning is predictable, you can schedule it via cron at whatever frequency makes sense, and it doesn't sit in memory doing anything when you're not using it.

Real-time monitoring under resource constraints is actually an open research problem and something I want to tackle in a future version properly, rather than just shipping a daemon that hammers the server.

---

## Why SHA-256

MD5 and SHA-1 both have known collision vulnerabilities at this point. SHA-256 is the sensible default: it's secure, well-audited, FIPS-approved, and supported natively in Python without any extra dependencies. BLAKE3 is faster but still hasn't been widely adopted in security tooling, so it's on the roadmap for a future version once it's more established.

---

## Architecture

Six classes, each handling one job:

```
ConfigManager        - reads and validates config.yaml
FileSystemMonitor    - walks configured paths, collects hashes and metadata
CommandOutputMonitor - runs commands in a sandboxed environment, hashes stdout
BaselineManager      - saves and loads baselines with tamper detection
Comparator           - diffs the current state against the stored baseline
ReportManager        - writes JSON report and prints console summary
Orchestrator         - ties everything together based on the CLI command
```

Baselines are written atomically using a temp file and `os.replace()` so a crash mid-write can't corrupt your reference state. There's also a separate SHA-256 hash file for the baseline itself, so the tool can verify it hasn't been tampered with before running a scan.

---

## Requirements

- Python 3.8+
- PyYAML: `pip install pyyaml`
- Linux (developed and tested on Fedora 42, should work on any standard distro)
- No root needed for the tool itself; some commands you choose to monitor may need sudo

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

Console output looks like:

```
Changes detected:
- [new_item_detected] job=webroot obj=/var/www/html/shell.php
- [hash_mismatch]     job=nginx_config obj=/etc/nginx/nginx.conf
- [hash_mismatch]     job=open_ports obj=open_ports
```

A full JSON report also gets written to `~/.change_detect/report.json`.

Exit codes are scriptable:
- `0` - nothing changed
- `1` - changes found
- `2` - something went wrong (bad config, baseline integrity failure, etc.)

---

## Running on a schedule

```bash
0 * * * * python3 /path/to/fim_tool.py scan --config /path/to/config.yaml >> /var/log/fim.log 2>&1
```

---

## How it compares to Tripwire and OSSEC

| | linux-fim-tool | Tripwire | OSSEC |
|---|---|---|---|
| Root required | No* | Yes | Yes |
| Setup time | ~2 min | ~10 min | ~15 min |
| Config complexity | Low (YAML) | High (policy files) | High (agent config) |
| Real-time monitoring | No | No | Yes |
| Command output monitoring | Yes | No | No |
| User space only | Yes | No | No |

*The tool itself doesn't need root. Specific commands you configure it to monitor might.

---

## Known limitations

- Single-threaded, so scanning very large file systems is slower than it could be
- Baseline is stored locally, so an attacker with access to the state directory could tamper with it. GPG signing and remote storage are on the roadmap.
- Minor accuracy issues with permission change detection in edge cases around symlinks

---

## What's next

- inotify-based near-real-time monitoring with proper resource budgeting
- ML-based classification to distinguish suspicious changes from routine ones
- GPG-signed baselines
- Remote baseline storage and multi-host support
- Kubernetes and container monitoring extension

---

## Research context

Developed as part of MSc Computing research at Bangor University (2025-26), supervised by Dr Cameron Gray. The dissertation compared this tool against Tripwire and OSSEC across small, medium, and large-scale environments. The core finding was that a user-space, on-demand approach is genuinely viable for Linux web server environments, with the trade-offs around real-time monitoring being the main area for future work.

---

## License

MIT
