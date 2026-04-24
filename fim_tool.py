#!/usr/bin/env python3
from __future__ import annotations
import argparse
import dataclasses
import fnmatch
import hashlib
import json
import os
import stat
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import subprocess

try:
    import yaml  # PyYAML
except Exception as e:
    print("PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    raise

FILE_CHUNK_SIZE = 1024 * 1024  # 1 MiB
DEFAULT_TIMEOUT = 15  # seconds
MAX_STDOUT = 10 * 1024 * 1024  # 10 MiB
RESTRICTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TOOL_VERSION = "2.0.0"


# Utility helpers
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dir_secure(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def write_secure(path: Path, data: bytes):
    # Atomic write: temp file in same dir -> fsync -> rename
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_permissions(mode: int) -> str:
    return format(stat.S_IMODE(mode), "04o")


# Config
@dataclasses.dataclass
class JobConfig:
    id: str
    type: str  # "file_system" or "command_output"
    target: str
    recursive: bool = False
    ignore_patterns: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    timeout_seconds: int = DEFAULT_TIMEOUT


class ConfigManager:
    def __init__(self, path: Path):
        self.path = path
        self.jobs: List[JobConfig] = []

    def load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict) or "monitoring_jobs" not in data:
            raise ValueError("config.yaml must contain a 'monitoring_jobs' list")
        jobs = data["monitoring_jobs"]
        if not isinstance(jobs, list) or not jobs:
            raise ValueError("'monitoring_jobs' must be a non-empty list")
        seen_ids = set()
        parsed: List[JobConfig] = []
        for idx, job in enumerate(jobs):
            if not isinstance(job, dict):
                raise ValueError(f"Job at index {idx} must be a mapping")
            jid = job.get("id")
            jtype = job.get("type")
            target = job.get("target")
            if not (isinstance(jid, str) and jid):
                raise ValueError(f"Job {idx}: 'id' must be a non-empty string")
            if jid in seen_ids:
                raise ValueError(f"Duplicate job id: {jid}")
            seen_ids.add(jid)
            if jtype not in ("file_system", "command_output"):
                raise ValueError(f"Job {jid}: 'type' must be 'file_system' or 'command_output'")
            if not (isinstance(target, str) and target):
                raise ValueError(f"Job {jid}: 'target' must be a non-empty string")
            recursive = bool(job.get("recursive", False))
            ignore_patterns = job.get("ignore_patterns", [])
            if ignore_patterns is None:
                ignore_patterns = []
            if not isinstance(ignore_patterns, list) or not all(isinstance(p, str) for p in ignore_patterns):
                raise ValueError(f"Job {jid}: 'ignore_patterns' must be a list of strings if provided")
            timeout_seconds = int(job.get("timeout", DEFAULT_TIMEOUT)) if jtype == "command_output" else DEFAULT_TIMEOUT
            parsed.append(JobConfig(
                id=jid,
                type=jtype,
                target=target,
                recursive=recursive,
                ignore_patterns=tuple(ignore_patterns),
                timeout_seconds=timeout_seconds,
            ))
        self.jobs = parsed


# Monitors
class Monitor(ABC):
    def __init__(self, job: JobConfig):
        self.job = job

    @abstractmethod
    def collect(self) -> Dict:
        """Return a structure suitable for baseline 'monitoring_data[job.id]'"""
        raise NotImplementedError


class FileSystemMonitor(Monitor):
    def collect(self) -> Dict:
        target = Path(self.job.target)
        result: Dict[str, Dict[str, str]] = {}
        paths: List[Path] = []
        if target.is_dir():
            if not self.job.recursive:
                for child in target.iterdir():
                    if child.is_file() or child.is_symlink():
                        paths.append(child)
            else:
                for root, dirs, files in os.walk(target, followlinks=False):
                    root_path = Path(root)
                    for fname in files:
                        p = root_path / fname
                        paths.append(p)
        elif target.exists():
            paths.append(target)
        else:
            paths = []

        if self.job.ignore_patterns:
            filtered = []
            for p in paths:
                name = str(p)
                if any(fnmatch.fnmatch(name, pat) for pat in self.job.ignore_patterns):
                    continue
                filtered.append(p)
            paths = filtered

        for p in paths:
            try:
                st = os.lstat(p)
                entry: Dict[str, str] = {}
                if stat.S_ISLNK(st.st_mode):
                    target_str = os.readlink(p)
                    entry["type"] = "symlink"
                    entry["link_target"] = target_str
                    entry["hash"] = sha256_bytes(target_str.encode("utf-8", errors="surrogateescape"))
                    entry["permissions"] = normalize_permissions(st.st_mode)
                    entry["mtime"] = str(int(st.st_mtime))
                    entry["size"] = str(st.st_size)
                elif stat.S_ISREG(st.st_mode):
                    entry["type"] = "file"
                    entry["hash"] = self._hash_file(p)
                    entry["permissions"] = normalize_permissions(st.st_mode)
                    entry["mtime"] = str(int(st.st_mtime))
                    entry["size"] = str(st.st_size)
                else:
                    continue
                result[str(p)] = entry
            except FileNotFoundError:
                continue
            except PermissionError:
                result[str(p)] = {"type": "error", "error": "PermissionDenied"}
        return result

    def _hash_file(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb", buffering=FILE_CHUNK_SIZE) as f:
            for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()


class CommandOutputMonitor(Monitor):
    def collect(self) -> Dict:
        cmd_str = self.job.target
        argv = self._split_shell_like(cmd_str)
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["PATH"] = RESTRICTED_PATH
        try:
            cp = subprocess.run(
                argv,
                capture_output=True,
                text=False,
                timeout=self.job.timeout_seconds,
                env=env,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "job_error",
                "error": "CommandTimeout",
                "timeout_seconds": self.job.timeout_seconds,
            }
        except FileNotFoundError:
            return {
                "status": "job_error",
                "error": "CommandNotFound",
            }
        stdout = cp.stdout[:MAX_STDOUT]
        stderr = cp.stderr[:MAX_STDOUT]
        if cp.returncode != 0:
            return {
                "status": "job_error",
                "error": "NonZeroExit",
                "exit_code": cp.returncode,
                "stderr_excerpt": stderr.decode("utf-8", errors="replace")[:1024],
            }
        hashed = sha256_bytes(stdout)
        excerpt = stdout.decode("utf-8", errors="replace")[:256]
        return {
            "status": "ok",
            "hash": hashed,
            "output_excerpt": excerpt,
        }

    @staticmethod
    def _split_shell_like(s: str) -> List[str]:
        import shlex
        return shlex.split(s)


# Baseline and comparison
class BaselineManager:
    def __init__(self, baseline_dir: Path):
        self.dir = baseline_dir
        self.file = self.dir / "baseline.json"
        self.hash_file = self.dir / "baseline.json.sha256"
        self.run_log = self.dir / "run.log.jsonl"

    def load(self) -> Dict:
        if not self.file.exists():
            return {}
        with open(self.file, "rb") as f:
            data = json.load(f)
        expected = (self.hash_file.read_text().strip() if self.hash_file.exists() else "")
        actual = sha256_file(self.file)
        if not expected or expected != actual:
            raise RuntimeError("BaselineIntegrityFailure: baseline hash mismatch or missing")
        return data

    def save(self, data: Dict):
        ensure_dir_secure(self.dir)
        data = dict(data)
        data["timestamp"] = utc_now_iso()
        data["tool_version"] = TOOL_VERSION
        payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        write_secure(self.file, payload)
        h = sha256_file(self.file)
        write_secure(self.hash_file, (h + "\n").encode("ascii"))
        self._append_run_log({
            "timestamp": utc_now_iso(),
            "event": "baseline_saved",
            "file": str(self.file),
            "hash": h,
        })

    def _append_run_log(self, obj: Dict):
        ensure_dir_secure(self.dir)
        line = json.dumps(obj, separators=(",", ":")) + "\n"
        with open(self.run_log, "a", encoding="utf-8") as f:
            f.write(line)
        os.chmod(self.run_log, 0o600)


class Comparator:
    def compare(self, baseline: Dict, current: Dict) -> Tuple[List[Dict], bool]:
        changes: List[Dict] = []
        any_errors = False
        base_jobs: Dict = baseline.get("monitoring_data", {}) if baseline else {}
        curr_jobs: Dict = current.get("monitoring_data", {})
        job_ids = set(base_jobs.keys()) | set(curr_jobs.keys())
        for jid in sorted(job_ids):
            b = base_jobs.get(jid)
            c = curr_jobs.get(jid)
            if b is None and c is not None:
                changes.append(self._record("new_item_detected", jid, "job", jid, None, c))
                continue
            if b is not None and c is None:
                changes.append(self._record("missing_item", jid, "job", jid, b, None))
                continue
            if isinstance(c, dict) and "status" in c:
                if c.get("status") == "job_error":
                    any_errors = True
                    changes.append(self._record("job_error", jid, c.get("error", "Unknown"), jid, None, c))
                else:
                    if b.get("hash") != c.get("hash"):
                        changes.append(self._record("hash_mismatch", jid, "command_output", jid, b, c))
            else:
                bpaths = set(b.keys()) if isinstance(b, dict) else set()
                cpaths = set(c.keys()) if isinstance(c, dict) else set()
                for path in sorted(cpaths - bpaths):
                    changes.append(self._record("new_item_detected", jid, "file", path, None, c[path]))
                for path in sorted(bpaths - cpaths):
                    changes.append(self._record("missing_item", jid, "file", path, b[path], None))
                for path in sorted(bpaths & cpaths):
                    be = b[path]
                    ce = c[path]
                    if be.get("type") != ce.get("type"):
                        changes.append(self._record("hash_mismatch", jid, "file", path, be, ce))
                        continue
                    if be.get("hash") != ce.get("hash"):
                        changes.append(self._record("hash_mismatch", jid, "file", path, be, ce))
                    else:
                        meta_changed = (
                            be.get("permissions") != ce.get("permissions") or
                            be.get("mtime") != ce.get("mtime") or
                            be.get("size") != ce.get("size")
                        )
                        if meta_changed:
                            changes.append(self._record("metadata_change", jid, "file", path, be, ce))
        return changes, any_errors

    @staticmethod
    def _record(typ: str, job_id: str, subtype: str, obj: str, old_state: Optional[Dict], new_state: Optional[Dict]) -> Dict:
        return {
            "timestamp": utc_now_iso(),
            "job_id": job_id,
            "type": typ,
            "subtype": subtype,
            "object": obj,
            "old_state": old_state,
            "new_state": new_state,
        }


# Reporting
class ReportManager:
    def __init__(self, path: Path):
        self.path = path

    def write_json(self, changes: List[Dict]):
        ensure_dir_secure(self.path.parent)
        payload = json.dumps(changes, indent=2).encode("utf-8")
        write_secure(self.path, payload)

    @staticmethod
    def print_console_summary(changes: List[Dict]):
        if not changes:
            print("No changes detected.")
            return
        print("Changes detected:")
        for ch in changes:
            print(f"- [{ch['type']}] job={ch['job_id']} obj={ch['object']}")


# Orchestrator
class ChangeDetectionTool:
    def __init__(self, config: ConfigManager, baseline: BaselineManager, report: Optional[ReportManager] = None):
        self.config = config
        self.baseline = baseline
        self.report = report

    def _collect_all(self) -> Dict:
        monitoring_data: Dict[str, Dict] = {}
        for job in self.config.jobs:
            if job.type == "file_system":
                mon = FileSystemMonitor(job)
            elif job.type == "command_output":
                mon = CommandOutputMonitor(job)
            else:
                continue
            monitoring_data[job.id] = mon.collect()
        return {
            "monitoring_data": monitoring_data,
        }

    def init_baseline(self):
        current = self._collect_all()
        self.baseline.save(current)

    def scan(self) -> Tuple[List[Dict], bool]:
        baseline_data = self.baseline.load()
        current = self._collect_all()
        comp = Comparator()
        return comp.compare(baseline_data, current)


# CLI
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="System Change Detection Tool (MVP)")
    parser.add_argument("command", choices=["init", "scan"], help="init baseline or scan for changes")
    parser.add_argument("--config", required=True, help="Path to config.yaml")
    parser.add_argument("--state-dir", default=str(Path.home() / ".change_detect"), help="Directory to store baseline and logs")
    parser.add_argument("--report", default=str(Path.home() / ".change_detect" / "report.json"), help="Path to write JSON report (scan only)")
    args = parser.parse_args(argv)

    cfg_path = Path(args.config)
    state_dir = Path(args.state_dir)
    rpt_path = Path(args.report)

    try:
        cfg = ConfigManager(cfg_path)
        cfg.load()
    except Exception as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    baseline = BaselineManager(state_dir)
    tool = ChangeDetectionTool(cfg, baseline, ReportManager(rpt_path))

    if args.command == "init":
        try:
            tool.init_baseline()
            print(f"Baseline created at {baseline.file}")
            return 0
        except Exception as e:
            print(f"Failed to create baseline: {e}", file=sys.stderr)
            return 2

    elif args.command == "scan":
        try:
            changes, any_errors = tool.scan()
        except RuntimeError as re:
            print(str(re), file=sys.stderr)
            return 2
        except Exception as e:
            print(f"Scan failed: {e}", file=sys.stderr)
            return 2
        tool.report.write_json(changes)
        ReportManager.print_console_summary(changes)
        if any_errors:
            return 2
        return 1 if changes else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())