#!/usr/bin/env python3
"""
ESF Event Collector for Elasticsearch/Kibana

Runs eslogger and turns each raw event into a flat, Elastic Defend-shaped ECS document
(dotted keys: process.executable, file.path, event.action, ...). Events are keyed on the
eslogger event name (the one key of raw["event"]), never on event numbers. Categories and
field paths come from the macOS plugin taxonomy, the same table the macos_esf_ecs pipeline
is built from, so collected documents and converted rules agree.
"""
import sys
import json
import subprocess
import signal
import os
import socket
import time
import pwd
import random
import importlib.util
from datetime import datetime
from typing import Dict, Any, Optional

# Collectors run under bare python3: load the pure-dataclass taxonomy by path, not through the
# plugin package, whose __init__ imports pySigma.
_spec = importlib.util.spec_from_file_location("coresigma_taxonomy", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "pipelines", "pysigma-pipeline-macos",
    "sigma", "pipelines", "macos", "taxonomy.py"))
_taxonomy = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _taxonomy  # dataclasses look the defining module up in sys.modules
_spec.loader.exec_module(_taxonomy)
ESF_CATEGORIES, ESF_FIELDS = _taxonomy.ESF_CATEGORIES, _taxonomy.ESF_FIELDS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # siblings import under python3 -I too
import outputs  # noqa: E402

# eslogger subscription: every event a category needs, plus process lifecycle
ESLOGGER_EVENTS = sorted({e for c in ESF_CATEGORIES.values() for e in c.events} | {"fork", "exit"})


def _eslogger():
    return ["eslogger"] if os.geteuid() == 0 else ["sudo", "eslogger"]


def _report_skipped(events):
    skipped = [e for e in ESLOGGER_EVENTS if e not in events]
    if skipped:
        print(f"Skipping {len(skipped)} events this macOS release's eslogger doesn't support: {', '.join(skipped)}",
              file=sys.stderr)


def supported_events():
    """ESLOGGER_EVENTS that this macOS release's eslogger lists. eslogger refuses a subscription naming an event the
    system doesn't have (older releases list fewer), so those are skipped and named on stderr."""
    try:
        listed = subprocess.run(_eslogger() + ["--list-events"], capture_output=True, text=True, timeout=60,
                                check=True).stdout.split()
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"eslogger --list-events failed (exit {e.returncode}): {(e.stderr or '').strip()}")
    except (OSError, subprocess.SubprocessError) as e:
        raise SystemExit(f"eslogger --list-events failed: {e}")
    events = [e for e in ESLOGGER_EVENTS if e in set(listed)]
    if not events:
        raise SystemExit("eslogger --list-events lists none of the events the collector subscribes to")
    _report_skipped(events)
    return events

# Event name -> its category's ECS values. Tuple values ("any of") are always event.action,
# which normalize_event already sets to the event name.
EVENT_ECS = {
    event: {k: v for k, v in cat.ecs.items() if not isinstance(v, tuple)}
    for cat in ESF_CATEGORIES.values() for event in cat.events
}


def _get(d: Any, path: str) -> Any:
    """Value at a dotted path in nested dicts, or None."""
    for part in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(part)
    return d


def _field_value(raw: Dict[str, Any], event_name: str, field) -> Any:
    """A taxonomy field's value for this event: the first of its raw paths that is present."""
    paths = field.raw.get(event_name, field.raw.get("*")) or []
    for path in [paths] if isinstance(paths, str) else paths:
        value = _get(raw, path)
        if value is not None:
            if path.endswith(".new_path.filename"):
                # new_path destinations split dir and filename; ECS file.path is the full path
                value = os.path.join(_get(raw, path[:-len("filename")] + "dir.path") or "", value)
            return value
    return None


class ESFCollector:
    """
    Collects and normalizes ESF events for Elasticsearch.

    Output: flat Defend-shaped ECS (process.executable, process.pid, file.path, ...),
    the fields the macos_esf_ecs pipeline maps Sigma rules onto.
    """
    
    ENABLE_FILTERING = True
    
    SECURITY_PATHS = {
        "/Library/LaunchAgents", "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents", "/System/Library/LaunchDaemons",
        "~/Library/LaunchAgents", "/Users/*/Library/LaunchAgents",
        "/Library/StartupItems", "/etc/periodic",
        "/Library/Extensions", "/System/Library/Extensions",
        "/private/etc", "/etc/sudoers", "/etc/pam.d", "/etc/ssh",
        "/Library/Application Support/com.apple.TCC",
        "/Users/*/Library/Application Support/com.apple.TCC",
        "/var/db/auth.db", "/var/db/sudo",
        "/Library/Preferences/com.apple.loginitems.plist",
        "/Users/*/Library/Preferences/com.apple.loginitems.plist",
        "/Library/Managed Preferences",
        "/var/db/ConfigurationProfiles",
        "/Library/Preferences/com.apple.alf.plist",
        "/Library/Preferences/com.apple.security",
        "/.aws/", "/.ssh/",  # credential-file opens
    }

    # Kept on create only: the file-creation rules need them, but opens and renames there never stop
    CREATE_PATHS = (
        "/Library/Application Support/", ".app/Contents/",  # staging and media-in-code rules
        "/.claude/", "/.vscode/",  # AI-agent and IDE config persistence
    )

    def __init__(self, out=None, seed=None):
        """out: where documents go, an outputs sender (default stdout). seed: for the fork sampling, so a
        replay keeps the same forks every time (None: random)."""
        self.out = out or outputs.LineWriter()
        self._random = random.Random(seed)
        self.running = True
        self.events = ESLOGGER_EVENTS  # what collect() subscribes to; main() narrows it to supported_events()

        self.filter_stats = {
            'mprotect': {'kept': 0, 'filtered': 0},
            'rename': {'kept': 0, 'filtered': 0},
            'fork': {'kept': 0, 'filtered': 0},
            'open': {'kept': 0, 'filtered': 0},
            'close': {'kept': 0, 'filtered': 0},
            'lookup': {'kept': 0, 'filtered': 0},
            'total_events': 0
        }
        self.last_stats_time = None
        import time
        self.start_time = time.time()
        
        self._user_cache = {}
    
    def _signal_handler(self, signum, frame):
        self.running = False
    
    def _print_filter_stats(self):
        import time
        elapsed = time.time() - self.start_time
        stats = self.filter_stats
        tracked_types = ['mprotect', 'rename', 'fork', 'open', 'close', 'lookup']
        total_processed = sum(
            stats[k]['kept'] + stats[k]['filtered'] 
            for k in tracked_types
        )
        if total_processed == 0:
            return
        
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"Filter Statistics (after {int(elapsed)}s)", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        
        for event_type in tracked_types:
            total = stats[event_type]['kept'] + stats[event_type]['filtered']
            if total > 0:
                pct = (stats[event_type]['kept'] / total * 100)
                print(f"{event_type}: {stats[event_type]['kept']:,} kept, "
                      f"{stats[event_type]['filtered']:,} filtered ({pct:.1f}% kept)", 
                      file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
    
    def should_keep_event(self, raw: Dict[str, Any]) -> bool:
        if not self.ENABLE_FILTERING:
            return True
        
        event_name = next(iter(raw["event"]))
        event_data = raw["event"][event_name] or {}
        
        if event_name == "mprotect":
            protection = event_data.get("protection", 0)
            if protection & 0x6 == 0x6:
                self.filter_stats['mprotect']['kept'] += 1
                return True
            self.filter_stats['mprotect']['filtered'] += 1
            return False
        
        elif event_name == "rename":
            source_path = self._extract_file_path(raw, "SourceFilename")
            dest_path = self._extract_file_path(raw, "TargetFilename")
            if not source_path and not dest_path:
                process_path = raw.get("process", {}).get("executable", {}).get("path", "")
                noisy = ["/usr/bin/log", "/usr/bin/tr", "/usr/bin/sed", "/usr/bin/jq", "/usr/bin/wc"]
                if any(p in process_path for p in noisy):
                    self.filter_stats['rename']['filtered'] += 1
                    return False
                self.filter_stats['rename']['kept'] += 1
                return True
            # a hidden destination name feeds the rename-to-dotfile rule
            should_keep = (self._is_security_path(source_path) or self._is_security_path(dest_path)
                           or os.path.basename(dest_path).startswith("."))
            if should_keep:
                self.filter_stats['rename']['kept'] += 1
            else:
                self.filter_stats['rename']['filtered'] += 1
            return should_keep
        
        elif event_name == "fork":
            process_path = raw.get("process", {}).get("executable", {}).get("path", "")
            security_procs = ["bash", "sh", "zsh", "python", "perl", "ruby", "node",
                            "curl", "wget", "nc", "ssh", "scp", "sudo", "su", "launchd"]
            if any(p in process_path.lower() for p in security_procs):
                self.filter_stats['fork']['kept'] += 1
                return True
            should_keep = self._random.random() < 0.1
            if should_keep:
                self.filter_stats['fork']['kept'] += 1
            else:
                self.filter_stats['fork']['filtered'] += 1
            return should_keep
        
        elif event_name == "create":
            path = self._extract_file_path(raw, "TargetFilename")
            # root /Library/Caches only (a SECURITY_PATHS entry also matches the busy per-user caches)
            return (self._is_security_path(path) or path.startswith("/Library/Caches/com.apple.")
                    or any(p in path for p in self.CREATE_PATHS))
        
        elif event_name == "setextattr":
            file_path = self._extract_file_path(raw, "TargetFilename")
            extattr = event_data.get("extattr") or ""
            return "quarantine" in extattr.lower() or self._is_security_path(file_path)
        
        elif event_name == "open":
            # Keep opens to security-relevant paths (used in Sigma rules)
            if self._is_security_path(self._extract_file_path(raw, "TargetFilename")):
                self.filter_stats['open']['kept'] += 1
                return True
            self.filter_stats['open']['filtered'] += 1
            return False
        
        return True
    
    def _extract_file_path(self, raw: Dict[str, Any], field: str) -> str:
        """Full path of a taxonomy file field (TargetFilename, SourceFilename) for this event, or ''."""
        return _field_value(raw, next(iter(raw["event"])), ESF_FIELDS[field]) or ""
    
    def _is_security_path(self, file_path: str) -> bool:
        if not file_path:
            return False
        for sec_path in self.SECURITY_PATHS:
            if file_path.startswith(sec_path.replace("~", "/Users")) or \
               sec_path.replace("*", "") in file_path:
                return True
        return False
    
    def normalize_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a raw eslogger event to a flat Defend-shaped ECS document.
        
        event.action is the eslogger event name; event.category/type and every other field
        come from the taxonomy. For exec, process.* is the exec target and process.parent.*
        the pre-exec image. Nothing else from the raw event (e.g. exec env) is copied.
        """
        event_name = next(iter(raw["event"]))
        normalized = {
            "@timestamp": raw.get("time"),
            "event.action": event_name,
            "host.name": socket.gethostname(),
            **EVENT_ECS.get(event_name, {}),
        }
        for field in ESF_FIELDS.values():
            value = _field_value(raw, event_name, field)
            if isinstance(value, list):  # exec args: ECS command_line is the joined string
                value = " ".join(value)
            elif field.ecs == "event.outcome" and value is not None:  # ESF's success flag, or an OD error code
                value = "success" if (value if isinstance(value, bool) else value == 0) else "failure"
            elif field.ecs == "file.hash.sha256" and value:  # eslogger's hex is uppercase; ECS and Defend's lowercase
                value = value.lower()
            if value is not None:
                normalized[field.ecs] = value
        
        # The process process.* describes: the exec target, else the acting process
        token = _get(raw, "event.exec.target.audit_token" if event_name == "exec" else "process.audit_token") or {}
        normalized["process.entity_id"] = f"{token.get('pid')}-{token.get('pidversion')}"
        euid = token.get("euid")
        if euid is not None:
            normalized["user.id"] = str(euid)
            name = self._get_username(euid)
            if name is not None:
                normalized["user.name"] = name
        return normalized

    def _get_username(self, uid: int) -> Optional[str]:
        """Local account name for a uid, cached; None if the uid has no account."""
        if uid not in self._user_cache:
            try:
                self._user_cache[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                self._user_cache[uid] = None
        return self._user_cache[uid]
    
    def collect(self) -> bool:
        """Run eslogger until it exits or a signal stops us. Returns False if eslogger failed to start."""
        process = None
        started = False
        try:
            eslogger_cmd = _eslogger() + ["--format", "json"] + self.events
            if eslogger_cmd[0] == "sudo":
                print("[DEBUG] Running with sudo", file=sys.stderr)
            
            print(f"[DEBUG] Running: {' '.join(eslogger_cmd)}", file=sys.stderr)
            
            process = subprocess.Popen(
                eslogger_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=0
            )
            
            print(f"Started eslogger (PID: {process.pid})", file=sys.stderr)
            
            import time
            time.sleep(2)
            
            if process.poll() is not None:
                stderr_output = process.stderr.read()
                print(f"❌ eslogger exited (code: {process.returncode})", file=sys.stderr)
                print(f"Error: {stderr_output}", file=sys.stderr)
                return False

            started = True
            print("Collecting events... (Ctrl+C to stop)", file=sys.stderr)
            
            import threading
            def read_stderr():
                try:
                    for line in process.stderr:
                        if line.strip():
                            print(f"[eslogger] {line.strip()}", file=sys.stderr)
                except (IOError, ValueError):
                    pass
            
            threading.Thread(target=read_stderr, daemon=True).start()
            
            event_count = 0
            last_heartbeat = time.time()
            
            for line in process.stdout:
                if not self.running:
                    break
                
                current_time = time.time()
                if current_time - last_heartbeat >= 5:
                    print(f"[DEBUG] {event_count} events collected", file=sys.stderr)
                    last_heartbeat = current_time
                
                if not line.strip():
                    continue
                
                try:
                    raw_event = json.loads(line.strip())
                    event_count += 1
                    self.filter_stats['total_events'] += 1
                    
                    if event_count == 1:
                        print("✅ First event received!", file=sys.stderr)
                    
                    if current_time - (self.last_stats_time or 0) >= 30:
                        self._print_filter_stats()
                        self.last_stats_time = current_time
                    
                    if not self.should_keep_event(raw_event):
                        continue
                    
                    self.out.send(self.normalize_event(raw_event))
                
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error: {e}", file=sys.stderr)
                    continue
            
            if process.poll() is not None:
                print(f"\n⚠️  eslogger exited (code: {process.returncode})", file=sys.stderr)
            
            process.terminate()
            process.wait()
            
        except KeyboardInterrupt:
            print("\nShutting down...", file=sys.stderr)
            if process:
                process.terminate()
                process.wait()
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            if process:
                process.terminate()
                process.wait()
        return started


def daemonize(pid_file: str, log_file: str):
    """
    Daemonize the current process.
    
    Args:
        pid_file: Path to write PID file
        log_file: Path to redirect stdout/stderr
    """
    import atexit
    
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Parent exits
    except OSError as e:
        print(f"Fork #1 failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0o077)  # PID and log files: owner only
    
    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Parent exits
    except OSError as e:
        print(f"Fork #2 failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Open log file
    log_fd = open(log_file, 'a+')
    
    # Redirect stdin to /dev/null, stdout/stderr to log
    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())
    
    # Write PID file
    pid = os.getpid()
    with open(pid_file, 'w') as f:
        f.write(str(pid))
    
    # Remove PID file on exit
    def cleanup():
        try:
            os.remove(pid_file)
        except OSError:
            pass
    
    atexit.register(cleanup)
    
    print(f"[{datetime.now().isoformat()}] Daemon started (PID: {pid})", file=sys.stderr)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="ESF Collector (ESF + ECS output)")
    outputs.add_args(parser)
    parser.add_argument("--no-filtering", action="store_true",
                       help="Disable intelligent filtering")
    parser.add_argument("--daemon", action="store_true",
                       help="Run as background daemon")
    parser.add_argument("--pid-file", default="/var/run/coresigma-esf.pid",
                       help="PID file path (daemon mode)")
    parser.add_argument("--log-file", default="/var/log/coresigma-esf.log",
                       help="Log file path (daemon mode)")
    
    args = parser.parse_args()

    # Daemon mode
    if args.daemon:
        # Check if already running
        if os.path.exists(args.pid_file):
            try:
                with open(args.pid_file, 'r') as f:
                    old_pid = int(f.read().strip())
                # Check if process is actually running
                os.kill(old_pid, 0)
                print(f"Daemon already running (PID: {old_pid})", file=sys.stderr)
                sys.exit(1)
            except (OSError, ValueError):
                # Process not running, remove stale PID file
                os.remove(args.pid_file)

    events = supported_events()  # once, before daemonizing, so a failure shows on the terminal
    if args.daemon:
        print(f"Starting daemon (log: {args.log_file})...", file=sys.stderr)
        daemonize(args.pid_file, args.log_file)
        _report_skipped(events)  # again, into the daemon's log
    
    collector = ESFCollector(outputs.open_output(args, "esf"))  # after daemonize: its flush thread can't survive fork
    collector.events = events
    # here, not in __init__: a library user (replay_capture.py, tests) keeps its own Ctrl-C
    signal.signal(signal.SIGINT, collector._signal_handler)
    signal.signal(signal.SIGTERM, collector._signal_handler)
    
    if args.no_filtering:
        collector.ENABLE_FILTERING = False
        print(f"[{datetime.now().isoformat()}] ⚠️  Filtering DISABLED", file=sys.stderr)
    else:
        print(f"[{datetime.now().isoformat()}] ℹ️  Filtering ENABLED", file=sys.stderr)
    
    # Run collector with auto-restart on failure; a signal clears collector.running and ends the loop
    delay = 5
    started = True
    try:
        while collector.running:
            try:
                started = collector.collect()
            except Exception as e:
                print(f"[{datetime.now().isoformat()}] Collector error: {e}", file=sys.stderr)
                if not args.daemon:
                    raise
                started = False
            if not args.daemon:
                break  # Normal exit in non-daemon mode
            if started:
                delay = 5
            elif collector.running:
                # eslogger failed to start: back off 5 -> 60 s instead of spinning
                print(f"[{datetime.now().isoformat()}] Restarting in {delay} seconds...", file=sys.stderr)
                time.sleep(delay)
                delay = min(delay * 2, 60)
    finally:
        collector.out.close()  # flush what is still buffered
    if not args.daemon and not started:
        sys.exit(1)  # eslogger never started (e.g. no Full Disk Access): launchctl list shows the failure


if __name__ == "__main__":
    main()
