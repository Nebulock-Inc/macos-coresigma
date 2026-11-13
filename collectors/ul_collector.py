#!/usr/bin/env python3
"""
Unified Logging Collector for Sigma Pipeline

Streams `log stream --style ndjson` (one JSON event per line) and turns each event into a flat
ECS document. The log predicate and the field mapping come from the macOS plugin taxonomy
(UL_CATEGORIES, UL_FIELDS), the same table the macos_ul_ecs pipeline is built from.
"""
import sys
import json
import os
import socket
import subprocess
import signal
import time
import importlib.util
from datetime import datetime, timezone
from typing import Dict, Any, List

# Collectors run under bare python3: load the pure-dataclass taxonomy by path, not through the
# plugin package, whose __init__ imports pySigma.
_spec = importlib.util.spec_from_file_location("coresigma_taxonomy", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "pipelines", "pysigma-pipeline-macos",
    "sigma", "pipelines", "macos", "taxonomy.py"))
_taxonomy = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _taxonomy  # dataclasses look the defining module up in sys.modules
_spec.loader.exec_module(_taxonomy)
UL_CATEGORIES, UL_FIELDS = _taxonomy.UL_CATEGORIES, _taxonomy.UL_FIELDS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # siblings import under python3 -I too
import outputs  # noqa: E402

# NSPredicate spelling of each UL_CATEGORIES modifier; [c] makes it case-insensitive, as Sigma matching is
NS_OPERATORS = {"=": "==[c]", "startswith": "BEGINSWITH[c]", "endswith": "ENDSWITH[c]"}
# Every UL_CATEGORIES predicate, ORed.
# launchd's never matches live: `log stream` doesn't deliver /sbin/launchd lines; `log show` does.
PREDICATE = " OR ".join(
    f'{field} {NS_OPERATORS[modifier]} "{value}"'
    for category in UL_CATEGORIES.values() for field, modifier, value in category.raw
)
LOG_STREAM = ["log", "stream", "--style", "ndjson", "--level", "info", "--predicate", PREDICATE]
LOG_SHOW = ["log", "show", "--style", "ndjson", "--info", "--last", "5m", "--predicate", PREDICATE]


class ULCollector:
    """Collects and normalizes Unified Logging events for Sigma pipeline"""
    
    def __init__(self, out=None):
        """out: where documents go, an outputs sender (default stdout)."""
        self.out = out or outputs.LineWriter()
        self.running = True
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.running = False
    
    def normalize_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """A raw `log --style ndjson` event as a flat ECS document: UL_FIELDS' ecs keys, @timestamp, host.name."""
        doc = {
            "@timestamp": datetime.strptime(raw["timestamp"], "%Y-%m-%d %H:%M:%S.%f%z")
                                  .astimezone(timezone.utc).isoformat(),
            "host.name": socket.gethostname(),
        }
        for field in UL_FIELDS.values():
            value = raw.get(field.raw)
            if value is not None:
                doc[field.ecs] = value
        if "user.id" in doc:
            doc["user.id"] = str(doc["user.id"])  # keyword, as in ESF documents
        return doc
    
    def _emit(self, doc: Dict[str, Any]):
        self.out.send(doc)
    
    def _run(self, cmd: List[str]) -> int:
        """Run a `log` command, emitting its events until it exits or a signal stops us. Returns events emitted."""
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
        print(f"Started {' '.join(cmd[:2])} (PID: {proc.pid})", file=sys.stderr)
        count = errors = 0
        try:
            for line in proc.stdout:
                if not self.running:
                    break
                if not line.startswith("{"):  # log's "Filtering the log data using ..." header
                    continue
                try:
                    doc = self.normalize_event(json.loads(line))
                except Exception as e:  # one bad line must not end the stream
                    errors += 1
                    if errors & (errors - 1) == 0:  # log the 1st, 2nd, 4th, 8th ... only
                        print(f"Skipped {errors} unparsable {cmd[1]} lines, latest: {e!r}", file=sys.stderr)
                    continue
                count += 1
                self._emit(doc)
        finally:
            # always reap log: also when stopped by a signal or an error, or stdout closed before exit
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            proc.stdout.close()
            print(f"{' '.join(cmd[:2])} exited (code: {proc.wait()}) after {count} events, {errors} skipped",
                  file=sys.stderr)
        return count
    
    def collect(self, capture_recent: bool = True):
        """
        Stream UL events until a signal clears self.running, restarting `log stream` whenever it exits.
        
        Args:
            capture_recent: If True, first emit the last 5 minutes from `log show`
        """
        if capture_recent:
            self._run(LOG_SHOW)
        delay = 1
        while self.running:
            if self._run(LOG_STREAM):
                delay = 1
            if self.running:
                # back off 1 -> 60 s while the stream exits without events, so it can't spin
                print(f"Restarting log stream in {delay} s", file=sys.stderr)
                time.sleep(delay)
                delay = min(delay * 2, 60)

def daemonize(pid_file: str, log_file: str):
    """
    Daemonize the current process.
    
    Args:
        pid_file: Path to write PID file
        log_file: Path to redirect stdout/stderr
    """
    import os
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
    
    print(f"[{datetime.now(timezone.utc).isoformat()}] Daemon started (PID: {pid})", file=sys.stderr)


def main():
    """Main entry point"""
    import argparse
    import os
    
    parser = argparse.ArgumentParser(description="UL Event Collector for Sigma Pipeline")
    outputs.add_args(parser)
    parser.add_argument("--no-recent", action="store_true",
                       help="Skip capturing recent events on startup")
    parser.add_argument("--daemon", action="store_true",
                       help="Run as background daemon")
    parser.add_argument("--pid-file", default="/var/run/coresigma-ul.pid",
                       help="PID file path (daemon mode)")
    parser.add_argument("--log-file", default="/var/log/coresigma-ul.log",
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
        
        print(f"Starting daemon (log: {args.log_file})...", file=sys.stderr)
        daemonize(args.pid_file, args.log_file)
    
    collector = ULCollector(outputs.open_output(args, "ul"))  # after daemonize: its flush thread can't survive fork
    # here, not in __init__: a library user (replay_capture.py, tests) keeps its own Ctrl-C
    signal.signal(signal.SIGINT, collector._signal_handler)
    signal.signal(signal.SIGTERM, collector._signal_handler)
    
    # Run collector with auto-restart on failure; collect() restarts log stream itself and returns on a signal
    try:
        while collector.running:
            try:
                collector.collect(capture_recent=not args.no_recent)
            except Exception as e:
                print(f"[{datetime.now(timezone.utc).isoformat()}] Collector error: {e}", file=sys.stderr)
                if not args.daemon:
                    raise
                # In daemon mode, wait and restart
                print(f"[{datetime.now(timezone.utc).isoformat()}] Restarting in 5 seconds...", file=sys.stderr)
                time.sleep(5)
    finally:
        collector.out.close()  # flush what is still buffered


if __name__ == "__main__":
    main()

