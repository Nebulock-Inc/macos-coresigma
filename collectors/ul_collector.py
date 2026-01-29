#!/usr/bin/env python3
"""
Unified Logging Collector for Sigma Pipeline
Collects UL events and normalizes fields to Sigma-compatible names
"""
import sys
import json
import subprocess
import signal
import re
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

class ULCollector:
    """Collects and normalizes Unified Logging events for Sigma pipeline"""
    
    # Security-critical subsystems for filtering
    # Ordered by security priority
    SECURITY_SUBSYSTEMS = [
        # Critical - Keep all events (privilege escalation, privacy)
        "com.apple.TCC",
        "com.apple.sudo",
        "com.apple.gatekeeper",
        "com.apple.syspolicy",
        "com.apple.securityd",
        
        # High - Authentication and authorization
        "com.apple.alf",
        "com.apple.opendirectoryd",
        "com.apple.authorization",
        "com.apple.authd",
        
        # Additional security-relevant subsystems
        "com.apple.ManagedClient",    # MDM/enterprise policies
        "com.apple.launchd",          # Persistence mechanisms
        "com.apple.xpc",              # IPC security
    ]
    
    # Subsystems that don't need message filtering (always keep all)
    CRITICAL_SUBSYSTEMS = {
        "com.apple.TCC",
        "com.apple.sudo", 
        "com.apple.gatekeeper",
        "com.apple.syspolicy",
    }
    
    # Keywords indicating high-value security events (always keep)
    SIGNAL_KEYWORDS = [
        "denied", "failed", "rejected", "blocked", "invalid",
        "violation", "unauthorized", "suspicious", "malware",
        "quarantine", "xprotect", "codesign", "notarization",
        "COMMAND=", "TTY=", "USER=root", "authentication",
        "kextload", "profile", "policy",
    ]
    
    # Keywords indicating routine/noise events (filter from non-critical subsystems)
    NOISE_KEYWORDS = [
        "succeeded", "allowed", "completed successfully",
        "query completed", "check passed", "request completed",
    ]
    
    # Enable filtering by default (set to False for full capture)
    ENABLE_FILTERING = True
    
    def __init__(self, output: str = "stdout", es_url: Optional[str] = None):
        """
        Initialize UL collector
        
        Args:
            output: Output destination ('stdout', 'elasticsearch', 'file')
            es_url: Elasticsearch URL if output is 'elasticsearch'
        """
        self.output = output
        self.es_url = es_url
        self.running = True
        self.es_client = None
        
        if output == "elasticsearch":
            try:
                # Try relative import first (when used as a module)
                try:
                    from .auth import create_elasticsearch_client, AuthenticationError
                except ImportError:
                    # Fall back to direct import (when run as a script)
                    from auth import create_elasticsearch_client, AuthenticationError
                
                es_url_final = es_url if es_url else 'http://localhost:9200'
                try:
                    self.es_client = create_elasticsearch_client(es_url_final)
                    info = self.es_client.info()
                    print(f"✅ Connected to Elasticsearch: {es_url_final} (cluster: {info.get('cluster_name', 'unknown')})", file=sys.stderr)
                except AuthenticationError as e:
                    print(f"❌ Authentication error: {e}", file=sys.stderr)
                    self.es_client = None
                except Exception as e:
                    print(f"⚠️  Elasticsearch connection failed: {e}", file=sys.stderr)
                    self.es_client = None
            except ImportError as e:
                print(f"❌ ERROR: {e}", file=sys.stderr)
                self.es_client = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.running = False
    
    def normalize_event(self, ul_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize UL event to Sigma-compatible field names
        
        Args:
            ul_event: Raw UL event from log show
            
        Returns:
            Normalized event with Sigma field names
        """
        # Handle timestamp - log stream uses format: "2025-12-04 16:28:00.574185-0500"
        timestamp = ul_event.get("timestamp", "")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()
        elif isinstance(timestamp, str):
            # Parse timestamp string (format: "2025-12-04 16:28:00.574185-0500")
            try:
                # Remove microseconds if present and parse
                # Format: "YYYY-MM-DD HH:MM:SS.microseconds-timezone"
                if ' ' in timestamp:
                    # Check if it ends with timezone offset like "-0500" or "+0500"
                    if len(timestamp) > 5 and timestamp[-5] in ['-', '+']:
                        # Split date/time and timezone
                        tz_sign = timestamp[-5]
                        dt_str = timestamp[:-5]
                        tz_str = timestamp[-4:]  # Just the digits
                        
                        # Parse datetime part
                        if '.' in dt_str:
                            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
                        else:
                            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                        
                        # Convert timezone offset to timedelta
                        tz_hours = int(tz_str[:2])
                        tz_mins = int(tz_str[2:4])
                        if tz_sign == '-':
                            tz_offset = timezone(timedelta(hours=-tz_hours, minutes=-tz_mins))
                        else:
                            tz_offset = timezone(timedelta(hours=tz_hours, minutes=tz_mins))
                        dt = dt.replace(tzinfo=tz_offset)
                        # Convert to UTC and format as ISO
                        timestamp = dt.astimezone(timezone.utc).isoformat()
                    else:
                        # No timezone, try simpler parsing
                        dt = datetime.fromisoformat(timestamp.replace(' ', 'T'))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        timestamp = dt.astimezone(timezone.utc).isoformat()
                else:
                    # Try ISO format directly
                    dt = datetime.fromisoformat(timestamp)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    timestamp = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                # If parsing fails, use current time
                timestamp = datetime.now(timezone.utc).isoformat()
        elif isinstance(timestamp, (int, float)):
            # Convert Unix timestamp to ISO format
            timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        
        # Extract subsystem and category (at top level in log stream output)
        subsystem = ul_event.get("subsystem", "")
        category = ul_event.get("category", "")
        
        # Extract message - eventMessage is a string, formatString is at top level
        message = ul_event.get("eventMessage", "")
        if not message:
            message = ul_event.get("formatString", "")
        if not message:
            message = ul_event.get("message", "")
        
        # Build ECS-compliant normalized event
        normalized = {
            # Core ECS fields
            "@timestamp": timestamp,
            "event.kind": "event",
            "event.module": "macos",
            "event.dataset": "macos.ul",
            "event.category": category,
            
            # Data stream fields
            "data_stream.type": "logs",
            "data_stream.dataset": "macos.ul",
            "data_stream.namespace": "default",
            
            # Host info
            "host.os.family": "darwin",
            "host.os.type": "macos",
            
            # Legacy compatibility
            "sourcetype": "macos:ul",
            
            # UL-specific fields mapped to ECS
            "log.logger": subsystem,           # ECS: log.logger for subsystem
            "message": message,                 # ECS: message
            
            # Also keep native UL fields for backward compatibility
            "ul.subsystem": subsystem,
            "ul.category": category,
            "subsystem": subsystem,             # Legacy
            "category": category,               # Legacy
        }
        
        # Extract process information
        # Handle both string and object formats for 'process' field
        process_path = ul_event.get("processImagePath", "")
        process_field = ul_event.get("process", "")
        
        # If process is an object (dict), extract the executable path
        if isinstance(process_field, dict):
            if not process_path:
                process_path = process_field.get("executable", "") or process_field.get("path", "")
        elif isinstance(process_field, str) and not process_path:
            process_path = process_field
        
        pid = ul_event.get("processID")
        if not pid:
            pid = ul_event.get("pid")
        
        # ECS process fields
        import os
        if process_path and isinstance(process_path, str):
            normalized["process.executable"] = process_path
            normalized["process.name"] = os.path.basename(process_path)
        if pid is not None:
            normalized["process.pid"] = pid
        
        # Legacy compatibility - only use string values
        if isinstance(process_path, str):
            normalized["ProcessName"] = process_path
        normalized["ProcessId"] = pid
        
        # Extract user if present
        user_id = ul_event.get("userID")
        if user_id is not None:
            normalized["user.id"] = str(user_id)
            normalized["UserId"] = user_id  # Legacy
        
        # Extract user from message if present
        user = self._extract_user(message)
        if user:
            normalized["user.name"] = user
            normalized["User"] = user  # Legacy
        
        # Extract network information if present (maps to ECS destination.*/source.*)
        network_info = self._extract_network_info(message)
        if network_info:
            # Map to ECS fields
            if "DestinationIp" in network_info:
                normalized["destination.ip"] = network_info["DestinationIp"]
            if "DestinationPort" in network_info:
                normalized["destination.port"] = network_info["DestinationPort"]
            if "SourceIp" in network_info:
                normalized["source.ip"] = network_info["SourceIp"]
            if "SourcePort" in network_info:
                normalized["source.port"] = network_info["SourcePort"]
        
        # Set hostname (ECS: host.name)
        hostname = ul_event.get("hostname", "") or ul_event.get("host", "")
        if hostname:
            normalized["host.name"] = hostname
        
        return normalized
    
    def _extract_user(self, message: str) -> Optional[str]:
        """Extract username from message"""
        # Common patterns for user extraction
        patterns = [
            r'user:\s*(\w+)',
            r'username:\s*(\w+)',
            r'(\w+)\s+logged in',
            r'(\w+)\s+executed',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def should_keep_event(self, ul_event: Dict[str, Any]) -> bool:
        """
        Filter UL events to reduce noise while preserving security signal.
        
        Args:
            ul_event: Raw UL event from log stream
            
        Returns:
            True if event should be kept, False to filter
        """
        if not self.ENABLE_FILTERING:
            return True
        
        subsystem = ul_event.get("subsystem", "")
        message = ul_event.get("eventMessage", "") or ul_event.get("formatString", "") or ""
        message_lower = message.lower()
        
        # Always keep events from critical subsystems
        if subsystem in self.CRITICAL_SUBSYSTEMS:
            return True
        
        # Always keep events with security signal keywords
        if any(kw.lower() in message_lower for kw in self.SIGNAL_KEYWORDS):
            return True
        
        # Filter routine/noise events from non-critical subsystems
        if any(kw.lower() in message_lower for kw in self.NOISE_KEYWORDS):
            return False
        
        # Default: keep the event
        return True
    
    def _extract_network_info(self, message: str) -> Optional[Dict[str, Any]]:
        """Extract network IP addresses and ports from message"""
        # IP address patterns
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        port_pattern = r':(\d{1,5})\b'
        
        ips = re.findall(ip_pattern, message)
        ports = re.findall(port_pattern, message)
        
        if not ips:
            return None
        
        network_info = {}
        
        if len(ips) >= 1:
            network_info["DestinationIp"] = ips[0]
        if len(ips) >= 2:
            network_info["SourceIp"] = ips[1]
        elif len(ips) == 1:
            network_info["DestinationIp"] = ips[0]
        
        if len(ports) >= 1:
            network_info["DestinationPort"] = int(ports[0])
        if len(ports) >= 2:
            network_info["SourcePort"] = int(ports[1])
        
        return network_info
    
    def send_to_elasticsearch(self, event: Dict[str, Any]):
        """Send event to Elasticsearch"""
        if not self.es_client:
            print("⚠️  WARNING: es_client is None, cannot index UL event", file=sys.stderr)
            return
        
        try:
            index_name = f"macos-telemetry-ul-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
            self.es_client.index(index=index_name, body=event)
            # Debug: Print every 50th event to confirm indexing
            if hasattr(self, '_indexed_count'):
                self._indexed_count += 1
            else:
                self._indexed_count = 1
            
            if self._indexed_count % 50 == 0:
                print(f"[DEBUG] Indexed {self._indexed_count} UL events to {index_name}", file=sys.stderr)
        except Exception as e:
            print(f"❌ ERROR sending to Elasticsearch: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
    
    def collect(self, capture_recent: bool = True):
        """
        Main collection loop - reads from log stream
        
        Args:
            capture_recent: If True, also capture recent events from last 5 minutes
                           before starting real-time stream
        """
        try:
            # Build log show predicate for security subsystems
            predicate_parts = []
            for subsystem in self.SECURITY_SUBSYSTEMS:
                predicate_parts.append(f'subsystem == "{subsystem}"')
            
            predicate = " OR ".join(predicate_parts)
            
            # First, capture recent events (last 5 minutes) if requested
            if capture_recent:
                print("Capturing recent events (last 5 minutes)...", file=sys.stderr)
                log_show_cmd = [
                    "log", "show", "--predicate", predicate,
                    "--style", "json", "--last", "5m"
                ]
                
                recent_process = subprocess.Popen(
                    log_show_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                recent_count = 0
                for line in recent_process.stdout:
                    if not line.strip():
                        continue
                    try:
                        raw_event = json.loads(line.strip())
                        normalized = self.normalize_event(raw_event)
                        recent_count += 1
                        
                        if self.output == "stdout":
                            print(json.dumps(normalized))
                        elif self.output == "elasticsearch":
                            self.send_to_elasticsearch(normalized)
                    except (json.JSONDecodeError, Exception):
                        continue
                
                recent_process.wait()
                print(f"Captured {recent_count} recent events", file=sys.stderr)
                print("Starting real-time stream...", file=sys.stderr)
            
            # For continuous collection, stream new events
            # Add --level info to reduce noise
            log_stream_cmd = [
                "log", "stream", "--predicate", predicate,
                "--style", "json", "--level", "info"
            ]
            
            process = subprocess.Popen(
                log_stream_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            print(f"Started log stream (PID: {process.pid})", file=sys.stderr)
            print("Collecting UL events from security subsystems...", file=sys.stderr)
            print(f"Monitoring: {len(self.SECURITY_SUBSYSTEMS)} subsystems", file=sys.stderr)
            print("(Press Ctrl+C to stop)", file=sys.stderr)
            
            # Process events - log stream outputs JSON arrays [ {...}, {...} ]
            # The array may be very large and continuously growing, so we parse
            # individual event objects from within the array as they appear
            event_count = 0
            buffer = ""
            in_array = False
            skip_filtering = True
            
            # Read in chunks for better performance
            while self.running:
                try:
                    chunk = process.stdout.read(8192)  # 8KB chunks
                    if not chunk:
                        time.sleep(0.1)
                        continue
                    
                    buffer += chunk
                    
                    # Skip "Filtering..." message on first chunk
                    if skip_filtering and buffer.startswith("Filtering"):
                        newline = buffer.find('\n')
                        if newline > 0:
                            buffer = buffer[newline+1:]
                        skip_filtering = False
                    
                    # Find array start
                    if not in_array:
                        bracket_start = buffer.find('[')
                        if bracket_start >= 0:
                            buffer = buffer[bracket_start+1:]  # Skip the [
                            in_array = True
                    
                    if in_array:
                        # Parse complete event objects from the array
                        # Look for complete JSON objects: { ... }
                        while True:
                            # Find next {
                            obj_start = buffer.find('{')
                            if obj_start == -1:
                                break
                            
                            # Find matching }
                            brace_count = 0
                            obj_end = -1
                            for i, char in enumerate(buffer[obj_start:], obj_start):
                                if char == '{':
                                    brace_count += 1
                                elif char == '}':
                                    brace_count -= 1
                                    if brace_count == 0:
                                        obj_end = i + 1
                                        break
                            
                            if obj_end > 0:
                                # Found complete object
                                obj_str = buffer[obj_start:obj_end]
                                
                                # Check if followed by comma or closing bracket
                                after_obj = buffer[obj_end:obj_end+2].strip()
                                if after_obj.startswith(',') or after_obj.startswith(']'):
                                    # This is an event object, parse it
                                    try:
                                        raw_event = json.loads(obj_str)
                                        if isinstance(raw_event, dict):
                                            # Validate it's actually an event object (has expected fields)
                                            if 'eventType' in raw_event or 'subsystem' in raw_event:
                                                # Apply filtering
                                                if not self.should_keep_event(raw_event):
                                                    continue
                                                
                                                normalized = self.normalize_event(raw_event)
                                                event_count += 1
                                                
                                                # Log every 10th event
                                                if event_count % 10 == 0:
                                                    print(f"Processed {event_count} UL events...", file=sys.stderr)
                                                
                                                if self.output == "stdout":
                                                    print(json.dumps(normalized))
                                                elif self.output == "elasticsearch":
                                                    self.send_to_elasticsearch(normalized)
                                                elif self.output == "file":
                                                    print(json.dumps(normalized))
                                    except (json.JSONDecodeError, AttributeError, TypeError) as e:
                                        # Not a valid event object, skip
                                        if event_count < 3:
                                            print(f"[DEBUG] Skipping invalid object: {e}", file=sys.stderr)
                                        pass
                                
                                # Remove processed object (including comma if present)
                                if after_obj.startswith(','):
                                    buffer = buffer[obj_end+1:].lstrip()
                                else:
                                    buffer = buffer[obj_end:].lstrip()
                                
                                # If we hit ], we're done with this array
                                if buffer.startswith(']'):
                                    in_array = False
                                    buffer = buffer[1:].lstrip()
                                    # Look for next array
                                    if buffer.startswith('['):
                                        buffer = buffer[1:].lstrip()
                                        in_array = True
                            else:
                                # Incomplete object, wait for more data
                                break
                    
                    # Limit buffer size to prevent memory issues
                    if len(buffer) > 100000:  # 100KB
                        # If we have a large buffer and no progress, clear it
                        # (this shouldn't happen normally, but protects against issues)
                        print(f"[WARNING] Large buffer ({len(buffer)} bytes), clearing...", file=sys.stderr)
                        buffer = ""
                        in_array = False
                        skip_filtering = True
                        
                except Exception as e:
                    print(f"Error in collection loop: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    time.sleep(1)
                    continue
            
            print(f"Total events processed: {event_count}", file=sys.stderr)
            
            process.terminate()
            process.wait()
            
        except KeyboardInterrupt:
            print("\nShutting down...", file=sys.stderr)
        except Exception as e:
            print(f"Error in collector: {e}", file=sys.stderr)
            sys.exit(1)

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
    os.umask(0)
    
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
    parser.add_argument("--output", choices=["stdout", "elasticsearch", "file"], 
                       default="stdout", help="Output destination")
    parser.add_argument("--es-url", default="http://localhost:9200",
                       help="Elasticsearch URL (for elasticsearch output)")
    parser.add_argument("--no-filtering", action="store_true",
                       help="Disable noise filtering (capture all events)")
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
    
    collector = ULCollector(output=args.output, es_url=args.es_url)
    
    if args.no_filtering:
        collector.ENABLE_FILTERING = False
        print(f"[{datetime.now(timezone.utc).isoformat()}] Filtering DISABLED - capturing all events", file=sys.stderr)
    else:
        print(f"[{datetime.now(timezone.utc).isoformat()}] Filtering ENABLED - reducing noise", file=sys.stderr)
    
    # Run collector with auto-restart on failure
    while True:
        try:
    collector.collect(capture_recent=not args.no_recent)
            if not args.daemon:
                break  # Normal exit in non-daemon mode
        except Exception as e:
            print(f"[{datetime.now(timezone.utc).isoformat()}] Collector error: {e}", file=sys.stderr)
            if not args.daemon:
                raise
            # In daemon mode, wait and restart
            print(f"[{datetime.now(timezone.utc).isoformat()}] Restarting in 5 seconds...", file=sys.stderr)
            time.sleep(5)


if __name__ == "__main__":
    main()

