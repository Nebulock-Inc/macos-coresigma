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
    SECURITY_SUBSYSTEMS = [
        "com.apple.TCC",
        "com.apple.sudo",
        "com.apple.gatekeeper",
        "com.apple.syspolicy",
        "com.apple.securityd",
        "com.apple.alf",
        "com.apple.opendirectoryd",
        "com.apple.authorization",
    ]
    
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
                from elasticsearch import Elasticsearch
                es_url_final = es_url if es_url else 'http://localhost:9200'
                self.es_client = Elasticsearch([es_url_final])
                # Test connection
                try:
                    info = self.es_client.info()
                    print(f"✅ Connected to Elasticsearch: {es_url_final} (cluster: {info.get('cluster_name', 'unknown')})", file=sys.stderr)
                except Exception as e:
                    print(f"⚠️  Elasticsearch connection test failed: {e}", file=sys.stderr)
            except ImportError:
                print("❌ ERROR: elasticsearch module not found. Install with: pip install elasticsearch", file=sys.stderr)
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
        
        normalized = {
            "@timestamp": timestamp,
            "sourcetype": "macos:ul",
        }
        
        # Extract subsystem and category (at top level in log stream output)
        subsystem = ul_event.get("subsystem", "")
        category = ul_event.get("category", "")
        
        # Extract message - eventMessage is a string, formatString is at top level
        message = ul_event.get("eventMessage", "")
        if not message:
            message = ul_event.get("formatString", "")
        if not message:
            message = ul_event.get("message", "")
        
        normalized["subsystem"] = subsystem
        normalized["category"] = category
        normalized["message"] = message
        normalized["CommandLine"] = message  # Map message to CommandLine for Sigma compatibility
        
        # Extract process information
        process_name = ul_event.get("processImagePath", "")
        if not process_name:
            process_name = ul_event.get("process", "")
        pid = ul_event.get("processID")
        if not pid:
            pid = ul_event.get("pid")
        
        normalized["ProcessName"] = process_name
        normalized["ProcessId"] = pid
        normalized["process"] = process_name
        
        # Extract user if present
        user_id = ul_event.get("userID")
        if user_id is not None:
            normalized["UserId"] = user_id
        
        # Extract user from message if present
        user = self._extract_user(message)
        if user:
            normalized["User"] = user
        
        # Extract network information if present
        network_info = self._extract_network_info(message)
        if network_info:
            normalized.update(network_info)
        
        # Set hostname
        normalized["host.name"] = ul_event.get("hostname", "") or ul_event.get("host", "")
        
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

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="UL Event Collector for Sigma Pipeline")
    parser.add_argument("--output", choices=["stdout", "elasticsearch", "file"], 
                       default="stdout", help="Output destination")
    parser.add_argument("--es-url", default="http://localhost:9200",
                       help="Elasticsearch URL (for elasticsearch output)")
    
    args = parser.parse_args()
    
    collector = ULCollector(output=args.output, es_url=args.es_url)
    collector.collect()

if __name__ == "__main__":
    main()

