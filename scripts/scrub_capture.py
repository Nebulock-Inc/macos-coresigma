#!/usr/bin/env python3
"""Scrub private data from captured events for test fixtures."""
import argparse
import gzip
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Optional


def load_private_strings(local_file: Optional[Path] = None) -> Dict[str, Any]:
    """Load private strings from local file for scrubbing config."""
    if local_file is None:
        # Check env var first
        env_path = os.environ.get("CORESIGMA_PRIVATE_STRINGS")
        if env_path:
            local_file = Path(env_path)
        else:
            local_file = Path(__file__).parent.parent / "tests" / "private_strings.local.json"

    if not local_file.exists():
        return None

    # Load and validate JSON
    try:
        with open(local_file, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Malformed JSON in {local_file}: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to read {local_file}: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate required keys
    required_keys = ["hostnames", "aws_account_ids", "instance_ids", "mac_serials", "user_homes", "usernames",
                     "ip_addresses", "falcon_agent_uuids"]  # required: a missing key would leave those values unscrubbed
    missing_keys = [k for k in required_keys if k not in data]
    if missing_keys:
        print(f"Error: Missing required keys in {local_file}: {', '.join(missing_keys)}", file=sys.stderr)
        print(f"Required keys: {', '.join(required_keys)}", file=sys.stderr)
        sys.exit(1)

    return data


def build_scrub_config(private_strings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build scrubbing configuration, merging private strings with generic patterns."""
    # Base config with placeholders and generic patterns
    config = {
        "hostname_placeholder": "host.example",
        "account_placeholder": "000000000000",
        "instance_placeholder": "i-00000000000000000",
        "serial_placeholder": "SERIALNUMBER",
        "home_placeholder": "/Users/user",
        "username_placeholder": "user",
        "org_placeholder": "example",
        "ip_placeholder": "10.0.0.1",
        "falcon_uuid_placeholder": "00000000-0000-0000-0000-000000000000",
        "mac_address_placeholder": "00:00:00:00:00:00",
        "name_placeholder": "Person",
        "bucket_placeholder": "example-bucket",
        # Generic patterns (always present)
        "org_names": ["nebulock", "Nebulock", "NEBULOCK"],
        "ip_addresses": ["169.254.169.123"],  # AWS time sync
        "falcon_agent_uuids": [],
    }

    # Add private strings if provided (empty lists without them)
    private_strings = private_strings or {}
    config["hostnames"] = private_strings.get("hostnames", [])
    config["aws_account_ids"] = private_strings.get("aws_account_ids", [])
    config["instance_ids"] = private_strings.get("instance_ids", [])
    config["mac_serials"] = private_strings.get("mac_serials", [])
    config["user_homes"] = private_strings.get("user_homes", [])
    config["usernames"] = private_strings.get("usernames", [])
    config["personal_names"] = private_strings.get("personal_names", [])
    bucket = private_strings.get("capture_bucket")
    config["capture_buckets"] = [bucket_name(bucket)] if bucket else []
    # the host's own IPs and Falcon agent IDs
    config["ip_addresses"] += private_strings.get("ip_addresses", [])
    config["falcon_agent_uuids"] = private_strings.get("falcon_agent_uuids", [])

    return config


def bucket_name(capture_bucket: str) -> str:
    """'s3://bucket/prefix/' or 'bucket/prefix' -> 'bucket': the name is what shows up in commands and URLs."""
    return capture_bucket.split("://", 1)[-1].split("/", 1)[0]


# Global config, initialized on first use
_SCRUB_CONFIG = None

# Compiled regex patterns (generic, not host-specific)
INSTANCE_ID_PATTERN = re.compile(r'\bi-[0-9a-f]{8,17}\b')
USER_HOME_PATTERN = re.compile(r'/Users/[^/\s]+')
ORG_NAME_PATTERN = re.compile(r'nebulock', re.IGNORECASE)
MAC_ADDRESS_PATTERN = re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b')


def get_scrub_config(private_strings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Get or initialize the global scrub config."""
    global _SCRUB_CONFIG
    if _SCRUB_CONFIG is None:
        _SCRUB_CONFIG = build_scrub_config(private_strings)
    return _SCRUB_CONFIG


def get_username_pattern(config: Dict[str, Any]) -> Optional[re.Pattern]:
    """Build username pattern from config."""
    usernames = config.get("usernames", [])
    if not usernames:
        return None
    # Escape each username and join with |; any case, like hostnames
    escaped = [re.escape(u) for u in usernames]
    return re.compile(r'\b(' + '|'.join(escaped) + r')\b', re.IGNORECASE)


def falcon_id_pattern(uuid: str) -> re.Pattern:
    """The 32 hex digits of a Falcon ID, in any case, dashed (8-4-4-4-12) or not."""
    h = uuid.replace("-", "").lower()
    parts = [h[:8], h[8:12], h[12:16], h[16:20], h[20:]] if len(h) == 32 else [h]
    return re.compile("-?".join(map(re.escape, parts)), re.IGNORECASE)


def scrub_string(s: str, config: Dict[str, Any], username_pattern: Optional[re.Pattern]) -> str:
    """Scrub private data from a string value."""
    # Replace hostnames (any case: DNS names and `hostname` output differ in case)
    for hostname in config.get("hostnames", []):
        s = re.sub(re.escape(hostname), config["hostname_placeholder"], s, flags=re.IGNORECASE)

    # Replace the capture bucket's name (before account IDs, which a bucket name can contain)
    for bucket in config.get("capture_buckets", []):
        s = s.replace(bucket, config["bucket_placeholder"])

    # Replace AWS account IDs
    for account_id in config.get("aws_account_ids", []):
        s = s.replace(account_id, config["account_placeholder"])

    # Replace known instance IDs
    for instance_id in config.get("instance_ids", []):
        s = s.replace(instance_id, config["instance_placeholder"])

    # Replace any instance ID pattern
    s = INSTANCE_ID_PATTERN.sub(config["instance_placeholder"], s)

    # Replace Mac serials
    for serial in config.get("mac_serials", []):
        s = s.replace(serial, config["serial_placeholder"])

    # Replace user home paths, any case (APFS is case-insensitive), before usernames to avoid double substitution
    for user_home in config.get("user_homes", []):
        s = re.sub(re.escape(user_home), config["home_placeholder"], s, flags=re.IGNORECASE)

    # Replace any /Users/<name> pattern
    s = USER_HOME_PATTERN.sub(config["home_placeholder"], s)

    # Replace usernames (standalone, not in paths)
    if username_pattern:
        s = username_pattern.sub(config["username_placeholder"], s)

    # Replace personal names: any case, whole words only, so "Al" doesn't rewrite "Also"
    for name in config.get("personal_names", []):
        s = re.sub(r'\b' + re.escape(name) + r'\b', config["name_placeholder"], s, flags=re.IGNORECASE)

    # Replace org names (case-insensitive)
    s = ORG_NAME_PATTERN.sub(config["org_placeholder"], s)

    # Replace IP addresses
    for ip in config.get("ip_addresses", []):
        s = s.replace(ip, config["ip_placeholder"])

    # Replace Falcon agent UUIDs: any case, with or without dashes (falconctl prints the aid one way, paths another)
    for uuid in config.get("falcon_agent_uuids", []):
        s = falcon_id_pattern(uuid).sub(config["falcon_uuid_placeholder"], s)

    # Replace MAC addresses
    s = MAC_ADDRESS_PATTERN.sub(config["mac_address_placeholder"], s)

    return s


def scrub_value(value: Any, key: str, config: Dict[str, Any], username_pattern: Optional[re.Pattern]) -> Any:
    """Recursively scrub a value, preserving types and structure."""
    # Drop env arrays
    if key == "env" and isinstance(value, list):
        return []
    # Unified Log boot session ID: per host and boot
    if key == "bootUUID" and isinstance(value, str):
        return ""

    if isinstance(value, str):
        return scrub_string(value, config, username_pattern)
    elif isinstance(value, dict):
        return {k: scrub_value(v, k, config, username_pattern) for k, v in value.items()}
    elif isinstance(value, list):
        return [scrub_value(item, None, config, username_pattern) for item in value]
    else:
        # Preserve all other types (int, bool, float, None) unchanged
        return value


def scrub_event(evt: dict) -> dict:
    """
    Scrub private data from an event.

    Drops env arrays and replaces private strings while preserving structure.
    Uses the global config initialized by load or CLI.
    """
    config = get_scrub_config()
    username_pattern = get_username_pattern(config)
    return {k: scrub_value(v, k, config, username_pattern) for k, v in evt.items()}


def process_esf_capture(input_path: Path, output_dir: Path, per_key: int):
    """Process an ESF capture file, grouping by event name."""
    print(f"Processing ESF capture: {input_path}")

    # Read and parse the capture file
    with gzip.open(input_path, 'rt', encoding='utf-8') as f:
        events = [json.loads(line) for line in f if line.strip()]

    print(f"Read {len(events)} events")

    # Group events by event name (key in event["event"] dict)
    grouped = defaultdict(list)
    for event in events:
        event_dict = event.get("event", {})
        if event_dict:
            # Get the single key name (e.g., "exec", "open", "fork")
            event_name = next(iter(event_dict), "unknown")
        else:
            event_name = "unknown"
        grouped[event_name].append(event)

    # Write scrubbed samples for each event name
    esf_dir = output_dir / "esf"
    esf_dir.mkdir(parents=True, exist_ok=True)

    for event_name, name_events in grouped.items():
        # Take up to per_key samples
        samples = name_events[:per_key]
        scrubbed_samples = [scrub_event(evt) for evt in samples]

        output_file = esf_dir / f"{event_name}.json"
        with open(output_file, 'w') as f:
            for scrubbed in scrubbed_samples:
                f.write(json.dumps(scrubbed) + '\n')

        print(f"  {event_name}: wrote {len(scrubbed_samples)} samples to {output_file.name}")


def process_ul_capture(input_path: Path, output_dir: Path, per_key: int):
    """Process a Unified Log capture file, grouping by subsystem or process."""
    print(f"Processing UL capture: {input_path}")

    # Read and parse the capture file
    with gzip.open(input_path, 'rt', encoding='utf-8') as f:
        events = [json.loads(line) for line in f if line.strip()]

    print(f"Read {len(events)} events")

    # Group by subsystem, falling back to process image name
    grouped = defaultdict(list)
    for event in events:
        key = event.get("subsystem")
        if not key:
            # Fallback to process image name
            key = event.get("processImagePath", "unknown")
            if "/" in key:
                key = key.split("/")[-1]
        grouped[key].append(event)

    # Write scrubbed samples for each group
    ul_dir = output_dir / "ul"
    ul_dir.mkdir(parents=True, exist_ok=True)

    for group_key, group_events in grouped.items():
        # Sanitize group key for filename
        safe_key = group_key.replace(".", "_").replace("/", "_")

        # Take up to per_key samples
        samples = group_events[:per_key]
        scrubbed_samples = [scrub_event(evt) for evt in samples]

        output_file = ul_dir / f"{safe_key}.ndjson"
        with open(output_file, 'w') as f:
            for scrubbed in scrubbed_samples:
                f.write(json.dumps(scrubbed) + '\n')

        print(f"  {safe_key}: wrote {len(scrubbed_samples)} samples to {output_file.name}")


def main():
    parser = argparse.ArgumentParser(description="Scrub private data from capture files")
    parser.add_argument("input", type=Path, help="Input .json.gz capture file")
    parser.add_argument("--per-key", type=int, default=3, help="Events per group key (default: 3)")
    parser.add_argument("--out", type=Path, required=True, help="Output directory for fixtures")
    parser.add_argument("--format", choices=["esf", "ul"], help="Force format (auto-detect if omitted)")

    args = parser.parse_args()

    # Load private strings (required for CLI)
    private_strings = load_private_strings()
    if private_strings is None:
        print("Error: Private strings file not found: tests/private_strings.local.json", file=sys.stderr)
        print("Copy tests/private_strings.local.json.example and fill with real values.", file=sys.stderr)
        return 1

    # Initialize global config with private strings
    global _SCRUB_CONFIG
    _SCRUB_CONFIG = build_scrub_config(private_strings)

    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}")
        return 1

    # Auto-detect format from filename if not specified
    format_type = args.format
    if not format_type:
        name = args.input.name.lower()
        if "esf" in name or "eslogger" in name:
            format_type = "esf"
        elif "ul" in name or "unifiedlog" in name or "log" in name:
            format_type = "ul"
        else:
            print("Error: Cannot auto-detect format. Use --format esf or --format ul")
            return 1

    # Process based on format
    if format_type == "esf":
        process_esf_capture(args.input, args.out, args.per_key)
    else:
        process_ul_capture(args.input, args.out, args.per_key)

    print(f"Done. Scrubbed fixtures written to {args.out}")
    return 0


if __name__ == "__main__":
    exit(main())
