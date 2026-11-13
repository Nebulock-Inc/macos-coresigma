"""Tests for fixture privacy and scrubbing."""
import gzip
import json
import re
import subprocess
import sys
from pathlib import Path
import pytest


# Fake values for unit tests (run without the local file)
FAKE_PRIVATE_STRINGS = {
    "hostnames": ["test-host-a"],
    "aws_account_ids": ["111122223333", "444455556666"],
    "instance_ids": ["i-0123456789abcdef0"],
    "mac_serials": ["C02FAKESERIAL"],
    "user_homes": ["/Users/ec2-user", "/Users/jdoe"],
    "usernames": ["ec2-user", "jdoe"],
    "ip_addresses": ["10.11.12.13"],
    "falcon_agent_uuids": ["00000000-1111-2222-3333-444444444444"],
    "personal_names": ["Jane"],
    "capture_bucket": "s3://example-bucket-111122223333/coresigma-test/captures/",
}

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
# Left out of the release (docs/superpowers/plans/2026-11-10-coresigma-refresh.md, Task 22): reviews, the plan and
# specs, captures, the talk and workshop drafts, and reports/ but for RELEASE_REPORTS. Keep the lists the same.
RELEASE_EXCLUDED = ("reviews/", "docs/superpowers/", "captures/", "docs/OBTS_Talk_CFP.md", "docs/OBTS_Workshop_CFP.md",
                    "docs/DEF CON 34 Workshop_ Detailed Outline.md")
RELEASE_REPORTS = ("reports/matrix.json", "reports/verification.json", "reports/sim_windows.json")


def without_credits(rel, text, credit_names):
    """text with each of credit_names (the private strings file's credit_names, never in the repo) taken out of the
    author credits only: rules/**/*.yml author: lines and README.md's last line. No names, no exemption."""
    lines = text.split("\n")
    if rel.startswith("rules/") and rel.endswith(".yml"):
        credits = [i for i, line in enumerate(lines) if line.startswith("author:")]
    elif rel == "README.md":
        credits = [max(i for i, line in enumerate(lines) if line.strip())]
    else:
        return text
    for i in credits:
        for name in credit_names:
            lines[i] = lines[i].replace(name, "")
    return "\n".join(lines)


def release_files():
    """Every file Task 22 copies into the release: tracked or untracked but not ignored (so no sim.env or local
    private strings), minus the exclusions."""
    listed = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT, capture_output=True,
                            text=True)
    if listed.returncode:
        pytest.skip("not a git checkout: the release file set comes from git ls-files")
    names = [n for n in listed.stdout.split("\0") if n and not n.startswith(RELEASE_EXCLUDED)
             and (not n.startswith("reports/") or n in RELEASE_REPORTS)]
    return [ROOT / n for n in names if (ROOT / n).is_file()]  # -c also lists tracked files deleted from the tree


@pytest.fixture
def fake_scrub_config(monkeypatch):
    """Provide fake scrub config for tests that don't need the local file."""
    from scripts.scrub_capture import build_scrub_config, get_username_pattern

    config = build_scrub_config(FAKE_PRIVATE_STRINGS)
    username_pattern = get_username_pattern(config)

    # Monkeypatch the module globals
    monkeypatch.setattr("scripts.scrub_capture._SCRUB_CONFIG", config)

    return config, username_pattern


def test_scrub_removes_private(fake_scrub_config):
    """Test that scrub_event removes all private data (using fake values)."""
    from scripts.scrub_capture import scrub_event

    # Synthetic exec event with fake private values
    # event_type is an integer (9 for exec), event name is key in event dict
    event = {
        "version": 1,
        "seq_num": 12345,
        "global_seq_num": 67890,
        "timestamp": "2024-11-10T10:30:00Z",
        "event_type": 9,  # exec = 9
        "process": {
            "audit_token": {
                "pid": 1234,
                "euid": 501,
                "egid": 20,
                "ruid": 501,
                "rgid": 20
            },
            "executable": {
                "path": "/usr/bin/python3"
            },
            "cwd": {
                "path": "/Users/ec2-user/projects/test"
            },
            "tty": {
                "path": "/dev/ttys000"
            }
        },
        "event": {
            "exec": {
                "target": {
                    "executable": {
                        "path": "/usr/bin/curl"
                    },
                    "cwd": {
                        "path": "/Users/jdoe/downloads"
                    }
                },
                "args": [
                    "curl",
                    "https://test-host-a.compute-1.amazonaws.com/api"
                ],
                "env": [
                    "AWS_SECRET_ACCESS_KEY=secretkey123",
                    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                    "HOME=/Users/ec2-user",
                    "PATH=/usr/local/bin:/usr/bin:/bin"
                ]
            }
        },
        "host": {
            "hostname": "test-host-a",
            "boot_uuid": "12345678-1234-1234-1234-123456789012"
        },
        "metadata": {
            "instance_id": "i-0123456789abcdef0",
            "account_id": "111122223333",
            "serial": "C02FAKESERIAL",
            "region": "us-east-1"
        }
    }

    scrubbed = scrub_event(event)

    # Verify env is dropped
    assert scrubbed["event"]["exec"]["env"] == []

    # Verify user home paths are rewritten
    assert scrubbed["process"]["cwd"]["path"] == "/Users/user/projects/test"
    assert scrubbed["event"]["exec"]["target"]["cwd"]["path"] == "/Users/user/downloads"
    assert all("ec2-user" not in arg for arg in scrubbed["event"]["exec"]["args"])
    assert all("jdoe" not in arg for arg in scrubbed["event"]["exec"]["args"])

    # Verify hostname is replaced
    assert scrubbed["host"]["hostname"] == "host.example"
    assert all("test-host-a" not in arg for arg in scrubbed["event"]["exec"]["args"])

    # Verify instance ID, account ID, and serial are replaced
    assert scrubbed["metadata"]["instance_id"] == "i-00000000000000000"
    assert scrubbed["metadata"]["account_id"] == "000000000000"
    assert scrubbed["metadata"]["serial"] == "SERIALNUMBER"

    # Verify structure is preserved
    assert scrubbed["version"] == event["version"]
    assert scrubbed["event_type"] == event["event_type"]  # Integer preserved
    assert scrubbed["process"]["audit_token"]["pid"] == event["process"]["audit_token"]["pid"]


def test_scrub_removes_usernames(fake_scrub_config):
    """Test that usernames outside /Users/ paths are scrubbed."""
    from scripts.scrub_capture import scrub_event

    # Sudo-shaped ESF event with usernames in fields
    event = {
        "event_type": 124,  # btm_launch_item_add
        "event": {
            "authentication": {
                "type": "sudo",
                "from_username": "ec2-user",
                "to_username": "root",
                "success": True,
                "message": "user jdoe executed sudo command"
            }
        },
        "process": {
            "executable": {"path": "/usr/bin/sudo"}
        }
    }

    scrubbed = scrub_event(event)

    # Verify usernames are replaced
    assert scrubbed["event"]["authentication"]["from_username"] == "user"
    assert scrubbed["event"]["authentication"]["to_username"] == "root"  # root stays
    assert "jdoe" not in scrubbed["event"]["authentication"]["message"]
    assert "user user executed sudo command" in scrubbed["event"]["authentication"]["message"]


def test_scrub_removes_nebulock(fake_scrub_config):
    """Test that nebulock (case-insensitive) is scrubbed."""
    from scripts.scrub_capture import scrub_event

    # Event with nebulock in various cases
    event = {
        "event_type": 124,
        "event": {
            "btm_launch_item_add": {
                "item": {
                    "label": "io.nebulock.coresigma.sim.plist",
                    "path": "/Library/LaunchDaemons/io.Nebulock.agent.plist",
                    "url": "https://NEBULOCK.io/downloads"
                }
            }
        }
    }

    scrubbed = scrub_event(event)

    # Verify nebulock is replaced (case-insensitive)
    item = scrubbed["event"]["btm_launch_item_add"]["item"]
    assert "nebulock" not in item["label"].lower()
    assert "example" in item["label"]
    assert "nebulock" not in item["path"].lower()
    assert "example" in item["path"]
    assert "nebulock" not in item["url"].lower()
    assert "example" in item["url"]


def test_scrub_ul_sudo_line(fake_scrub_config):
    """Test scrubbing of UL sudo log lines with usernames."""
    from scripts.scrub_capture import scrub_event

    # UL event with sudo log line containing username
    event = {
        "subsystem": "com.apple.sudo",
        "processImagePath": "/usr/bin/sudo",
        "message": "ec2-user : TTY=ttys000 ; PWD=/Users/ec2-user ; USER=root ; COMMAND=/usr/bin/true",
        "timestamp": "2024-11-10T10:30:00Z"
    }

    scrubbed = scrub_event(event)

    # Verify username and path are scrubbed
    assert "ec2-user" not in scrubbed["message"]
    assert "user : TTY=ttys000 ; PWD=/Users/user ; USER=root" in scrubbed["message"]


def test_no_generic_private_strings_in_fixtures():
    """No generic private pattern in the fixtures, and no MAC address or instance ID in any release file (always runs)."""
    # Generic forbidden strings (not host-specific); docs and simulations name ec2-user, AWS_ and Nebulock on purpose
    forbidden_case_insensitive = [
        "nebulock",
        "ec2-user",
        "AWS_",
    ]

    # Forbidden patterns. Allowed: the placeholder 00:00:00:00:00:00, and the documentation MACs 00-00-5E-00-53-xx
    # (RFC 7042) in data/fields.csv, the ECS field reference
    mac_pattern = re.compile(r'\b(?!00:00:00:00:00:00\b|00-00-5E-00-53-)([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b')
    # Instance IDs other than the placeholder, the examples' fake ID and AWS's documentation ID (data/fields.csv)
    instance_pattern = re.compile(r'\bi-(?!00000000000000000\b|0123456789abcdef0\b|1234567890abcdef0\b)[0-9a-f]{17}\b')
    # /Users/ pattern (anything other than /Users/user)
    user_home_pattern = re.compile(r'/Users/(?!user\b)[^/\s]+')

    files = release_files()
    for expected in ("README.md", "setup.sh", "rules/esf/macos_http_tools_with_protocol_indicators.yml",
                     "collectors/outputs.py", "tests/fixtures/esf/exec.json", "reports/matrix.json"):
        assert ROOT / expected in files
    assert not [f for f in files if f.relative_to(ROOT).as_posix().startswith(("reviews/", "docs/superpowers/"))]

    violations = []
    for path in files:
        name = path.relative_to(ROOT).as_posix()
        content = path.read_text(errors="replace")

        # Check for MAC addresses (except placeholder)
        mac_matches = mac_pattern.findall(content)
        if mac_matches:
            sample_mac = ''.join(mac_matches[0]) if mac_matches[0] else 'unknown'
            violations.append(f"{name}: contains MAC address pattern (e.g. {sample_mac}...)")

        # Check for instance IDs (except placeholder)
        instance_matches = instance_pattern.findall(content)
        if instance_matches:
            violations.append(f"{name}: contains instance ID pattern (e.g. {instance_matches[0]})")

        if not path.is_relative_to(FIXTURES) or path.suffix not in (".json", ".ndjson"):
            continue
        content_lower = content.lower()

        # Check case-insensitive strings
        for forbidden_str in forbidden_case_insensitive:
            if forbidden_str.lower() in content_lower:
                violations.append(f"{name}: contains '{forbidden_str}' (case-insensitive)")

        # Check for /Users/<name> paths (except /Users/user)
        home_matches = user_home_pattern.findall(content)
        if home_matches:
            violations.append(f"{name}: contains /Users/<name> path (e.g. {home_matches[0]})")

    assert not violations, f"Generic private patterns found:\n" + "\n".join(violations)


def test_no_real_private_strings_in_release_files():
    """No release file contains real host-specific private data (skips without the local file). A personal name is
    allowed only in an author credit, and only as one of the file's credit_names."""
    from scripts.scrub_capture import bucket_name, load_private_strings

    private_strings = load_private_strings()  # tests/private_strings.local.json or $CORESIGMA_PRIVATE_STRINGS
    if private_strings is None:
        pytest.skip("tests/private_strings.local.json not found: the real private strings check, personal names "
                    "included, didn't run")
    credit_names = private_strings.get("credit_names", [])

    # (key, pattern) for each private value; violations name the key, not the value
    checks = [("hostnames", re.compile(re.escape(v), re.IGNORECASE)) for v in private_strings["hostnames"]]
    checks += [("usernames", re.compile(re.escape(v), re.IGNORECASE))
               for v in private_strings["usernames"] if v != "ec2-user"]  # ec2-user is checked in the generic test
    checks += [(key, re.compile(re.escape(v))) for key in ("aws_account_ids", "instance_ids", "mac_serials",
                                                             "ip_addresses", "falcon_agent_uuids")
               for v in private_strings[key]]
    for v in private_strings.get("personal_names", []):  # as typed anywhere, or in any case as a word (as scrubbed)
        checks += [("personal_names", re.compile(re.escape(v))),
                   ("personal_names", re.compile(r'\b' + re.escape(v) + r'\b', re.IGNORECASE))]
    if private_strings.get("capture_bucket"):
        checks.append(("capture_bucket", re.compile(re.escape(bucket_name(private_strings["capture_bucket"])))))

    violations = set()
    for path in release_files():
        rel, text = path.relative_to(ROOT).as_posix(), path.read_text(errors="replace")
        uncredited = without_credits(rel, text, credit_names)
        violations |= {f"{rel}: contains a value from {key}" for key, pattern in checks
                       if pattern.search(uncredited if key == "personal_names" else text)}
    violations = sorted(violations)
    assert not violations, ("Real private strings found (an author credit is exempt only for the private strings "
                            "file's credit_names):\n" + "\n".join(violations))
    if not private_strings.get("personal_names"):
        pytest.skip("no personal_names in the private strings file: the personal-name check didn't run")


def test_author_credit_exempt_only_for_allowlisted_names():
    """Fails closed: without credit_names no credit line is exempt; with them, only those names, only on a rule's
    author: line or README's last line."""
    rule = "title: x\nauthor: Jane Doe - Example, Inc.\ndescription: Jane Doe wrote this\n"
    readme = "# x\nJane Doe set it up\n\nCreated by Jane Doe © 2025\n"
    jane = re.compile(r"\bJane\b", re.IGNORECASE)
    assert without_credits("rules/esf/x.yml", rule, []) == rule
    assert without_credits("README.md", readme, []) == readme
    assert jane.findall(without_credits("rules/esf/x.yml", rule, ["Jane Doe"])) == ["Jane"]  # description: kept
    assert jane.findall(without_credits("README.md", readme, ["Jane Doe"])) == ["Jane"]  # not the last line
    assert without_credits("README.md", readme, ["Jane Roe"]) == readme  # a name not on the list
    assert without_credits("docs/x.md", "author: Jane Doe\n", ["Jane Doe"]) == "author: Jane Doe\n"


def test_scrub_preserves_clean_events(fake_scrub_config):
    """Test that events without private data round-trip identically."""
    from scripts.scrub_capture import scrub_event

    # Event with no private data (REAL eslogger shape)
    clean_event = {
        "version": 1,
        "seq_num": 100,
        "timestamp": "2024-11-10T10:30:00Z",
        "event_type": 9,  # Integer
        "process": {
            "executable": {"path": "/usr/bin/ls"},
            "cwd": {"path": "/tmp"}
        },
        "event": {
            "exec": {
                "target": {
                    "executable": {"path": "/bin/cat"}
                },
                "args": ["cat", "/etc/hosts"],
                "env": []
            }
        }
    }

    scrubbed = scrub_event(clean_event)

    # Should be byte-for-byte identical when serialized
    assert json.dumps(clean_event, sort_keys=True) == json.dumps(scrubbed, sort_keys=True)


def test_cli_esf_mode(tmp_path):
    """Test CLI in ESF mode with synthetic capture (uses fake values)."""
    # Write fake private strings file
    fake_private_file = tmp_path / "fake_private.json"
    fake_private_file.write_text(json.dumps(FAKE_PRIVATE_STRINGS))

    hostname = FAKE_PRIVATE_STRINGS["hostnames"][0]
    account_id = FAKE_PRIVATE_STRINGS["aws_account_ids"][0]
    instance_id = FAKE_PRIVATE_STRINGS["instance_ids"][0]
    serial = FAKE_PRIVATE_STRINGS["mac_serials"][0]

    # Create synthetic ESF capture with values from local file
    events = [
        {
            "event_type": 9,  # exec
            "event": {"exec": {"args": ["curl", f"https://{hostname}.local"]}},
            "process": {"cwd": {"path": "/Users/ec2-user/work"}},
            "metadata": {"instance_id": instance_id}
        },
        {
            "event_type": 9,  # exec
            "event": {"exec": {"args": ["ls"], "env": ["SECRET=value"]}},
            "host": {"hostname": hostname}
        },
        {
            "event_type": 9,  # exec
            "event": {"exec": {"args": ["echo", "third exec"]}},
            "metadata": {"account_id": account_id}
        },
        {
            "event_type": 10,  # open
            "event": {"open": {"path": "/tmp/test"}},
            "metadata": {"serial": serial}
        },
        {
            "event_type": 10,  # open
            "event": {"open": {"path": "/var/log/system.log"}},
        },
    ]

    input_file = tmp_path / "esf.json.gz"
    with gzip.open(input_file, 'wt') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')

    # Run CLI with --per-key 2, pointing at fake private strings file
    output_dir = tmp_path / "fixtures"
    import os
    env = os.environ.copy()
    env["CORESIGMA_PRIVATE_STRINGS"] = str(fake_private_file)
    result = subprocess.run(
        [sys.executable, "scripts/scrub_capture.py",
         str(input_file), "--per-key", "2", "--out", str(output_dir)],
        capture_output=True, text=True,
        cwd=Path(__file__).parent.parent,
        env=env
    )

    assert result.returncode == 0, f"CLI failed: {result.stderr}"

    # Verify ESF grouping by event name (not event_type number)
    esf_dir = output_dir / "esf"
    assert esf_dir.exists()

    exec_file = esf_dir / "exec.json"
    assert exec_file.exists(), "exec.json should exist"

    open_file = esf_dir / "open.json"
    assert open_file.exists(), "open.json should exist"

    # Verify --per-key limit (should be max 2 per event name)
    exec_lines = exec_file.read_text().strip().split('\n')
    assert len(exec_lines) == 2, f"Expected 2 exec events, got {len(exec_lines)}"

    open_lines = open_file.read_text().strip().split('\n')
    assert len(open_lines) == 2, f"Expected 2 open events, got {len(open_lines)}"

    # Verify scrubbing was applied
    exec_content = exec_file.read_text()
    assert "ec2-user" not in exec_content
    assert hostname not in exec_content
    assert instance_id not in exec_content
    assert "/Users/user" in exec_content
    assert "host.example" in exec_content
    assert "i-00000000000000000" in exec_content
    assert '"env": []' in exec_content  # env should be dropped

    open_content = open_file.read_text()
    assert serial not in open_content
    assert "SERIALNUMBER" in open_content


def test_cli_ul_mode(tmp_path):
    """Test CLI in UL mode with synthetic capture (uses fake values)."""
    # Write fake private strings file
    fake_private_file = tmp_path / "fake_private.json"
    fake_private_file.write_text(json.dumps(FAKE_PRIVATE_STRINGS))

    hostname = FAKE_PRIVATE_STRINGS["hostnames"][0]
    account_id = FAKE_PRIVATE_STRINGS["aws_account_ids"][0]
    username = FAKE_PRIVATE_STRINGS["usernames"][1]  # jdoe

    # Create synthetic UL capture
    events = [
        {
            "subsystem": "com.apple.security",
            "message": f"TCC event on host {hostname}",
            "processImagePath": "/usr/libexec/tccd"
        },
        {
            "subsystem": "com.apple.security",
            "processImagePath": "/usr/libexec/tccd",
            "message": f"Account {account_id}"
        },
        {
            "subsystem": "com.apple.security",
            "message": "Third security event"
        },
        {
            "processImagePath": "/usr/sbin/syslogd",
            "message": f"ec2-user : TTY=ttys000 ; PWD=/Users/{username} ; USER=root"
        },
        {
            "processImagePath": "/usr/sbin/syslogd",
            "message": "nebulock agent started"
        },
    ]

    input_file = tmp_path / "ul.json.gz"
    with gzip.open(input_file, 'wt') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')

    # Run CLI with --per-key 2, pointing at fake private strings file
    output_dir = tmp_path / "fixtures"
    import os
    env = os.environ.copy()
    env["CORESIGMA_PRIVATE_STRINGS"] = str(fake_private_file)
    result = subprocess.run(
        [sys.executable, "scripts/scrub_capture.py",
         str(input_file), "--per-key", "2", "--out", str(output_dir)],
        capture_output=True, text=True,
        cwd=Path(__file__).parent.parent,
        env=env
    )

    assert result.returncode == 0, f"CLI failed: {result.stderr}"

    # Verify UL grouping by subsystem / process name
    ul_dir = output_dir / "ul"
    assert ul_dir.exists()

    security_file = ul_dir / "com_apple_security.ndjson"
    assert security_file.exists(), "com_apple_security.ndjson should exist"

    syslogd_file = ul_dir / "syslogd.ndjson"
    assert syslogd_file.exists(), "syslogd.ndjson should exist"

    # Verify --per-key limit
    security_lines = security_file.read_text().strip().split('\n')
    assert len(security_lines) == 2, f"Expected 2 security events, got {len(security_lines)}"

    syslogd_lines = syslogd_file.read_text().strip().split('\n')
    assert len(syslogd_lines) == 2, f"Expected 2 syslogd events, got {len(syslogd_lines)}"

    # Verify scrubbing was applied
    security_content = security_file.read_text()
    assert hostname not in security_content
    assert account_id not in security_content
    assert "host.example" in security_content
    assert "000000000000" in security_content

    syslogd_content = syslogd_file.read_text()
    assert username not in syslogd_content
    assert "ec2-user" not in syslogd_content
    assert "nebulock" not in syslogd_content.lower()
    assert "/Users/user" in syslogd_content
    assert "user : TTY=ttys000" in syslogd_content
    assert "example" in syslogd_content


def test_cli_malformed_json(tmp_path):
    """Test that CLI fails clearly on malformed JSON in private strings file."""
    # Write malformed JSON file
    malformed_file = tmp_path / "malformed.json"
    malformed_file.write_text("{invalid json")

    # Create minimal capture
    input_file = tmp_path / "test.json.gz"
    with gzip.open(input_file, 'wt') as f:
        f.write('{"event_type": 9, "event": {"exec": {}}}\n')

    import os
    env = os.environ.copy()
    env["CORESIGMA_PRIVATE_STRINGS"] = str(malformed_file)

    result = subprocess.run(
        [sys.executable, "scripts/scrub_capture.py",
         str(input_file), "--out", str(tmp_path / "out")],
        capture_output=True, text=True,
        cwd=Path(__file__).parent.parent,
        env=env
    )

    assert result.returncode != 0, "CLI should fail on malformed JSON"
    assert "Malformed JSON" in result.stderr
    assert str(malformed_file) in result.stderr


def test_cli_missing_keys(tmp_path):
    """Test that CLI fails clearly when private strings file is missing required keys."""
    # Write incomplete file (missing required keys)
    incomplete_file = tmp_path / "incomplete.json"
    incomplete_file.write_text(json.dumps({"hostnames": ["test"]}))

    # Create minimal capture
    input_file = tmp_path / "test.json.gz"
    with gzip.open(input_file, 'wt') as f:
        f.write('{"event_type": 9, "event": {"exec": {}}}\n')

    import os
    env = os.environ.copy()
    env["CORESIGMA_PRIVATE_STRINGS"] = str(incomplete_file)

    result = subprocess.run(
        [sys.executable, "scripts/scrub_capture.py",
         str(input_file), "--out", str(tmp_path / "out")],
        capture_output=True, text=True,
        cwd=Path(__file__).parent.parent,
        env=env
    )

    assert result.returncode != 0, "CLI should fail on missing keys"
    assert "Missing required keys" in result.stderr
    assert str(incomplete_file) in result.stderr


def test_scrub_host_ids_from_private_strings(monkeypatch):
    """Host IPs and Falcon agent IDs come from the private strings file; bootUUID is blanked."""
    from scripts.scrub_capture import build_scrub_config, scrub_event

    monkeypatch.setattr("scripts.scrub_capture._SCRUB_CONFIG", build_scrub_config(FAKE_PRIVATE_STRINGS))
    out = json.dumps(scrub_event({
        "bootUUID": "BBBBBBBB-0000-0000-0000-000000000000",
        "eventMessage": "from 10.11.12.13 agent 00000000-1111-2222-3333-444444444444 via 169.254.169.123",
    }))
    assert "10.11.12.13" not in out and "169.254.169.123" not in out
    assert "00000000-1111-2222-3333-444444444444" not in out and "BBBBBBBB" not in out
    assert build_scrub_config(None)["falcon_agent_uuids"] == []


def test_falcon_id_scrubbed_in_any_case_and_dash_form(monkeypatch):
    """An aid stored as 32 lowercase hex digits is also scrubbed upper case and dashed (falconctl's form)."""
    from scripts.scrub_capture import build_scrub_config, scrub_event
    private = dict(FAKE_PRIVATE_STRINGS, falcon_agent_uuids=["0123456789abcdef0123456789abcdef"])
    monkeypatch.setattr("scripts.scrub_capture._SCRUB_CONFIG", build_scrub_config(private))
    out = json.dumps(scrub_event({"a": "aid 0123456789ABCDEF0123456789ABCDEF", "b": "01234567-89ab-cdef-0123-456789abcdef"}))
    assert "0123456789" not in out.lower().replace("-", "")


def test_scrub_personal_names_bucket_and_hostname_in_any_case(monkeypatch):
    """personal_names in any case (whole words), the capture bucket's name, and hostnames in any case."""
    from scripts.scrub_capture import build_scrub_config, scrub_event
    monkeypatch.setattr("scripts.scrub_capture._SCRUB_CONFIG", build_scrub_config(FAKE_PRIVATE_STRINGS))
    out = scrub_event({"a": "JANE copied s3://example-bucket-111122223333/coresigma-test/captures/esf.json.gz",
                       "b": "Test-Host-A.local: jane's notes, Janet's too"})
    assert out == {"a": "Person copied s3://example-bucket/coresigma-test/captures/esf.json.gz",
                   "b": "host.example.local: Person's notes, Janet's too"}


def test_scrub_usernames_and_user_homes_in_any_case(monkeypatch):
    from scripts.scrub_capture import build_scrub_config, scrub_event
    monkeypatch.setattr("scripts.scrub_capture._SCRUB_CONFIG", build_scrub_config(FAKE_PRIVATE_STRINGS))
    out = scrub_event({"a": "JDoe : TTY=ttys000 ; PWD=/users/JDOE/x ; USER=root", "b": "EC2-User logged in; jdoes stays"})
    assert out == {"a": "user : TTY=ttys000 ; PWD=/Users/user/x ; USER=root", "b": "user logged in; jdoes stays"}
