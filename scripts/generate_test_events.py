#!/usr/bin/env python3
"""
Generate test events that trigger Sigma/ESF rules.

Run this AFTER starting the ESF collector to generate events
that will be captured and should trigger detection rules.

This covers ESF rules only; scripts/generate_ul_events.py generates Unified Log events.
Rules are created disabled: enable them with `deploy_sigma_rules.py --enable`.

    python3 scripts/generate_test_events.py [--dry-run]
"""
import argparse
import os
import subprocess
import time

def run_cmd(cmd, description, dry_run=False, shell=True):
    """Run a command and print status; with dry_run, print the command instead."""
    print(f"  → {description}")
    if dry_run:
        print(f"    $ {cmd}")
        return
    try:
        if shell:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        else:
            subprocess.run(cmd, capture_output=True, timeout=5)
    except Exception as e:
        print(f"    (Note: {e})")

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--dry-run", action="store_true", help="print the commands and files without running or writing them")
    dry_run = parser.parse_args(argv).dry_run
    print("=" * 60)
    print("Generating Test Events for Sigma Rule Detection")
    print("=" * 60)
    print("\nMake sure the ESF collector is running!")
    print("Events will be generated that should trigger various rules.\n")
    
    pid = os.getpid()
    
    # 1. Process execution from temporary directories
    print("\n[1] Process Execution from Temp Directories")
    print("    Rule: process_execution_suspicious.yml")
    run_cmd(f"touch /tmp/test_exec_{pid}", "Creating file in /tmp", dry_run)
    run_cmd("/bin/bash -c 'echo test_sigma'", "Running bash -c", dry_run)
    run_cmd("python3 -c 'print(1)'", "Running python3 -c", dry_run)
    run_cmd(f"rm -f /tmp/test_exec_{pid}", "Removing the /tmp file", dry_run)
    
    # 2. File creation in persistence locations
    print("\n[2] File Creation in Persistence Locations")
    print("    Rule: file_creation_persistence.yml, macos_esf_launch_persistence_creation.yml")
    test_plist = os.path.expanduser(f"~/Library/LaunchAgents/.test_sigma_{pid}.plist")
    if dry_run:
        print(f"  → would create and remove {test_plist}")
    else:
        try:
            with open(test_plist, 'w') as f:
                f.write("<!-- test -->")
            print(f"  → Created {test_plist}")
            time.sleep(0.5)
            os.remove(test_plist)
            print(f"  → Removed {test_plist}")
        except OSError as e:  # no ~/Library/LaunchAgents on a fresh account, or no permission: skip this step only
            print(f"  → (skipped: {e.strerror} for {test_plist})")
    
    # 3. Curl/wget downloads
    print("\n[3] Network Download Tools")
    print("    Rule: macos_http_tools_with_protocol_indicators.yml")
    run_cmd("curl -s -o /dev/null https://example.com", "curl https://example.com", dry_run)
    run_cmd("curl -s -o /dev/null http://example.com", "curl http://example.com", dry_run)
    
    # 4. SSH commands
    print("\n[4] SSH Connection Detection")
    print("    Rule: macos_ssh_connection_detection.yml")
    run_cmd("ssh -V", "ssh -V (version check)", dry_run)
    
    # 5. Sensitive file access
    print("\n[5] Sensitive File Access")
    print("    Rule: macos_esf_sensitive_file_access.yml")
    run_cmd("cat /etc/hosts > /dev/null", "Reading /etc/hosts", dry_run)
    run_cmd("cat /etc/passwd > /dev/null", "Reading /etc/passwd", dry_run)
    
    # 6. Hidden file creation (dotfiles)
    print("\n[6] Hidden File Creation")
    print("    Rule: macos_esf_rename_to_hidden_dotfile.yml")
    hidden_file = f"/tmp/.hidden_sigma_{pid}"
    run_cmd(f"touch {hidden_file}", f"Creating {hidden_file}", dry_run)
    run_cmd(f"rm -f {hidden_file}", f"Removing {hidden_file}", dry_run)
    
    # 7. Network tools
    print("\n[7] Network Utility Tools")
    print("    Rule: macos_network_utility_tools_for_c2.yml")
    run_cmd("nc -h 2>/dev/null || true", "netcat help", dry_run)
    run_cmd("nslookup example.com 2>/dev/null || true", "nslookup", dry_run)
    
    # 8. Data compression tools
    print("\n[8] Data Compression Tools")
    print("    Rule: macos_data_compression_tools.yml")
    run_cmd("tar --version > /dev/null", "tar version", dry_run)
    run_cmd("gzip --version > /dev/null", "gzip version", dry_run)
    
    # 9. Git operations (common, will generate close events)
    print("\n[9] Git Operations (generates file events)")
    run_cmd("git status 2>/dev/null || true", "git status", dry_run)
    
    # 10. File operations in /etc
    print("\n[10] File Operations in Sensitive Directories")
    print("    Rule: macos_esf_deletion_in_sensitive_directories.yml")
    # Just read operations - we can't delete from /etc
    run_cmd("ls -la /etc/sudoers 2>/dev/null || true", "Listing /etc/sudoers", dry_run)
    
    # Cleanup
    print("\n" + "=" * 60)
    print("Test Events Generated!")
    print("=" * 60)
    print("\nCheck Kibana Discover or Dashboard to see captured events.")
    print("Filter by time range: Last 5 minutes")
    print("\nKey fields to examine:")
    print("  - event.action (exec, open, close, create, etc.)")
    print("  - process.executable")
    print("  - process.command_line")
    print("  - file.path")

if __name__ == "__main__":
    main()
