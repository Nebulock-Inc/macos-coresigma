"""
Unit tests for ESF Collector normalization.

Tests verify that:
1. Raw ESF events are properly normalized to ECS format
2. Native ESF fields are flattened with esf.* prefix
3. ECS fields match Elastic Defend conventions
"""
import sys
import os
import pytest

# Add collectors to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'collectors'))

from esf_collector import ESFCollector, ESF_EVENT_TYPE_MAP
from tests.fixtures import (
    SAMPLE_EXEC_EVENT,
    SAMPLE_EXEC_EVENT_SUSPICIOUS_PATH,
    SAMPLE_CREATE_EVENT,
    SAMPLE_UNLINK_EVENT,
    SAMPLE_RENAME_EVENT,
    SAMPLE_SETUID_EVENT,
    SAMPLE_SETGID_EVENT,
    SAMPLE_SIGNAL_EVENT,
    SAMPLE_PTRACE_EVENT,
    SAMPLE_KEXTLOAD_EVENT,
    SAMPLE_XPC_CONNECT_EVENT,
    SAMPLE_MPROTECT_EVENT,
    SAMPLE_AUTH_SUCCESS_EVENT,
    SAMPLE_AUTH_FAILURE_EVENT,
    SAMPLE_MOUNT_EVENT,
    ALL_SAMPLE_EVENTS,
)


@pytest.fixture
def collector():
    """Create an ESF collector instance for testing."""
    return ESFCollector(output="stdout")


class TestEventTypeMapping:
    """Test ESF event type to name mapping."""
    
    def test_exec_event_type(self):
        assert ESF_EVENT_TYPE_MAP[9] == "exec"
    
    def test_create_event_type(self):
        assert ESF_EVENT_TYPE_MAP[13] == "create"
    
    def test_unlink_event_type(self):
        assert ESF_EVENT_TYPE_MAP[19] == "unlink"
    
    def test_rename_event_type(self):
        assert ESF_EVENT_TYPE_MAP[21] == "rename"
    
    def test_setuid_event_type(self):
        assert ESF_EVENT_TYPE_MAP[24] == "setuid"
    
    def test_signal_event_type(self):
        assert ESF_EVENT_TYPE_MAP[27] == "signal"
    
    def test_ptrace_event_type(self):
        assert ESF_EVENT_TYPE_MAP[64] == "ptrace"
    
    def test_kextload_event_type(self):
        assert ESF_EVENT_TYPE_MAP[17] == "kextload"


class TestExecEventNormalization:
    """Test process execution (exec) event normalization."""
    
    def test_exec_event_has_base_ecs_fields(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        assert "@timestamp" in normalized
        assert normalized["event.kind"] == "event"
        assert normalized["event.category"] == "process"
        assert normalized["event.type"] == "start"
        assert normalized["event.action"] == "exec"
        assert normalized["host.os.family"] == "darwin"
    
    def test_exec_event_has_process_fields(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        assert normalized["process.pid"] == 12345
        assert normalized["process.executable"] == "/usr/bin/curl"
        assert normalized["process.name"] == "curl"
        assert normalized["process.parent.pid"] == 1
    
    def test_exec_event_has_command_line(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        assert "process.command_line" in normalized
        assert "curl" in normalized["process.command_line"]
        assert "https://malicious.com" in normalized["process.command_line"]
    
    def test_exec_event_has_user_fields(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        assert normalized["process.user.id"] == "501"
        assert normalized["process.real_user.id"] == "501"
        assert normalized["process.group.id"] == "20"
    
    def test_exec_event_has_code_signature(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        assert normalized["process.code_signature.exists"] is True
        assert normalized["process.code_signature.signing_id"] == "com.apple.curl"
    
    def test_exec_event_has_parent_process(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        assert normalized["process.parent.executable"] == "/bin/bash"
        assert normalized["process.parent.name"] == "bash"
    
    def test_exec_event_has_native_esf_fields(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        # Native ESF fields should be flattened with esf.* prefix
        assert normalized["esf.event_type"] == 9
        assert normalized["esf.event_name"] == "exec"
        assert "esf.process.executable.path" in normalized
        assert "esf.process.audit_token.pid" in normalized
    
    def test_unsigned_process_code_signature(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT_SUSPICIOUS_PATH)
        
        assert normalized["process.code_signature.exists"] is False


class TestFileEventNormalization:
    """Test file event normalization (create, unlink, rename)."""
    
    def test_create_event_has_file_path(self, collector):
        normalized = collector.normalize_event(SAMPLE_CREATE_EVENT)
        
        assert normalized["event.action"] == "create"
        assert normalized["event.category"] == "file"
        assert normalized["event.type"] == "creation"
        assert normalized["file.path"] == "/Library/LaunchAgents/com.malware.plist"
        assert normalized["file.name"] == "com.malware.plist"
    
    def test_unlink_event_has_file_path(self, collector):
        normalized = collector.normalize_event(SAMPLE_UNLINK_EVENT)
        
        assert normalized["event.action"] == "unlink"
        assert normalized["event.category"] == "file"
        assert normalized["event.type"] == "deletion"
        assert normalized["file.path"] == "/private/etc/sudoers.d/custom"
    
    def test_rename_event_has_source_and_dest(self, collector):
        normalized = collector.normalize_event(SAMPLE_RENAME_EVENT)
        
        assert normalized["event.action"] == "rename"
        assert normalized["file.source.path"] == "/tmp/malware.tmp"
        assert normalized["file.target.path"] == "/Users/victim/.hidden_malware"


class TestPrivilegeEscalationEvents:
    """Test setuid/setgid event normalization."""
    
    def test_setuid_event_has_target_user(self, collector):
        normalized = collector.normalize_event(SAMPLE_SETUID_EVENT)
        
        assert normalized["event.action"] == "setuid"
        assert normalized["event.category"] == "iam"
        assert normalized["user.target.id"] == "0"
    
    def test_setgid_event_has_target_group(self, collector):
        normalized = collector.normalize_event(SAMPLE_SETGID_EVENT)
        
        assert normalized["event.action"] == "setgid"
        assert normalized["group.target.id"] == "0"


class TestSignalAndPtraceEvents:
    """Test signal and ptrace event normalization."""
    
    def test_signal_event_has_target_process(self, collector):
        normalized = collector.normalize_event(SAMPLE_SIGNAL_EVENT)
        
        assert normalized["event.action"] == "signal"
        assert normalized["signal.number"] == 9
        assert normalized["target.process.pid"] == 99
        assert normalized["target.process.executable"] == "/usr/libexec/xpcproxy"
    
    def test_ptrace_event_has_target_and_request(self, collector):
        normalized = collector.normalize_event(SAMPLE_PTRACE_EVENT)
        
        assert normalized["event.action"] == "ptrace"
        assert normalized["event.category"] == "intrusion_detection"
        assert normalized["ptrace.request"] == 31
        assert normalized["target.process.pid"] == 500
        assert "Safari" in normalized["target.process.executable"]


class TestKernelExtensionEvents:
    """Test kernel extension load event normalization."""
    
    def test_kextload_event_has_driver_info(self, collector):
        normalized = collector.normalize_event(SAMPLE_KEXTLOAD_EVENT)
        
        assert normalized["event.action"] == "kextload"
        assert normalized["event.category"] == "driver"
        assert normalized["driver.name"] == "com.suspicious.rootkit"
        assert normalized["file.path"] == "/tmp/rootkit.kext"


class TestXPCEvents:
    """Test XPC connection event normalization."""
    
    def test_xpc_connect_event_has_service_name(self, collector):
        normalized = collector.normalize_event(SAMPLE_XPC_CONNECT_EVENT)
        
        assert normalized["event.action"] == "xpc_connect"
        assert normalized["xpc.service_name"] == "com.apple.security.authhost"


class TestMprotectEvents:
    """Test memory protection change event normalization."""
    
    def test_mprotect_event_has_protection_flags(self, collector):
        normalized = collector.normalize_event(SAMPLE_MPROTECT_EVENT)
        
        assert normalized["event.action"] == "mprotect"
        assert normalized["memory.protection"] == 7  # rwx
        assert normalized["memory.protection_string"] == "rwx"


class TestAuthenticationEvents:
    """Test authentication event normalization."""
    
    def test_auth_success_event(self, collector):
        normalized = collector.normalize_event(SAMPLE_AUTH_SUCCESS_EVENT)
        
        assert normalized["event.action"] == "authentication"
        assert normalized["event.category"] == "authentication"
        assert normalized["event.outcome"] == "success"
        assert normalized["authentication.type"] == "password"
    
    def test_auth_failure_event(self, collector):
        normalized = collector.normalize_event(SAMPLE_AUTH_FAILURE_EVENT)
        
        assert normalized["event.outcome"] == "failure"


class TestMountEvents:
    """Test mount event normalization."""
    
    def test_mount_event_has_path_and_type(self, collector):
        normalized = collector.normalize_event(SAMPLE_MOUNT_EVENT)
        
        assert normalized["event.action"] == "mount"
        assert normalized["file.path"] == "/Volumes/UntrustedUSB"
        assert normalized["file.type"] == "msdos"


class TestEventFiltering:
    """Test event filtering logic."""
    
    def test_exec_events_always_kept(self, collector):
        assert collector.should_keep_event(SAMPLE_EXEC_EVENT) is True
    
    def test_security_path_file_creation_kept(self, collector):
        assert collector.should_keep_event(SAMPLE_CREATE_EVENT) is True
    
    def test_is_security_path_detection(self, collector):
        assert collector._is_security_path("/Library/LaunchAgents/test.plist") is True
        assert collector._is_security_path("/Library/LaunchDaemons/test.plist") is True
        assert collector._is_security_path("/private/etc/sudoers") is True
        assert collector._is_security_path("/tmp/random.txt") is False


class TestEntityIdGeneration:
    """Test unique entity ID generation."""
    
    def test_entity_id_generated(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        assert "process.entity_id" in normalized
        assert len(normalized["process.entity_id"]) == 16  # SHA256 truncated
    
    def test_entity_id_unique_per_process(self, collector):
        norm1 = collector.normalize_event(SAMPLE_EXEC_EVENT)
        norm2 = collector.normalize_event(SAMPLE_EXEC_EVENT_SUSPICIOUS_PATH)
        
        # Different PIDs should produce different entity IDs
        assert norm1["process.entity_id"] != norm2["process.entity_id"]


class TestDataStreamFields:
    """Test data stream metadata fields."""
    
    def test_data_stream_fields_present(self, collector):
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        assert normalized["data_stream.type"] == "logs"
        assert "data_stream.dataset" in normalized
        assert normalized["data_stream.namespace"] == "default"


class TestAllEventsNormalize:
    """Test that all sample events normalize without errors."""
    
    def test_all_events_normalize_successfully(self, collector):
        for event in ALL_SAMPLE_EVENTS:
            normalized = collector.normalize_event(event)
            
            # Basic assertions for all events
            assert "@timestamp" in normalized
            assert "event.action" in normalized
            assert "event.category" in normalized
            assert "esf.event_type" in normalized
            assert "process.pid" in normalized or "esf.process.audit_token.pid" in normalized


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
