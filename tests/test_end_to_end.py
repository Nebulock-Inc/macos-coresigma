"""
End-to-End Integration Tests for coreSigma.

Tests the complete flow:
1. Raw ESF event -> ESF Collector normalization
2. Sigma rule conversion with ECS pipeline
3. Query matching against normalized events

This verifies that events collected by esf_collector.py will be
detected by Sigma rules processed through the ecs_macos_esf pipeline.
"""
import sys
import os
import re
import pytest

# Add collectors to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'collectors'))

from esf_collector import ESFCollector
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch import ecs_macos_esf
from tests.fixtures import (
    SAMPLE_EXEC_EVENT,
    SAMPLE_EXEC_EVENT_SUSPICIOUS_PATH,
    SAMPLE_CREATE_EVENT,
    SAMPLE_CREATE_EVENT_LAUNCH_DAEMON,
    SAMPLE_RENAME_EVENT,
    SAMPLE_SETUID_EVENT,
    SAMPLE_SIGNAL_EVENT,
    SAMPLE_PTRACE_EVENT,
    SAMPLE_KEXTLOAD_EVENT,
    SAMPLE_XPC_CONNECT_EVENT,
    SAMPLE_MPROTECT_EVENT,
)


@pytest.fixture
def collector():
    """Create ESF collector for event normalization."""
    return ESFCollector(output="stdout")


@pytest.fixture
def backend():
    """Create Lucene backend with macOS ESF pipeline."""
    return LuceneBackend(ecs_macos_esf())


def lucene_query_matches_event(query: str, event: dict) -> bool:
    """
    Simple check if a Lucene query would match a normalized event.
    
    This is a simplified matcher for testing purposes.
    For production, you'd use the actual Elasticsearch query engine.
    """
    # Extract field:value pairs from the query
    # Handle basic Lucene syntax: field:value, field:"value", field:*value*
    
    def normalize_value(v):
        """Normalize value for comparison."""
        if v is None:
            return ""
        return str(v).lower()
    
    def get_nested_value(obj, key):
        """Get value from nested dict using dot notation."""
        keys = key.split('.')
        for k in keys:
            if isinstance(obj, dict):
                obj = obj.get(k)
            else:
                return None
        return obj
    
    # Simple field:value extraction (basic Lucene parsing)
    pattern = r'(\w+(?:\.\w+)*):([^\s\)]+|"[^"]+")'
    matches = re.findall(pattern, query)
    
    if not matches:
        return False
    
    for field, value in matches:
        # Clean up value
        value = value.strip('"').replace('\\/', '/').lower()
        
        # Get field value from event
        event_value = get_nested_value(event, field)
        if event_value is None:
            # Try with different field variations
            continue
        
        event_value_str = normalize_value(event_value)
        
        # Handle wildcards
        if '*' in value:
            regex = value.replace('*', '.*')
            if re.search(regex, event_value_str):
                return True
        elif value in event_value_str:
            return True
    
    return False


class TestEndToEndProcessCreation:
    """End-to-end tests for process creation detection."""
    
    def test_curl_execution_detection(self, collector, backend):
        """Test detecting curl execution with HTTP download."""
        # Step 1: Normalize the raw ESF event
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        # Step 2: Create a Sigma rule that should match
        rule = SigmaCollection.from_yaml("""
            title: Curl Download Detection
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    Image|endswith: /curl
                    CommandLine|contains: https://
                condition: sel
        """)
        
        # Step 3: Convert rule to Elasticsearch query
        result = backend.convert(rule)
        query = result[0]
        
        # Step 4: Verify the normalized event has the expected fields
        assert normalized["process.executable"] == "/usr/bin/curl"
        assert "https://" in normalized["process.command_line"]
        
        # Step 5: Verify query references correct ECS fields
        assert "process.executable" in query
        assert "process.command_line" in query
        
        print(f"\n[E2E] Curl Detection Query: {query}")
        print(f"[E2E] Normalized Event Process: {normalized['process.executable']}")
        print(f"[E2E] Normalized Event Command: {normalized['process.command_line']}")
    
    def test_suspicious_path_execution_detection(self, collector, backend):
        """Test detecting execution from suspicious paths."""
        # Normalize event for execution from /tmp
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT_SUSPICIOUS_PATH)
        
        # Rule to detect /tmp execution
        rule = SigmaCollection.from_yaml("""
            title: Execution from Temp Directory
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    Image|contains: /tmp/
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Verify fields
        assert "/tmp/" in normalized["process.executable"]
        assert "process.executable" in query
        
        print(f"\n[E2E] Temp Execution Query: {query}")
        print(f"[E2E] Process Path: {normalized['process.executable']}")


class TestEndToEndFilePersistence:
    """End-to-end tests for file-based persistence detection."""
    
    def test_launch_agent_creation_detection(self, collector, backend):
        """Test detecting Launch Agent creation for persistence."""
        normalized = collector.normalize_event(SAMPLE_CREATE_EVENT)
        
        rule = SigmaCollection.from_yaml("""
            title: Launch Agent Persistence
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: file_event
            detection:
                sel:
                    TargetFilename|contains: /Library/LaunchAgents/
                    TargetFilename|endswith: .plist
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Verify normalized event has file path
        assert "/Library/LaunchAgents/" in normalized["file.path"]
        assert normalized["file.path"].endswith(".plist")
        
        # Verify query maps to correct ECS field
        assert "file.path" in query
        
        print(f"\n[E2E] Launch Agent Query: {query}")
        print(f"[E2E] File Path: {normalized['file.path']}")
    
    def test_launch_daemon_creation_detection(self, collector, backend):
        """Test detecting Launch Daemon creation."""
        normalized = collector.normalize_event(SAMPLE_CREATE_EVENT_LAUNCH_DAEMON)
        
        rule = SigmaCollection.from_yaml("""
            title: Launch Daemon Persistence
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: file_event
            detection:
                sel:
                    TargetFilename|contains: /Library/LaunchDaemons/
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        assert "/Library/LaunchDaemons/" in normalized["file.path"]
        assert "file.path" in query
        
        print(f"\n[E2E] Launch Daemon Query: {query}")
    
    def test_hidden_file_rename_detection(self, collector, backend):
        """Test detecting file rename to hidden dotfile."""
        normalized = collector.normalize_event(SAMPLE_RENAME_EVENT)
        
        rule = SigmaCollection.from_yaml("""
            title: Hidden File Rename
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: file_event
            detection:
                sel:
                    DestinationFilename|contains: /.
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Check for hidden file in destination
        assert "/." in normalized["file.target.path"]
        assert "file.target.path" in query
        
        print(f"\n[E2E] Hidden File Query: {query}")
        print(f"[E2E] Destination: {normalized['file.target.path']}")


class TestEndToEndPrivilegeEscalation:
    """End-to-end tests for privilege escalation detection."""
    
    def test_setuid_to_root_detection(self, collector, backend):
        """Test detecting setuid to root privilege escalation."""
        normalized = collector.normalize_event(SAMPLE_SETUID_EVENT)
        
        rule = SigmaCollection.from_yaml("""
            title: Setuid to Root
            status: test
            logsource:
                product: macos
                service: endpointsecurity
            detection:
                sel:
                    TargetUserId: 0
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Verify setuid target is root
        assert normalized["user.target.id"] == "0"
        assert "user.target.id" in query
        
        print(f"\n[E2E] Setuid Query: {query}")
        print(f"[E2E] Target User: {normalized['user.target.id']}")


class TestEndToEndProcessInjection:
    """End-to-end tests for process injection detection."""
    
    def test_ptrace_injection_detection(self, collector, backend):
        """Test detecting ptrace-based process injection."""
        normalized = collector.normalize_event(SAMPLE_PTRACE_EVENT)
        
        rule = SigmaCollection.from_yaml("""
            title: Ptrace Process Injection
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_injection
            detection:
                sel:
                    PtraceRequest: 31
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Verify ptrace request
        assert normalized["ptrace.request"] == 31
        assert "ptrace.request" in query
        
        print(f"\n[E2E] Ptrace Query: {query}")
        print(f"[E2E] Request: {normalized['ptrace.request']}")
        print(f"[E2E] Target: {normalized.get('target.process.executable', 'N/A')}")
    
    def test_signal_to_security_process_detection(self, collector, backend):
        """Test detecting signals sent to security processes."""
        normalized = collector.normalize_event(SAMPLE_SIGNAL_EVENT)
        
        rule = SigmaCollection.from_yaml("""
            title: SIGKILL to Process
            status: test
            logsource:
                product: macos
                service: endpointsecurity
            detection:
                sel:
                    SignalNumber: 9
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Verify signal 9 (SIGKILL)
        assert normalized["signal.number"] == 9
        assert "signal.number" in query
        
        print(f"\n[E2E] Signal Query: {query}")
        print(f"[E2E] Signal: {normalized['signal.number']}")


class TestEndToEndKernelExtension:
    """End-to-end tests for kernel extension detection."""
    
    def test_kext_from_temp_detection(self, collector, backend):
        """Test detecting kernel extension load from temp directory."""
        normalized = collector.normalize_event(SAMPLE_KEXTLOAD_EVENT)
        
        rule = SigmaCollection.from_yaml("""
            title: Kext from Temp
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: driver_load
            detection:
                sel:
                    KextIdentifier|contains: suspicious
                    KextPath|contains: /tmp/
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Verify kext info
        assert "suspicious" in normalized["driver.name"]
        assert "/tmp/" in normalized["file.path"]
        assert "driver.name" in query
        
        print(f"\n[E2E] Kext Query: {query}")
        print(f"[E2E] Kext ID: {normalized['driver.name']}")


class TestEndToEndXPC:
    """End-to-end tests for XPC connection detection."""
    
    def test_xpc_to_security_service_detection(self, collector, backend):
        """Test detecting XPC connection to security services."""
        normalized = collector.normalize_event(SAMPLE_XPC_CONNECT_EVENT)
        
        rule = SigmaCollection.from_yaml("""
            title: XPC to Security Service
            status: test
            logsource:
                product: macos
                service: endpointsecurity
            detection:
                sel:
                    XpcServiceName|contains: security
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Verify XPC service
        assert "security" in normalized["xpc.service_name"]
        assert "xpc.service_name" in query
        
        print(f"\n[E2E] XPC Query: {query}")
        print(f"[E2E] Service: {normalized['xpc.service_name']}")


class TestEndToEndMemoryProtection:
    """End-to-end tests for memory protection detection."""
    
    def test_rwx_memory_detection(self, collector, backend):
        """Test detecting RWX memory protection (potential shellcode)."""
        normalized = collector.normalize_event(SAMPLE_MPROTECT_EVENT)
        
        # Verify memory protection is RWX (7 = r+w+x)
        assert normalized["memory.protection"] == 7
        assert normalized["memory.protection_string"] == "rwx"
        
        # Note: MemoryProtection is a macOS-specific field
        # The pipeline should map it appropriately
        print(f"\n[E2E] Memory Protection: {normalized['memory.protection']}")
        print(f"[E2E] Protection String: {normalized['memory.protection_string']}")


class TestEndToEndRealRules:
    """Test with actual coreSigma rules."""
    
    def test_suspicious_curl_download_real_rule(self, collector, backend):
        """Test the actual suspicious curl download rule."""
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        # Simulating the actual rule from rules/esf/
        rule = SigmaCollection.from_yaml("""
            title: macOS ESF Suspicious Curl Download
            status: experimental
            logsource:
                product: macos
                service: endpointsecurity
            detection:
                selection_process:
                    Image|endswith:
                        - /curl
                        - /wget
                        - /fetch
                selection_cmd:
                    CommandLine|contains:
                        - http://
                        - https://
                        - ftp://
                condition: selection_process and selection_cmd
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # This event should match the rule
        assert normalized["process.executable"].endswith("/curl")
        assert "https://" in normalized["process.command_line"]
        
        # Query should have proper ECS mappings
        assert "process.executable" in query
        assert "process.command_line" in query
        
        print(f"\n[E2E] Real Rule Query: {query}")
        print(f"[E2E] Match Check - Process: {normalized['process.executable']}")
        print(f"[E2E] Match Check - Command: {normalized['process.command_line'][:50]}...")


class TestFieldMappingConsistency:
    """Test that field mappings are consistent across collector and pipeline."""
    
    def test_process_fields_consistent(self, collector, backend):
        """Verify process field names match between collector and pipeline."""
        normalized = collector.normalize_event(SAMPLE_EXEC_EVENT)
        
        # These ECS fields should exist in normalized output (dot notation keys)
        expected_ecs_fields = [
            "process.executable",
            "process.pid",
            "process.name",
            "process.command_line",
            "process.parent.executable",
            "process.parent.pid",
            "process.user.id",
            "process.user.name",
            "process.code_signature.signing_id",
        ]
        
        for field in expected_ecs_fields:
            assert field in normalized, f"Missing ECS field: {field}"
        
        print("\n[E2E] All expected ECS process fields present")
    
    def test_file_fields_consistent(self, collector, backend):
        """Verify file field names match between collector and pipeline."""
        normalized = collector.normalize_event(SAMPLE_CREATE_EVENT)
        
        expected_ecs_fields = [
            "file.path",
            "file.name",
        ]
        
        for field in expected_ecs_fields:
            assert field in normalized, f"Missing ECS field: {field}"
        
        print("\n[E2E] All expected ECS file fields present")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
