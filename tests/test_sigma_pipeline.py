"""
Sigma Pipeline Integration Tests.

Tests verify that:
1. Sigma rules are properly converted to Elasticsearch queries
2. Field mappings from Sigma taxonomy to ECS work correctly
3. Logsource conditions are properly applied
"""
import pytest
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch import ecs_macos_esf


@pytest.fixture
def pipeline():
    """Create the ECS macOS ESF pipeline."""
    return ecs_macos_esf()


@pytest.fixture
def backend(pipeline):
    """Create a Lucene backend with the macOS ESF pipeline."""
    return LuceneBackend(pipeline)


class TestProcessCreationRules:
    """Test Sigma rules for process creation events."""
    
    def test_process_creation_field_mapping(self, backend):
        """Test that Sigma process fields map to ECS."""
        rule = SigmaCollection.from_yaml("""
            title: Test Process Creation
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    Image: /usr/bin/curl
                    CommandLine|contains: malicious
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        # Verify field mappings
        assert "process.executable" in query
        assert "process.command_line" in query
        assert "curl" in query.lower()
        assert "malicious" in query.lower()
    
    def test_process_with_parent_fields(self, backend):
        """Test parent process field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test Parent Process
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    ParentImage|endswith: /bash
                    Image|endswith: /curl
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "process.parent.executable" in query
        assert "process.executable" in query
    
    def test_process_user_field_mapping(self, backend):
        """Test user field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test User Fields
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    User: root
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "process.user.name" in query
        assert "root" in query


class TestFileEventRules:
    """Test Sigma rules for file events."""
    
    def test_file_creation_field_mapping(self, backend):
        """Test file creation field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test File Creation
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: file_event
            detection:
                sel:
                    TargetFilename|contains: LaunchAgents
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "file.path" in query
        assert "LaunchAgents" in query
    
    def test_file_rename_source_dest_mapping(self, backend):
        """Test file rename source/destination mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test File Rename
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: file_event
            detection:
                sel:
                    SourceFilename|contains: /tmp/
                    DestinationFilename|contains: .hidden
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "file.source.path" in query
        assert "file.target.path" in query


class TestSignalAndPtraceRules:
    """Test Sigma rules for signal and ptrace events."""
    
    def test_signal_event_mapping(self, backend):
        """Test signal event field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test Signal Event
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_event
            detection:
                sel:
                    SignalNumber: 9
                    TargetImage|contains: security
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "signal.number" in query
        assert "target.process.executable" in query
    
    def test_ptrace_event_mapping(self, backend):
        """Test ptrace event field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test Ptrace Event
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
        assert len(result) == 1
        query = result[0]
        
        assert "ptrace.request" in query


class TestPrivilegeEscalationRules:
    """Test Sigma rules for privilege escalation events."""
    
    def test_setuid_event_mapping(self, backend):
        """Test setuid event field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test Setuid Event
            status: test
            logsource:
                product: macos
                service: endpointsecurity
            detection:
                sel:
                    TargetUserId: 0
                    UserId: 501
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "user.target.id" in query
        assert "process.user.id" in query


class TestCodeSignatureRules:
    """Test Sigma rules for code signature events."""
    
    def test_code_signature_field_mapping(self, backend):
        """Test code signature field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test Code Signature
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    SigningID|contains: malware
                    TeamID: ""
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "process.code_signature.signing_id" in query
        assert "process.code_signature.team_id" in query


class TestKernelExtensionRules:
    """Test Sigma rules for kernel extension events."""
    
    def test_kext_field_mapping(self, backend):
        """Test kernel extension field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test Kext Event
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: driver_load
            detection:
                sel:
                    KextIdentifier|contains: suspicious
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "driver.name" in query


class TestXPCRules:
    """Test Sigma rules for XPC events."""
    
    def test_xpc_service_field_mapping(self, backend):
        """Test XPC service field mapping."""
        rule = SigmaCollection.from_yaml("""
            title: Test XPC Event
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
        assert len(result) == 1
        query = result[0]
        
        assert "xpc.service_name" in query


class TestLogsourceConditions:
    """Test that logsource conditions are properly applied."""
    
    def test_process_creation_adds_event_action(self, backend):
        """Test that process_creation adds event.action condition."""
        rule = SigmaCollection.from_yaml("""
            title: Test Event Action
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    Image: /usr/bin/curl
                condition: sel
        """)
        
        result = backend.convert(rule)
        query = result[0]
        
        # Should include event.action:exec or esf.event_type:9
        assert "event.action" in query or "esf.event_type" in query
    
    def test_file_event_adds_event_category(self, backend):
        """Test that file_event logsource works."""
        rule = SigmaCollection.from_yaml("""
            title: Test File Event Category
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: file_event
            detection:
                sel:
                    TargetFilename|contains: /tmp/
                condition: sel
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1


class TestComplexRules:
    """Test complex Sigma rules with multiple conditions."""
    
    def test_rule_with_or_condition(self, backend):
        """Test rule with OR condition."""
        rule = SigmaCollection.from_yaml("""
            title: Test OR Condition
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel_curl:
                    Image|endswith: /curl
                sel_wget:
                    Image|endswith: /wget
                condition: sel_curl or sel_wget
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "curl" in query.lower()
        assert "wget" in query.lower()
    
    def test_rule_with_and_condition(self, backend):
        """Test rule with AND condition."""
        rule = SigmaCollection.from_yaml("""
            title: Test AND Condition
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel_process:
                    Image|endswith: /curl
                sel_args:
                    CommandLine|contains: https://
                condition: sel_process and sel_args
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "process.executable" in query
        assert "process.command_line" in query
    
    def test_rule_with_not_condition(self, backend):
        """Test rule with NOT condition."""
        rule = SigmaCollection.from_yaml("""
            title: Test NOT Condition
            status: test
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                sel:
                    Image|endswith: /curl
                filter:
                    User: root
                condition: sel and not filter
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "NOT" in query or "not" in query.lower()


class TestRealWorldRules:
    """Test with rules similar to actual coreSigma rules."""
    
    def test_suspicious_curl_download_rule(self, backend):
        """Test suspicious curl download detection."""
        rule = SigmaCollection.from_yaml("""
            title: macOS ESF Suspicious Curl Download
            status: experimental
            logsource:
                product: macos
                service: endpointsecurity
                category: process_creation
            detection:
                selection_process:
                    Image|endswith:
                        - /curl
                        - /wget
                selection_cmd:
                    CommandLine|contains:
                        - http://
                        - https://
                condition: selection_process and selection_cmd
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        # Should map to ECS fields
        assert "process.executable" in query
        assert "process.command_line" in query

    def test_osascript_password_prompt_rule(self, backend):
        """Test AMOS-style osascript hidden password prompt detection."""
        rule = SigmaCollection.from_yaml("""
            title: macOS ESF Osascript Hidden Password Prompt
            status: experimental
            logsource:
                product: macos
                service: endpointsecurity
            detection:
                selection_process:
                    Image|endswith: /osascript
                selection_cmd:
                    CommandLine|contains|all:
                        - display dialog
                        - hidden answer
                condition: selection_process and selection_cmd
        """)

        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]

        # Should map to ECS fields
        assert "process.executable" in query
        assert "process.command_line" in query
        assert "hidden" in query

    def test_persistence_via_launch_agent_rule(self, backend):
        """Test launch agent persistence detection."""
        rule = SigmaCollection.from_yaml("""
            title: macOS Launch Agent Persistence
            status: experimental
            logsource:
                product: macos
                service: endpointsecurity
                category: file_event
            detection:
                selection:
                    TargetFilename|contains:
                        - /Library/LaunchAgents/
                        - /Library/LaunchDaemons/
                    TargetFilename|endswith: .plist
                condition: selection
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "file.path" in query
        assert "LaunchAgents" in query or "LaunchDaemons" in query
    
    def test_setuid_privilege_escalation_rule(self, backend):
        """Test setuid privilege escalation detection."""
        rule = SigmaCollection.from_yaml("""
            title: macOS Setuid Privilege Escalation
            status: experimental
            logsource:
                product: macos
                service: endpointsecurity
            detection:
                selection_to_root:
                    TargetUserId: 0
                filter_root_source:
                    UserId: 0
                condition: selection_to_root and not filter_root_source
        """)
        
        result = backend.convert(rule)
        assert len(result) == 1
        query = result[0]
        
        assert "user.target.id" in query
        assert "process.user.id" in query


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
