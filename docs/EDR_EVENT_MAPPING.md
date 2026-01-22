# EDR Event Mapping: ESF/UL to Enterprise EDR Platforms

## Executive Summary

This document provides a comprehensive mapping of macOS Endpoint Security Framework (ESF) event types and Unified Logging (UL) subsystems to equivalent event types/names in major enterprise EDR platforms:

- **CrowdStrike Falcon**
- **SentinelOne**
- **Jamf Protect** (native ESF collection)
- **Microsoft Sentinel** (via Azure Monitor Agent)

---

## Table of Contents

1. [ESF Event Type Mappings](#esf-event-type-mappings)
2. [UL Subsystem Mappings](#ul-subsystem-mappings)
3. [Platform-Specific Notes](#platform-specific-notes)
4. [Detection Rule Equivalency](#detection-rule-equivalency)

---

## ESF Event Type Mappings

### Process Execution Events

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 9 | exec | `ProcessRollup2Event` | `Process` | `exec` | `ProcessCreation` | `ProcessCreation` |
| 11 | fork | `ProcessRollup2Event` (parent-child) | `Process` (parent-child) | `fork` | `ProcessCreation` (parent-child) | `ProcessCreation` (parent-child) |
| 28 | exit | `ProcessRollup2Event` (exit) | `Process` (exit) | `exit` | `ProcessTermination` | `ProcessTermination` |

**Field Mappings:**
- ESF `Image` → CrowdStrike `ImageFileName`, SentinelOne `processPath`, Jamf `Image`, Sentinel `Image`
- ESF `CommandLine` → All platforms: `CommandLine` or `CommandLineArguments`
- ESF `ProcessId` → All platforms: `ProcessId` or `ProcessId`
- ESF `ParentProcessId` → All platforms: `ParentProcessId` or `ParentPid`

---

### File System Events

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 10 | open | `FileOpenEvent` | `File` (read) | `open` | `FileRead` | `FileRead` |
| 13 | create | `FileCreationEvent` | `File` (create) | `create` | `FileCreate` | `FileCreate` |
| 15 | close | `FileCloseEvent` | `File` (close) | `close` | `FileClose` | `FileClose` |
| 19 | unlink | `FileDeletionEvent` | `File` (delete) | `unlink` | `FileDelete` | `FileDelete` |
| 21 | rename | `FileRenamedEvent` | `File` (rename) | `rename` | `FileRename` | `FileRename` |
| 31 | write | `FileWrittenEvent` | `File` (write) | `write` | `FileWrite` | `FileWrite` |
| 32 | setextattr | `FileAttributeChangedEvent` | `File` (metadata) | `setextattr` | `FileAttributeChange` | `FileAttributeChange` |

**Field Mappings:**
- ESF `file.path` → CrowdStrike `FilePath`, SentinelOne `filePath`, Jamf `file.path`, Sentinel `TargetFilePath`
- ESF `source.file.path` → All platforms: `SourceFilePath` or `OldFilePath`
- ESF `destination.file.path` → All platforms: `DestinationFilePath` or `NewFilePath`

---

### Kernel Extension Events

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 17 | kextload | `KernelExtensionLoadEvent` | `KernelExtension` (load) | `kextload` | `DriverLoad` | `DriverLoad` |
| 18 | kextunload | `KernelExtensionUnloadEvent` | `KernelExtension` (unload) | `kextunload` | `DriverUnload` | `DriverUnload` |

**Field Mappings:**
- ESF `kext.path` → CrowdStrike `KextPath`, SentinelOne `kextPath`, Jamf `kext.path`, Sentinel `DriverPath`
- ESF `kext.team_id` → CrowdStrike `KextTeamId`, SentinelOne `teamId`, Jamf `kext.team_id`, Sentinel `DriverSignature`

**Security Note:** These events are critical for detecting unsigned kernel extensions and rootkits. All platforms capture these events.

---

### Process Injection & Memory Protection

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 20 | mprotect | `MemoryProtectionEvent` | `Memory` (protection) | `mprotect` | `MemoryProtectionChange` | `MemoryProtectionChange` |
| 64 | ptrace | `ProcessInjectionEvent` | `Process` (injection) | `ptrace` | `ProcessInjection` | `ProcessInjection` |
| 145 | thread_create | `ThreadCreationEvent` | `Thread` (create) | `thread_create` | `ThreadCreation` | `ThreadCreation` |

**Field Mappings:**
- ESF `mprotect.prot` → CrowdStrike `ProtectionFlags`, SentinelOne `protection`, Jamf `mprotect.prot`, Sentinel `ProtectionFlags`
- ESF `target.process.pid` → All platforms: `TargetProcessId` or `InjectedProcessId`

**Security Note:** W+X (write+execute) memory protection changes are high-fidelity indicators of code injection.

---

### Privilege Escalation Events

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 24 | setuid | `PrivilegeEscalationEvent` | `Process` (setuid) | `setuid` | `PrivilegeEscalation` | `PrivilegeEscalation` |
| 25 | setgid | `PrivilegeEscalationEvent` | `Process` (setgid) | `setgid` | `PrivilegeEscalation` | `PrivilegeEscalation` |

**Field Mappings:**
- ESF `TargetUserId` → CrowdStrike `TargetUid`, SentinelOne `targetUid`, Jamf `TargetUserId`, Sentinel `TargetUserId`
- ESF `TargetGroupId` → All platforms: `TargetGid` or `TargetGroupId`

**Security Note:** Transitions to UID 0 (root) from non-root users are critical privilege escalation indicators.

---

### Process Signals

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 27 | signal | `ProcessSignalEvent` | `Process` (signal) | `signal` | `ProcessSignal` | `ProcessSignal` |

**Field Mappings:**
- ESF `signal.number` → CrowdStrike `SignalNumber`, SentinelOne `signal`, Jamf `signal.number`, Sentinel `SignalNumber`
- ESF `target.process.pid` → All platforms: `TargetProcessId` or `TargetPid`
- ESF `target.process.path` → All platforms: `TargetProcessPath` or `TargetImage`

**Security Note:** SIGKILL (9) sent to security tools (LittleSnitch, etc.) is a defense evasion technique.

---

### XPC (Inter-Process Communication)

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 65 | xpc_connect | `XpcConnectionEvent` | `XPC` (connect) | `xpc_connect` | `XpcConnection` | `XpcConnection` |

**Field Mappings:**
- ESF `xpc.service_name` → CrowdStrike `XpcServiceName`, SentinelOne `serviceName`, Jamf `xpc.service_name`, Sentinel `XpcServiceName`
- ESF `process.path` → All platforms: `ProcessPath` or `SourceProcessPath`

**Security Note:** XPC connections from unusual locations (e.g., /tmp) or to suspicious services indicate privilege escalation attempts.

---

### Authentication Events

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 111 | authentication | `AuthenticationEvent` | `Authentication` | `authentication` | `Authentication` | `Authentication` |

**Field Mappings:**
- ESF `auth.type` → CrowdStrike `AuthType`, SentinelOne `authType`, Jamf `auth.type`, Sentinel `AuthenticationType`
- ESF `auth.success` → All platforms: `AuthSuccess` or `AuthenticationSuccess`
- ESF `user.name` → All platforms: `UserName` or `AccountName`

---

### Code Signing & Security Policy

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 62 | cs_invalidated | `CodeSignatureInvalidEvent` | `CodeSigning` (invalid) | `cs_invalidated` | `CodeSignatureInvalid` | `CodeSignatureInvalid` |
| 94 | cs_invalidated | `CodeSignatureInvalidEvent` | `CodeSigning` (invalid) | `cs_invalidated` | `CodeSignatureInvalid` | `CodeSignatureInvalid` |
| 112 | xp_malware_detected | `MalwareDetectionEvent` | `Malware` (detected) | `xp_malware_detected` | `MalwareDetection` | `MalwareDetection` |
| 113 | xp_malware_remediated | `MalwareRemediationEvent` | `Malware` (remediated) | `xp_malware_remediated` | `MalwareRemediation` | `MalwareRemediation` |
| 146 | gatekeeper_user_override | `GatekeeperOverrideEvent` | `Gatekeeper` (override) | `gatekeeper_user_override` | `GatekeeperOverride` | `GatekeeperOverride` |
| 147 | tcc_modify | `TccModificationEvent` | `TCC` (modify) | `tcc_modify` | `TccModification` | `TccModification` |

**Field Mappings:**
- ESF `code_signature.signing_id` → CrowdStrike `SigningId`, SentinelOne `signingId`, Jamf `code_signature.signing_id`, Sentinel `SigningId`
- ESF `code_signature.team_id` → All platforms: `TeamId` or `CodeSigningTeamId`

**Security Note:** These events are critical for detecting malware, security policy bypasses, and privacy violations.

---

### Filesystem Mount Events

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 22 | mount | `FilesystemMountEvent` | `Filesystem` (mount) | `mount` | `FilesystemMount` | `FilesystemMount` |

**Field Mappings:**
- ESF `mount.path` → All platforms: `MountPath` or `MountPoint`
- ESF `mount.removable` → All platforms: `Removable` or `IsRemovable`

---

### Authorization Framework

| ESF Event | ESF Name | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-----------|----------|-------------|-------------|--------------|---------------------|
| 103 | authorization_petition | `AuthorizationPetitionEvent` | `Authorization` (petition) | `authorization_petition` | `AuthorizationPetition` | `AuthorizationPetition` |
| 104 | authorization_judgement | `AuthorizationJudgementEvent` | `Authorization` (judgement) | `authorization_judgement` | `AuthorizationJudgement` | `AuthorizationJudgement` |

**Field Mappings:**
- ESF `authorization.right` → All platforms: `AuthorizationRight` or `AuthRight`
- ESF `authorization.result` → All platforms: `AuthorizationResult` or `AuthResult`

---

## UL Subsystem Mappings

### TCC (Transparency, Consent, and Control)

| UL Subsystem | Category | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|--------------|----------|-------------|-------------|--------------|---------------------|
| com.apple.TCC | access | `TccAccessEvent` | `TCC` (access) | `tcc_access` | `TccAccess` | `TccAccess` |
| com.apple.TCC | denied | `TccDenialEvent` | `TCC` (denied) | `tcc_denied` | `TccDenial` | `TccDenial` |
| com.apple.TCC | modify | `TccModificationEvent` | `TCC` (modify) | `tcc_modify` | `TccModification` | `TccModification` |

**Field Mappings:**
- UL `service` → All platforms: `TccService` or `Service`
- UL `client` → All platforms: `TccClient` or `ClientPath`

**Security Note:** TCC modifications and unusual access patterns indicate privacy violations and potential malware behavior.

---

### Sudo Events

| UL Subsystem | Category | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|--------------|----------|-------------|-------------|--------------|---------------------|
| com.apple.sudo | execute | `SudoExecutionEvent` | `Sudo` (execute) | `sudo_execute` | `SudoExecution` | `SudoExecution` |
| com.apple.sudo | failure | `SudoFailureEvent` | `Sudo` (failure) | `sudo_failure` | `SudoFailure` | `SudoFailure` |

**Field Mappings:**
- UL `command` → All platforms: `SudoCommand` or `Command`
- UL `user` → All platforms: `SudoUser` or `UserName`

**Security Note:** Sudo executions are privilege escalation indicators. Failed sudo attempts may indicate brute-force attacks.

---

### Gatekeeper Events

| UL Subsystem | Category | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|--------------|----------|-------------|-------------|--------------|---------------------|
| com.apple.gatekeeper | block | `GatekeeperBlockEvent` | `Gatekeeper` (block) | `gatekeeper_block` | `GatekeeperBlock` | `GatekeeperBlock` |
| com.apple.gatekeeper | allow | `GatekeeperAllowEvent` | `Gatekeeper` (allow) | `gatekeeper_allow` | `GatekeeperAllow` | `GatekeeperAllow` |

**Field Mappings:**
- UL `path` → All platforms: `GatekeeperPath` or `BlockedPath`
- UL `reason` → All platforms: `GatekeeperReason` or `BlockReason`

**Security Note:** Gatekeeper blocks indicate unsigned/unnotarized applications, which may be malware.

---

### System Policy (SysPolicy)

| UL Subsystem | Category | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|--------------|----------|-------------|-------------|--------------|---------------------|
| com.apple.syspolicy | evaluation | `SysPolicyEvaluationEvent` | `SysPolicy` (evaluation) | `syspolicy_evaluation` | `SysPolicyEvaluation` | `SysPolicyEvaluation` |
| com.apple.syspolicy | violation | `SysPolicyViolationEvent` | `SysPolicy` (violation) | `syspolicy_violation` | `SysPolicyViolation` | `SysPolicyViolation` |

**Field Mappings:**
- UL `policy` → All platforms: `SysPolicy` or `PolicyName`
- UL `result` → All platforms: `SysPolicyResult` or `EvaluationResult`

---

### Security Daemon (securityd)

| UL Subsystem | Category | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|--------------|----------|-------------|-------------|--------------|---------------------|
| com.apple.securityd | codesign | `CodeSigningEvent` | `CodeSigning` | `securityd_codesign` | `CodeSigning` | `CodeSigning` |
| com.apple.securityd | keychain | `KeychainEvent` | `Keychain` | `securityd_keychain` | `KeychainAccess` | `KeychainAccess` |

**Field Mappings:**
- UL `process` → All platforms: `SecuritydProcess` or `ProcessPath`
- UL `operation` → All platforms: `SecuritydOperation` or `Operation`

---

### Application Layer Firewall (ALF)

| UL Subsystem | Category | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|--------------|----------|-------------|-------------|--------------|---------------------|
| com.apple.alf | block | `FirewallBlockEvent` | `Firewall` (block) | `alf_block` | `FirewallBlock` | `FirewallBlock` |
| com.apple.alf | allow | `FirewallAllowEvent` | `Firewall` (allow) | `alf_allow` | `FirewallAllow` | `FirewallAllow` |

**Field Mappings:**
- UL `source` → All platforms: `FirewallSource` or `SourceIp`
- UL `destination` → All platforms: `FirewallDestination` or `DestinationIp`

---

### Open Directory (User Management)

| UL Subsystem | Category | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|--------------|----------|-------------|-------------|--------------|---------------------|
| com.apple.opendirectoryd | create_user | `UserCreationEvent` | `User` (create) | `od_create_user` | `UserCreation` | `UserCreation` |
| com.apple.opendirectoryd | delete_user | `UserDeletionEvent` | `User` (delete) | `od_delete_user` | `UserDeletion` | `UserDeletion` |
| com.apple.opendirectoryd | modify_password | `PasswordModificationEvent` | `User` (password) | `od_modify_password` | `PasswordModification` | `PasswordModification` |

**Field Mappings:**
- UL `user` → All platforms: `UserName` or `AccountName`
- UL `action` → All platforms: `UserAction` or `Action`

---

### Authorization Framework (UL)

| UL Subsystem | Category | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|--------------|----------|-------------|-------------|--------------|---------------------|
| com.apple.authorization | petition | `AuthorizationPetitionEvent` | `Authorization` (petition) | `authorization_petition` | `AuthorizationPetition` | `AuthorizationPetition` |
| com.apple.authorization | judgement | `AuthorizationJudgementEvent` | `Authorization` (judgement) | `authorization_judgement` | `AuthorizationJudgement` | `AuthorizationJudgement` |

**Field Mappings:**
- UL `right` → All platforms: `AuthorizationRight` or `AuthRight`
- UL `result` → All platforms: `AuthorizationResult` or `AuthResult`

---

## Platform-Specific Notes

### CrowdStrike Falcon

**Event Schema:**
- Events are stored in `ProcessRollup2Event`, `FileOpenEvent`, etc.
- Field names use PascalCase (e.g., `ImageFileName`, `CommandLineArguments`)
- Event types are in the `EventType` field
- All events include `ComputerName`, `UserName`, `Timestamp`

**Query Language:** Falcon Query Language (FQL)

**Example Query:**
```
event_simpleName=ProcessRollup2Event ImageFileName=/bin/bash CommandLine=*curl*
```

**Coverage:** Excellent coverage of ESF events. Native macOS agent provides full ESF event collection.

---

### SentinelOne

**Event Schema:**
- Events are stored in `Process`, `File`, `Network`, etc. tables
- Field names use camelCase (e.g., `processPath`, `commandLine`)
- Event types are in the `eventType` field
- All events include `agentId`, `timestamp`, `endpointName`

**Query Language:** SentinelOne Query Language (SOQL)

**Example Query:**
```
eventType=Process AND processPath=/bin/bash AND commandLine CONTAINS curl
```

**Coverage:** Good coverage of ESF events. Native macOS agent provides ESF event collection.

---

### Jamf Protect

**Event Schema:**
- Events use native ESF event names (e.g., `exec`, `kextload`, `xpc_connect`)
- Field names match ESF field names (e.g., `Image`, `CommandLine`, `file.path`)
- Event types are in the `event_name` field
- All events include `hostname`, `timestamp`, `event_type`

**Query Language:** Elasticsearch Query DSL (Lucene)

**Example Query:**
```
event_name:exec AND Image:/bin/bash AND CommandLine:*curl*
```

**Coverage:** Native ESF collection - 100% coverage of all ESF events. This is the most direct mapping.

**Note:** Jamf Protect is built specifically for macOS and uses ESF directly, so field names and event types match exactly.

---

### Microsoft Sentinel

**Event Schema:**
- Events are stored in `DeviceProcessEvents`, `DeviceFileEvents`, etc.
- Field names use PascalCase (e.g., `ProcessCommandLine`, `FileName`)
- Event types are in the `ActionType` field
- All events include `DeviceName`, `TimeGenerated`, `AccountName`

**Query Language:** KQL (Kusto Query Language)

**Example Query:**
```
DeviceProcessEvents
| where ProcessCommandLine contains "curl"
| where FileName == "/bin/bash"
```

**Coverage:** Good coverage via Azure Monitor Agent. Some ESF events may require custom parsing.

**Note:** Microsoft Sentinel uses the Azure Monitor Agent on macOS, which collects ESF events but may normalize them differently than native ESF.

---

## Detection Rule Equivalency

### Example: Unsigned Kernel Extension Load

**ESF Rule (Sigma):**
```yaml
logsource:
  product: macos
  service: endpointsecurity
  category: kernel_extension
detection:
  selection:
    event_type: 17
    event_name: kextload
  filter:
    kext.team_id: '*'
  condition: selection and not filter
```

**CrowdStrike:**
```
event_simpleName=KernelExtensionLoadEvent KextTeamId=null
```

**SentinelOne:**
```
eventType=KernelExtension AND action=load AND teamId IS NULL
```

**Jamf Protect:**
```
event_name:kextload AND NOT kext.team_id:*
```

**Microsoft Sentinel:**
```
DeviceDriverEvents
| where ActionType == "DriverLoad"
| where DriverSignature == ""
```

---

### Example: SIGKILL to Security Tools

**ESF Rule (Sigma):**
```yaml
logsource:
  product: macos
  service: endpointsecurity
  category: process_signal
detection:
  selection:
    event_type: 27
    event_name: signal
    signal.number: 9
    target.process.path|contains:
      - /LittleSnitch
      - /Lulu
      - /BlockBlock
```

**CrowdStrike:**
```
event_simpleName=ProcessSignalEvent SignalNumber=9 TargetProcessPath=*LittleSnitch*
```

**SentinelOne:**
```
eventType=Process AND action=signal AND signal=9 AND targetProcessPath CONTAINS LittleSnitch
```

**Jamf Protect:**
```
event_name:signal AND signal.number:9 AND target.process.path:(*LittleSnitch* OR *Lulu* OR *BlockBlock*)
```

**Microsoft Sentinel:**
```
DeviceProcessEvents
| where ActionType == "ProcessSignal"
| where SignalNumber == 9
| where TargetProcessPath contains "LittleSnitch"
```

---

## Summary

### Coverage Comparison

| Platform | ESF Coverage | UL Coverage | Native ESF | Field Mapping |
|----------|--------------|-------------|------------|---------------|
| **CrowdStrike** | ✅ Excellent | ⚠️ Limited | ✅ Yes | ⚠️ Normalized |
| **SentinelOne** | ✅ Excellent | ⚠️ Limited | ✅ Yes | ⚠️ Normalized |
| **Jamf Protect** | ✅ 100% | ⚠️ Limited | ✅ Yes | ✅ Native |
| **Microsoft Sentinel** | ✅ Good | ⚠️ Limited | ⚠️ Via Agent | ⚠️ Normalized |

### Key Differences

1. **Field Naming:**
   - **Jamf Protect**: Native ESF field names (exact match)
   - **CrowdStrike/Sentinel**: PascalCase/camelCase normalization
   - **Microsoft Sentinel**: Azure Monitor schema normalization

2. **Event Type Naming:**
   - **Jamf Protect**: Native ESF event names (`exec`, `kextload`)
   - **CrowdStrike**: Event class names (`ProcessRollup2Event`, `KernelExtensionLoadEvent`)
   - **SentinelOne**: Generic types with actions (`Process`, `KernelExtension`)
   - **Microsoft Sentinel**: Action types (`ProcessCreation`, `DriverLoad`)

3. **Query Language:**
   - **Jamf Protect**: Elasticsearch/Lucene (matches our pipeline output)
   - **CrowdStrike**: FQL (Falcon Query Language)
   - **SentinelOne**: SOQL (SentinelOne Query Language)
   - **Microsoft Sentinel**: KQL (Kusto Query Language)

---

## Recommendations

1. **For Jamf Protect Users:**
   - Use our pipeline output directly - field names match exactly
   - Sigma rules convert to queries that work natively
   - No field mapping required

2. **For CrowdStrike/SentinelOne Users:**
   - Field mapping required for Sigma rule conversion
   - Consider creating platform-specific pipelines
   - Use platform query languages for best performance

3. **For Microsoft Sentinel Users:**
   - Field mapping required
   - May need custom parsing for some ESF events
   - Consider using Azure Monitor Agent ESF collection

4. **For Multi-Platform Environments:**
   - Use Sigma rules as the source of truth
   - Convert to platform-specific queries using backends
   - Maintain field mapping documentation

---

## References

- [Apple Endpoint Security Framework Documentation](https://developer.apple.com/documentation/endpointsecurity)
- [CrowdStrike Event Data Dictionary](https://falcon.crowdstrike.com/documentation/86/event-data-dictionary)
- [SentinelOne Event Types](https://usea1.sentinelone.net/api-docs/api-docs/)
- [Jamf Protect Event Reference](https://docs.jamf.com/jamf-protect/documentation/Event-Reference.html)
- [Microsoft Sentinel macOS Data Connectors](https://docs.microsoft.com/en-us/azure/sentinel/connect-macos)

---

*Last Updated: 2025-01-15*
*Document Version: 1.0*

