# Cross-Platform Information Model: Enterprise EDR Event Mapping

## Executive Summary

This document defines a unified, operating system-agnostic information model for security event telemetry using **enterprise EDR event types and names** as the primary abstraction layer. It maps EDR events to underlying macOS and Windows OS events, enabling cross-platform detection rule development and security operations.

**Goal:** Create a taxonomy that allows security teams to write detection rules and queries using enterprise EDR event types that work conceptually across both macOS and Windows, with platform-specific field mappings.

**Primary Mapping Layer:** Enterprise EDR Platforms
- **CrowdStrike Falcon**
- **SentinelOne**
- **Jamf Protect** (native ESF collection)
- **Microsoft Sentinel** (via Azure Monitor Agent)

**Reference Layer:** OS-Native Events
- macOS: Endpoint Security Framework (ESF) and Unified Logging (UL)
- Windows: Sysmon and Security Event Log

---

## Table of Contents

1. [Information Model Categories](#information-model-categories)
2. [EDR Event Type Mappings](#edr-event-type-mappings)
3. [OS Event Reference Mappings](#os-event-reference-mappings)
4. [Unified Field Mappings](#unified-field-mappings)
5. [Cross-Platform Detection Examples](#cross-platform-detection-examples)
6. [Platform-Specific Considerations](#platform-specific-considerations)

---

## Information Model Categories

The information model organizes events into 12 high-level categories that are conceptually equivalent across platforms:

1. **Process Lifecycle** - Process creation, termination, and execution
2. **File System Operations** - File create, read, write, delete, rename
3. **Network Activity** - Network connections, DNS queries
4. **Authentication & Authorization** - User logons, privilege changes
5. **Privilege Escalation** - Elevation of privileges, UAC/sudo
6. **Code Injection & Memory** - Process injection, memory protection changes
7. **Driver/Kernel Extensions** - Kernel module loading/unloading
8. **Persistence Mechanisms** - Scheduled tasks, services, launch agents
9. **Security Policy** - Antivirus, code signing, security controls
10. **Configuration Changes** - Registry/plist modifications, system config
11. **User & Account Management** - User creation, deletion, password changes
12. **System Integrity** - Time changes, audit policy modifications

---

## EDR Event Type Mappings

### 1. Process Lifecycle

#### Process Creation

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `ProcessRollup2Event` | `Process` | `exec` | `ProcessCreation` | See OS Reference |
| **Event Name** | `ProcessRollup2Event` | `Process` (create) | `exec` | `ProcessCreation` | - |
| **Description** | Process creation | Process creation | Process execution | Process creation | - |

**Unified EDR Fields:**
- `ProcessPath` / `ImageFileName` / `Image` - Executable path
- `CommandLine` / `CommandLineArguments` - Full command line arguments
- `ProcessId` - Process ID
- `ParentProcessId` / `ParentPid` - Parent process ID
- `User` / `UserName` / `AccountName` - Executing user
- `UserId` - User ID
- `WorkingDirectory` / `CurrentDirectory` - Working directory
- `IntegrityLevel` / `EffectiveUserId` - Privilege level

**EDR Platform Field Names:**
- **CrowdStrike**: `ImageFileName`, `CommandLine`, `ProcessId`, `ParentProcessId`, `UserName`, `UserId`
- **SentinelOne**: `processPath`, `commandLine`, `processId`, `parentProcessId`, `userName`, `userId`
- **Jamf Protect**: `Image`, `CommandLine`, `ProcessId`, `ParentProcessId`, `User`, `UserId`
- **Microsoft Sentinel**: `Image`, `ProcessCommandLine`, `ProcessId`, `ParentProcessId`, `AccountName`, `AccountSid`

**OS Event Reference:**
- **macOS ESF**: Event type 9 (`exec`)
- **Windows Sysmon**: Event ID 1 (`ProcessCreate`)
- **Windows Security**: Event ID 4688 (`ProcessCreation`)

---

#### Process Termination

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `ProcessRollup2Event` | `Process` | `exit` | `ProcessTermination` | See OS Reference |
| **Event Name** | `ProcessRollup2Event` (exit) | `Process` (exit) | `exit` | `ProcessTermination` | - |
| **Description** | Process termination | Process termination | Process exit | Process termination | - |

**Unified EDR Fields:**
- `ProcessId` - Terminated process ID
- `ExitCode` - Process exit code
- `ProcessPath` / `ImageFileName` / `Image` - Executable path

**OS Event Reference:**
- **macOS ESF**: Event type 28 (`exit`)
- **Windows Sysmon**: Event ID 5 (`ProcessTerminate`)
- **Windows Security**: Event ID 4689 (`ProcessTermination`)

---

#### Process Fork (macOS-specific)

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `ProcessRollup2Event` | `Process` | `fork` | `ProcessCreation` (parent-child) | See OS Reference |
| **Event Name** | `ProcessRollup2Event` (parent-child) | `Process` (parent-child) | `fork` | `ProcessCreation` (parent-child) | - |
| **Description** | Process fork | Process fork | Process fork | Process creation (parent-child) | - |

**Note:** Windows doesn't have a direct fork equivalent. Process creation events show parent-child relationships.

**OS Event Reference:**
- **macOS ESF**: Event type 11 (`fork`)
- **Windows**: No direct equivalent (use parent-child relationship in process creation)

---

### 2. File System Operations

#### File Creation

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FileCreationEvent` | `File` | `create` | `FileCreate` | See OS Reference |
| **Event Name** | `FileCreationEvent` | `File` (create) | `create` | `FileCreate` | - |
| **Description** | File creation | File creation | File creation | File creation | - |

**Unified EDR Fields:**
- `FilePath` / `TargetFilename` / `filePath` - Created file path
- `ProcessPath` / `ImageFileName` / `Image` - Process that created the file
- `ProcessId` - Process ID
- `User` / `UserName` - User who created the file

**EDR Platform Field Names:**
- **CrowdStrike**: `FilePath`, `ImageFileName`, `ProcessId`, `UserName`
- **SentinelOne**: `filePath`, `processPath`, `processId`, `userName`
- **Jamf Protect**: `file.path`, `Image`, `ProcessId`, `User`
- **Microsoft Sentinel**: `TargetFilePath`, `Image`, `ProcessId`, `AccountName`

**OS Event Reference:**
- **macOS ESF**: Event type 13 (`create`)
- **Windows Sysmon**: Event ID 11 (`FileCreate`)
- **Windows Security**: Event ID 4663 (`FileCreation`)

---

#### File Read/Open

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FileOpenEvent` | `File` | `open` | `FileRead` | See OS Reference |
| **Event Name** | `FileOpenEvent` | `File` (read) | `open` | `FileRead` | - |
| **Description** | File open/read | File read | File open | File read | - |

**Unified EDR Fields:**
- `FilePath` / `TargetFilename` / `filePath` - File path accessed
- `ProcessPath` / `ImageFileName` / `Image` - Process accessing the file
- `AccessMask` - Access permissions (Windows)

**OS Event Reference:**
- **macOS ESF**: Event type 10 (`open`)
- **Windows Sysmon**: Event ID 10 (`FileRead`)
- **Windows Security**: Event ID 4663 (`FileAccess`)

---

#### File Write

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FileWrittenEvent` | `File` | `write` | `FileWrite` | See OS Reference |
| **Event Name** | `FileWrittenEvent` | `File` (write) | `write` | `FileWrite` | - |
| **Description** | File write/modification | File write | File write | File write | - |

**Unified EDR Fields:**
- `FilePath` / `TargetFilename` / `filePath` - File path written
- `ProcessPath` / `ImageFileName` / `Image` - Process writing the file
- `FileSize` - File size (if available)

**OS Event Reference:**
- **macOS ESF**: Event type 31 (`write`)
- **Windows Sysmon**: Event ID 11 (`FileWrite`)
- **Windows Security**: Event ID 4663 (`FileModification`)

---

#### File Deletion

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FileDeletionEvent` | `File` | `unlink` | `FileDelete` | See OS Reference |
| **Event Name** | `FileDeletionEvent` | `File` (delete) | `unlink` | `FileDelete` | - |
| **Description** | File deletion | File deletion | File deletion | File deletion | - |

**Unified EDR Fields:**
- `FilePath` / `TargetFilename` / `filePath` - Deleted file path
- `ProcessPath` / `ImageFileName` / `Image` - Process that deleted the file

**OS Event Reference:**
- **macOS ESF**: Event type 19 (`unlink`)
- **Windows Sysmon**: Event ID 23 (`FileDelete`)
- **Windows Security**: Event ID 4660 (`FileDeletion`)

---

#### File Rename

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FileRenamedEvent` | `File` | `rename` | `FileRename` | See OS Reference |
| **Event Name** | `FileRenamedEvent` | `File` (rename) | `rename` | `FileRename` | - |
| **Description** | File rename/move | File rename | File rename | File rename | - |

**Unified EDR Fields:**
- `SourceFilePath` / `SourceFilename` / `OldFilePath` - Original file path
- `DestinationFilePath` / `DestinationFilename` / `NewFilePath` - New file path
- `ProcessPath` / `ImageFileName` / `Image` - Process performing the rename

**OS Event Reference:**
- **macOS ESF**: Event type 21 (`rename`)
- **Windows Sysmon**: Event ID 2 (`FileRename`)
- **Windows Security**: Event ID 4663 (`FileRename`)

---

### 3. Network Activity

#### Network Connection

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `NetworkConnectEvent` | `Network` | N/A (via NetworkExtension) | `NetworkConnection` | See OS Reference |
| **Event Name** | `NetworkConnectEvent` | `Network` (connect) | N/A | `NetworkConnection` | - |
| **Description** | Network connection established | Network connection | Network connection | Network connection | - |

**Unified EDR Fields:**
- `SourceIp` / `SourceAddress` - Source IP address
- `SourcePort` - Source port
- `DestinationIp` / `DestinationAddress` - Destination IP address
- `DestinationPort` - Destination port
- `Protocol` - Protocol (TCP/UDP)
- `ProcessPath` / `ImageFileName` / `Image` - Process making the connection
- `ProcessId` - Process ID

**EDR Platform Field Names:**
- **CrowdStrike**: `LocalAddress`, `LocalPort`, `RemoteAddress`, `RemotePort`, `Protocol`, `ImageFileName`, `ProcessId`
- **SentinelOne**: `sourceIp`, `sourcePort`, `destinationIp`, `destinationPort`, `protocol`, `processPath`, `processId`
- **Jamf Protect**: N/A (typically via NetworkExtension framework)
- **Microsoft Sentinel**: `SourceAddress`, `SourcePort`, `DestinationAddress`, `DestinationPort`, `Protocol`, `Image`, `ProcessId`

**OS Event Reference:**
- **macOS**: NetworkExtension framework or third-party tools
- **Windows Sysmon**: Event ID 3 (`NetworkConnect`)
- **Windows Security**: Event ID 5156 (`NetworkConnection`)

---

#### DNS Query

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `DnsQueryEvent` | `Dns` | N/A | `DnsQuery` | See OS Reference |
| **Event Name** | `DnsQueryEvent` | `Dns` (query) | N/A | `DnsQuery` | - |
| **Description** | DNS query | DNS query | DNS query | DNS query | - |

**Unified EDR Fields:**
- `QueryName` / `DomainName` - DNS query name
- `QueryType` - DNS query type (A, AAAA, etc.)
- `ProcessPath` / `ImageFileName` / `Image` - Process making the query
- `ResponseCode` - DNS response code

**OS Event Reference:**
- **macOS**: NetworkExtension framework or third-party tools
- **Windows Sysmon**: Event ID 22 (`DnsQuery`)
- **Windows Security**: Event ID 800 (ETW) (`DnsQuery`)

---

### 4. Authentication & Authorization

#### User Logon

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `AuthenticationEvent` | `Authentication` | `authentication` | `Authentication` | See OS Reference |
| **Event Name** | `AuthenticationEvent` | `Authentication` (logon) | `authentication` | `Logon` | - |
| **Description** | User authentication/logon | User logon | User authentication | Successful logon | - |

**Unified EDR Fields:**
- `UserName` / `AccountName` - Username
- `UserId` / `AccountSid` - User ID
- `LogonType` - Logon type (interactive, network, etc.)
- `SourceIp` / `IpAddress` - Source IP (for network logons)
- `AuthenticationPackage` / `AuthType` - Authentication method
- `LogonId` - Logon session ID

**EDR Platform Field Names:**
- **CrowdStrike**: `UserName`, `UserId`, `LogonType`, `SourceIp`, `AuthType`, `LogonId`
- **SentinelOne**: `userName`, `userId`, `logonType`, `sourceIp`, `authType`, `logonId`
- **Jamf Protect**: `User`, `UserId`, `auth.type`, N/A, `auth.type`, N/A
- **Microsoft Sentinel**: `AccountName`, `AccountSid`, `LogonType`, `IpAddress`, `AuthenticationPackageName`, `LogonId`

**OS Event Reference:**
- **macOS ESF**: Event type 111 (`authentication`)
- **macOS UL**: `com.apple.opendirectoryd` (login events)
- **Windows Security**: Event ID 4624 (`Logon`)

---

#### User Logoff

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `LogoffEvent` | `Authentication` | N/A | `Logoff` | See OS Reference |
| **Event Name** | `LogoffEvent` | `Authentication` (logoff) | N/A | `Logoff` | - |
| **Description** | User logoff | User logoff | User logoff | Account logged off | - |

**Unified EDR Fields:**
- `UserName` / `AccountName` - Username
- `LogonId` - Logon session ID

**OS Event Reference:**
- **macOS UL**: `com.apple.opendirectoryd` (logout events)
- **Windows Security**: Event ID 4634 (`Logoff`)

---

#### Failed Authentication

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `AuthenticationFailureEvent` | `Authentication` | `authentication` (failed) | `LogonFailure` | See OS Reference |
| **Event Name** | `AuthenticationFailureEvent` | `Authentication` (failure) | `authentication` (failed) | `LogonFailure` | - |
| **Description** | Failed authentication | Failed logon | Failed authentication | Failed logon attempt | - |

**Unified EDR Fields:**
- `UserName` / `AccountName` - Attempted username
- `FailureReason` - Reason for failure
- `SourceIp` / `IpAddress` - Source IP

**OS Event Reference:**
- **macOS ESF**: Event type 111 (`authentication`) with failure status
- **macOS UL**: `com.apple.sudo` (failed sudo)
- **Windows Security**: Event ID 4625 (`LogonFailure`)

---

### 5. Privilege Escalation

#### Privilege Escalation (Setuid/Setgid)

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `PrivilegeEscalationEvent` | `Process` | `setuid`, `setgid` | `PrivilegeEscalation` | See OS Reference |
| **Event Name** | `PrivilegeEscalationEvent` | `Process` (setuid/setgid) | `setuid`, `setgid` | `PrivilegeEscalation` | - |
| **Description** | Privilege elevation | Privilege elevation | Setuid/setgid | Special privileges assigned | - |

**Unified EDR Fields:**
- `SourceUserId` / `UserId` - Original user ID
- `TargetUserId` - Elevated user ID
- `ProcessPath` / `ImageFileName` / `Image` - Process performing escalation
- `CommandLine` - Command executed with elevated privileges

**EDR Platform Field Names:**
- **CrowdStrike**: `UserId`, `TargetUid`, `ImageFileName`, `CommandLine`
- **SentinelOne**: `userId`, `targetUid`, `processPath`, `commandLine`
- **Jamf Protect**: `UserId`, `TargetUserId`, `Image`, `CommandLine`
- **Microsoft Sentinel**: `AccountSid`, `TargetUserId`, `Image`, `ProcessCommandLine`

**OS Event Reference:**
- **macOS ESF**: Event type 24 (`setuid`), Event type 25 (`setgid`)
- **macOS UL**: `com.apple.sudo` (sudo execution)
- **Windows Security**: Event ID 4672 (`PrivilegeEscalation`)

---

#### UAC Elevation (Windows) / Sudo (macOS)

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `UACElevationEvent` | `Process` | N/A | `UACElevation` | See OS Reference |
| **Event Name** | `UACElevationEvent` | `Process` (elevation) | `sudo_execution` (UL) | `UACElevation` | - |
| **Description** | Privilege elevation request | UAC elevation | Sudo execution | Logon with explicit credentials | - |

**Unified EDR Fields:**
- `SourceUser` / `UserName` - Original user
- `TargetUser` - Elevated user (often SYSTEM/root)
- `ProcessPath` / `ImageFileName` / `Image` - Process requesting elevation
- `CommandLine` - Command to execute

**OS Event Reference:**
- **macOS UL**: `com.apple.sudo` (sudo execution)
- **Windows Security**: Event ID 4648 (`UACElevation`)

---

### 6. Code Injection & Memory

#### Process Injection

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `ProcessInjectionEvent` | `Process` | `ptrace` | `ProcessInjection` | See OS Reference |
| **Event Name** | `ProcessInjectionEvent` | `Process` (injection) | `ptrace` | `ProcessInjection` | - |
| **Description** | Process injection/trace | Process injection | Process trace/injection | Process injection | - |

**Unified EDR Fields:**
- `SourceProcessId` / `ProcessId` - Injecting process ID
- `TargetProcessId` / `InjectedProcessId` - Target process ID
- `SourceProcessPath` / `ImageFileName` / `Image` - Injecting process path
- `TargetProcessPath` / `TargetImage` - Target process path
- `InjectionMethod` - Injection technique

**EDR Platform Field Names:**
- **CrowdStrike**: `ProcessId`, `TargetProcessId`, `ImageFileName`, `TargetImage`, `InjectionMethod`
- **SentinelOne**: `processId`, `targetProcessId`, `processPath`, `targetProcessPath`, `injectionMethod`
- **Jamf Protect**: `ProcessId`, `target.process.pid`, `Image`, `target.process.path`, N/A
- **Microsoft Sentinel**: `ProcessId`, `TargetProcessId`, `Image`, `TargetImage`, `InjectionMethod`

**OS Event Reference:**
- **macOS ESF**: Event type 64 (`ptrace`)
- **Windows Sysmon**: Event ID 10 (`ProcessAccess` - injection)
- **Windows Security**: Event ID 4688 (indirect - process creation)

---

#### Memory Protection Change

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `MemoryProtectionEvent` | `Memory` | `mprotect` | `MemoryProtectionChange` | See OS Reference |
| **Event Name** | `MemoryProtectionEvent` | `Memory` (protection) | `mprotect` | `MemoryProtectionChange` | - |
| **Description** | Memory protection change | Memory protection | Memory protection change | Memory protection change | - |

**Unified EDR Fields:**
- `ProcessId` - Process ID
- `ProtectionFlags` / `protection` / `mprotect.prot` - Memory protection flags (e.g., W+X)
- `BaseAddress` - Memory base address
- `Size` - Memory region size

**EDR Platform Field Names:**
- **CrowdStrike**: `ProcessId`, `ProtectionFlags`, `BaseAddress`, `Size`
- **SentinelOne**: `processId`, `protection`, `baseAddress`, `size`
- **Jamf Protect**: `ProcessId`, `mprotect.prot`, N/A, N/A
- **Microsoft Sentinel**: `ProcessId`, `ProtectionFlags`, `BaseAddress`, `Size`

**OS Event Reference:**
- **macOS ESF**: Event type 20 (`mprotect`)
- **Windows**: Typically detected via EDR tools, not native Windows events

**Security Note:** W+X (write+execute) memory protection changes are high-fidelity indicators of code injection.

---

#### Thread Creation

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `ThreadCreationEvent` | `Thread` | `thread_create` | `ThreadCreation` | See OS Reference |
| **Event Name** | `ThreadCreationEvent` | `Thread` (create) | `thread_create` | `ThreadCreation` | - |
| **Description** | Thread creation | Thread creation | Thread creation | Thread creation | - |

**Unified EDR Fields:**
- `ProcessId` - Process ID
- `ThreadId` - Thread ID
- `StartAddress` - Thread start address

**OS Event Reference:**
- **macOS ESF**: Event type 145 (`thread_create`)
- **Windows Sysmon**: Event ID 10 (`ProcessAccess` - thread creation)

---

### 7. Driver/Kernel Extensions

#### Driver/Kernel Extension Load

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `KernelExtensionLoadEvent` | `KernelExtension` | `kextload` | `DriverLoad` | See OS Reference |
| **Event Name** | `KernelExtensionLoadEvent` | `KernelExtension` (load) | `kextload` | `DriverLoad` | - |
| **Description** | Kernel extension/driver load | Driver load | Kernel extension load | Driver loaded | - |

**Unified EDR Fields:**
- `DriverPath` / `KextPath` / `kext.path` - Driver/kext path
- `DriverSignature` / `KextTeamId` / `teamId` / `kext.team_id` - Code signing signature/team ID
- `DriverHash` - Driver hash (Windows)
- `ProcessPath` / `ImageFileName` / `Image` - Process loading the driver

**EDR Platform Field Names:**
- **CrowdStrike**: `KextPath`, `KextTeamId`, `DriverHash`, `ImageFileName`
- **SentinelOne**: `kextPath`, `teamId`, `driverHash`, `processPath`
- **Jamf Protect**: `kext.path`, `kext.team_id`, N/A, `Image`
- **Microsoft Sentinel**: `DriverPath`, `DriverSignature`, `DriverHash`, `Image`

**OS Event Reference:**
- **macOS ESF**: Event type 17 (`kextload`)
- **Windows Sysmon**: Event ID 6 (`DriverLoad`)
- **Windows Security**: Event ID 7045 (`DriverLoad`)

**Security Note:** Unsigned drivers/kexts are critical security indicators.

---

#### Driver/Kernel Extension Unload

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `KernelExtensionUnloadEvent` | `KernelExtension` | `kextunload` | `DriverUnload` | See OS Reference |
| **Event Name** | `KernelExtensionUnloadEvent` | `KernelExtension` (unload) | `kextunload` | `DriverUnload` | - |
| **Description** | Kernel extension/driver unload | Driver unload | Kernel extension unload | Driver unloaded | - |

**Unified EDR Fields:**
- `DriverPath` / `KextPath` / `kext.path` - Driver/kext path
- `ProcessPath` / `ImageFileName` / `Image` - Process unloading the driver

**OS Event Reference:**
- **macOS ESF**: Event type 18 (`kextunload`)
- **Windows Sysmon**: Event ID 6 (`DriverUnload`)
- **Windows Security**: Event ID 7036 (`DriverUnload`)

---

### 8. Persistence Mechanisms

#### Scheduled Task Creation

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FileCreationEvent` | `File` | `create` | `ScheduledTaskCreated` | See OS Reference |
| **Event Name** | `FileCreationEvent` (task file) | `File` (create) | `create` (in persistence paths) | `ScheduledTaskCreated` | - |
| **Description** | Scheduled task/launch agent creation | Task file creation | Launch agent creation | Scheduled task created | - |

**Unified EDR Fields:**
- `TaskPath` / `FilePath` / `filePath` - Task/plist file path
- `TaskName` - Task name
- `TaskCommand` - Task command
- `ProcessPath` / `ImageFileName` / `Image` - Process creating the task

**OS Event Reference:**
- **macOS ESF**: Event type 13 (`create`) in persistence paths (`/Library/LaunchAgents`, etc.)
- **Windows Sysmon**: Event ID 11 (`FileCreate` - task file)
- **Windows Security**: Event ID 4698 (`ScheduledTaskCreated`)

---

#### Service Installation

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FileCreationEvent` | `File` | `create` | `ServiceInstalled` | See OS Reference |
| **Event Name** | `FileCreationEvent` (service file) | `File` (create) | `create` (in service paths) | `ServiceInstalled` | - |
| **Description** | Service/daemon installation | Service file creation | Launch daemon creation | Service installed | - |

**Unified EDR Fields:**
- `ServicePath` / `FilePath` / `filePath` - Service file path
- `ServiceName` - Service name
- `ServiceCommand` - Service command
- `ProcessPath` / `ImageFileName` / `Image` - Process installing the service

**OS Event Reference:**
- **macOS ESF**: Event type 13 (`create`) in service paths (`/Library/LaunchDaemons`, etc.)
- **Windows Sysmon**: Event ID 11 (`FileCreate` - service file)
- **Windows Security**: Event ID 7045 (`ServiceInstalled`)

---

### 9. Security Policy

#### Code Signature Validation Failure

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `CodeSignatureInvalidEvent` | `CodeSigning` | `cs_invalidated` | `CodeSignatureInvalid` | See OS Reference |
| **Event Name** | `CodeSignatureInvalidEvent` | `CodeSigning` (invalid) | `cs_invalidated` | `CodeSignatureInvalid` | - |
| **Description** | Code signature invalid | Code signing failure | Code signature invalid | Code signature invalid | - |

**Unified EDR Fields:**
- `ProcessPath` / `ImageFileName` / `Image` - Process with invalid signature
- `SigningId` / `signingId` / `code_signature.signing_id` - Signing identifier
- `TeamId` / `CodeSigningTeamId` - Team identifier (macOS)
- `SignatureStatus` - Signature validation status

**EDR Platform Field Names:**
- **CrowdStrike**: `ImageFileName`, `SigningId`, `TeamId`, `SignatureStatus`
- **SentinelOne**: `processPath`, `signingId`, `teamId`, `signatureStatus`
- **Jamf Protect**: `Image`, `code_signature.signing_id`, `code_signature.team_id`, N/A
- **Microsoft Sentinel**: `Image`, `SigningId`, `CodeSigningTeamId`, `SignatureStatus`

**OS Event Reference:**
- **macOS ESF**: Event type 62, 94 (`cs_invalidated`)
- **macOS UL**: `com.apple.securityd` (codesign failure)
- **Windows Security**: Event ID 5058 (`CodeSignatureInvalid`)

---

#### Malware Detection

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `MalwareDetectionEvent` | `Malware` | `xp_malware_detected` | `MalwareDetection` | See OS Reference |
| **Event Name** | `MalwareDetectionEvent` | `Malware` (detected) | `xp_malware_detected` | `MalwareDetection` | - |
| **Description** | Malware detected | Malware detected | XProtect detection | Malware detected | - |

**Unified EDR Fields:**
- `FilePath` / `TargetFilename` / `filePath` - File path with malware
- `ThreatName` - Malware name
- `ThreatType` - Threat type
- `Action` - Action taken (quarantine, block, etc.)

**OS Event Reference:**
- **macOS ESF**: Event type 112 (`xp_malware_detected`)
- **macOS UL**: `com.apple.gatekeeper` (XProtect detection)
- **Windows Security**: Event ID 1116 (Windows Defender) (`MalwareDetection`)

---

#### Security Policy Bypass

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `GatekeeperOverrideEvent` | `Gatekeeper` | `gatekeeper_user_override` | `SecurityPolicyBypass` | See OS Reference |
| **Event Name** | `GatekeeperOverrideEvent` | `Gatekeeper` (override) | `gatekeeper_user_override` | `SecurityPolicyBypass` | - |
| **Description** | Security policy bypass | Gatekeeper override | Gatekeeper override | Security policy bypass | - |

**Unified EDR Fields:**
- `FilePath` / `TargetFilename` / `filePath` - File that bypassed policy
- `PolicyName` - Policy name (Gatekeeper, etc.)
- `User` / `UserName` - User who bypassed policy

**OS Event Reference:**
- **macOS ESF**: Event type 146 (`gatekeeper_user_override`)
- **macOS UL**: `com.apple.gatekeeper` (override)
- **Windows**: No direct equivalent (SmartScreen is different)

---

#### Privacy Database Modification (TCC)

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `TccModificationEvent` | `TCC` | `tcc_modify` | `TccModification` | See OS Reference |
| **Event Name** | `TccModificationEvent` | `TCC` (modify) | `tcc_modify` | `TccModification` | - |
| **Description** | TCC database modification | TCC modification | TCC modification | TCC modification | - |

**Unified EDR Fields:**
- `Service` / `TccService` - TCC service name
- `Client` / `TccClient` - Client application
- `AccessType` - Access type granted/denied

**EDR Platform Field Names:**
- **CrowdStrike**: `TccService`, `TccClient`, `AccessType`
- **SentinelOne**: `service`, `client`, `accessType`
- **Jamf Protect**: N/A (ESF event), `service` (UL), `client` (UL)
- **Microsoft Sentinel**: `TccService`, `TccClient`, `AccessType`

**OS Event Reference:**
- **macOS ESF**: Event type 147 (`tcc_modify`)
- **macOS UL**: `com.apple.TCC` (modify)
- **Windows**: No direct equivalent (different privacy model)

---

### 10. Configuration Changes

#### Registry/Property List Modification

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FileWrittenEvent` | `File` | `write` | `RegistryModification` | See OS Reference |
| **Event Name** | `FileWrittenEvent` (plist) | `File` (write) | `write` (to plist files) | `RegistryModification` | - |
| **Description** | Configuration modification | Configuration change | Property list modification | Registry value modified | - |

**Unified EDR Fields:**
- `ConfigPath` / `RegistryKey` / `FilePath` - Configuration path/registry key
- `ConfigValue` / `RegistryValue` - Configuration value
- `ProcessPath` / `ImageFileName` / `Image` - Process modifying configuration

**OS Event Reference:**
- **macOS ESF**: Event type 31 (`write`) to plist files
- **Windows Sysmon**: Event ID 13 (`RegistryValueSet`)
- **Windows Security**: Event ID 4657 (`RegistryModification`)

---

### 11. User & Account Management

#### User Creation

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `UserCreationEvent` | `User` | `od_create_user` | `UserCreated` | See OS Reference |
| **Event Name** | `UserCreationEvent` | `User` (create) | `od_create_user` | `UserCreated` | - |
| **Description** | User account creation | User creation | User creation | User account created | - |

**Unified EDR Fields:**
- `UserName` / `AccountName` - Created username
- `UserId` / `AccountSid` - User ID
- `ProcessPath` / `ImageFileName` / `Image` - Process creating the user
- `SourceUser` / `SubjectUserName` - User who created the account

**OS Event Reference:**
- **macOS ESF**: Event type 141 (`od_create_user`)
- **macOS UL**: `com.apple.opendirectoryd` (user creation)
- **Windows Security**: Event ID 4720 (`UserCreated`)

---

#### User Deletion

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `UserDeletionEvent` | `User` | `od_delete_user` | `UserDeleted` | See OS Reference |
| **Event Name** | `UserDeletionEvent` | `User` (delete) | `od_delete_user` | `UserDeleted` | - |
| **Description** | User account deletion | User deletion | User deletion | User account deleted | - |

**Unified EDR Fields:**
- `UserName` / `AccountName` - Deleted username
- `SourceUser` / `SubjectUserName` - User who deleted the account

**OS Event Reference:**
- **macOS ESF**: Event type 142 (`od_delete_user`)
- **macOS UL**: `com.apple.opendirectoryd` (user deletion)
- **Windows Security**: Event ID 4726 (`UserDeleted`)

---

#### Password Change

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `PasswordModificationEvent` | `User` | `od_modify_password` | `PasswordChange` | See OS Reference |
| **Event Name** | `PasswordModificationEvent` | `User` (password) | `od_modify_password` | `PasswordChange` | - |
| **Description** | Password modification | Password change | Password change | Password change attempt | - |

**Unified EDR Fields:**
- `UserName` / `AccountName` - Username
- `SourceUser` / `SubjectUserName` - User changing password
- `TargetUser` - Target user (if different)

**OS Event Reference:**
- **macOS ESF**: Event type 135 (`od_modify_password`)
- **macOS UL**: `com.apple.opendirectoryd` (password modification)
- **Windows Security**: Event ID 4724 (`PasswordChange`)

---

### 12. System Integrity

#### Process Signal (Termination)

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `ProcessSignalEvent` | `Process` | `signal` | `ProcessSignal` | See OS Reference |
| **Event Name** | `ProcessSignalEvent` | `Process` (signal) | `signal` | `ProcessSignal` | - |
| **Description** | Process signal sent | Process signal | Process signal | Process terminated | - |

**Unified EDR Fields:**
- `SignalNumber` / `signal` / `signal.number` - Signal number (SIGKILL=9, SIGTERM=15)
- `SourceProcessId` / `ProcessId` - Process sending signal
- `TargetProcessId` / `TargetPid` - Target process ID
- `TargetProcessPath` / `TargetImage` - Target process path

**EDR Platform Field Names:**
- **CrowdStrike**: `SignalNumber`, `ProcessId`, `TargetProcessId`, `TargetProcessPath`
- **SentinelOne**: `signal`, `processId`, `targetProcessId`, `targetProcessPath`
- **Jamf Protect**: `signal.number`, `ProcessId`, `target.process.pid`, `target.process.path`
- **Microsoft Sentinel**: `SignalNumber`, `ProcessId`, `TargetProcessId`, `TargetImage`

**OS Event Reference:**
- **macOS ESF**: Event type 27 (`signal`)
- **Windows Security**: Event ID 4689 (`ProcessTerminated`)

**Security Note:** SIGKILL (9) sent to security tools is a defense evasion technique.

---

#### Filesystem Mount

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `FilesystemMountEvent` | `Filesystem` | `mount` | `FilesystemMount` | See OS Reference |
| **Event Name** | `FilesystemMountEvent` | `Filesystem` (mount) | `mount` | `FilesystemMount` | - |
| **Description** | Filesystem mount | Filesystem mount | Filesystem mount | Volume mounted | - |

**Unified EDR Fields:**
- `MountPath` / `MountPoint` - Mount point
- `DevicePath` - Device path
- `FileSystemType` - Filesystem type
- `Removable` / `IsRemovable` - Whether device is removable

**OS Event Reference:**
- **macOS ESF**: Event type 22 (`mount`)
- **Windows Security**: Event ID 4656 (`VolumeMounted`)

---

#### XPC Connection (macOS-specific)

| Information Model | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel | OS Reference |
|-------------------|-------------|-------------|--------------|-------------------|--------------|
| **Event Type** | `XpcConnectionEvent` | `XPC` | `xpc_connect` | `XpcConnection` | See OS Reference |
| **Event Name** | `XpcConnectionEvent` | `XPC` (connect) | `xpc_connect` | `XpcConnection` | - |
| **Description** | XPC connection | XPC connection | XPC connection | Named pipe connection (closest) | - |

**Unified EDR Fields:**
- `ServiceName` / `XpcServiceName` / `serviceName` / `xpc.service_name` - Service name
- `ProcessPath` / `ImageFileName` / `Image` - Process making connection
- `TargetProcessPath` / `TargetImage` - Target process path

**EDR Platform Field Names:**
- **CrowdStrike**: `XpcServiceName`, `ImageFileName`, `TargetImage`
- **SentinelOne**: `serviceName`, `processPath`, `targetProcessPath`
- **Jamf Protect**: `xpc.service_name`, `Image`, `target.process.path`
- **Microsoft Sentinel**: `XpcServiceName`, `Image`, `TargetImage`

**OS Event Reference:**
- **macOS ESF**: Event type 65 (`xpc_connect`)
- **Windows Security**: Event ID 5145 (`NamedPipe` - closest equivalent)

**Note:** XPC is macOS-specific; Windows uses named pipes, RPC, etc.

---

## Unified Field Mappings

### Process Fields

| Unified EDR Field | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-------------------|-------------|-------------|--------------|-------------------|
| `ProcessPath` | `ImageFileName` | `processPath` | `Image` | `Image` |
| `CommandLine` | `CommandLine` | `commandLine` | `CommandLine` | `ProcessCommandLine` |
| `ProcessId` | `ProcessId` | `processId` | `ProcessId` | `ProcessId` |
| `ParentProcessId` | `ParentProcessId` | `parentProcessId` | `ParentProcessId` | `ParentProcessId` |
| `UserName` | `UserName` | `userName` | `User` | `AccountName` |
| `UserId` | `UserId` | `userId` | `UserId` | `AccountSid` |
| `WorkingDirectory` | `CurrentDirectory` | `workingDirectory` | N/A | `ProcessWorkingDirectory` |
| `IntegrityLevel` | `IntegrityLevel` | `integrityLevel` | `EffectiveUserId` | `MandatoryLabel` |

### File Fields

| Unified EDR Field | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-------------------|-------------|-------------|--------------|-------------------|
| `FilePath` | `FilePath` | `filePath` | `file.path` | `TargetFilePath` |
| `SourceFilePath` | `SourceFilePath` | `sourceFilePath` | `source.file.path` | `SourceFilePath` |
| `DestinationFilePath` | `DestinationFilePath` | `destinationFilePath` | `destination.file.path` | `DestinationFilePath` |
| `FileHash` | `FileHash` | `fileHash` | N/A | `FileHash` |
| `FileSize` | `Size` | `fileSize` | N/A | `FileSize` |

### Network Fields

| Unified EDR Field | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-------------------|-------------|-------------|--------------|-------------------|
| `SourceIp` | `LocalAddress` | `sourceIp` | N/A | `SourceAddress` |
| `SourcePort` | `LocalPort` | `sourcePort` | N/A | `SourcePort` |
| `DestinationIp` | `RemoteAddress` | `destinationIp` | N/A | `DestinationAddress` |
| `DestinationPort` | `RemotePort` | `destinationPort` | N/A | `DestinationPort` |
| `Protocol` | `Protocol` | `protocol` | N/A | `Protocol` |

### Authentication Fields

| Unified EDR Field | CrowdStrike | SentinelOne | Jamf Protect | Microsoft Sentinel |
|-------------------|-------------|-------------|--------------|-------------------|
| `UserName` | `UserName` | `userName` | `User` | `AccountName` |
| `LogonType` | `LogonType` | `logonType` | N/A | `LogonType` |
| `SourceIp` | `SourceIp` | `sourceIp` | N/A | `IpAddress` |
| `AuthenticationPackage` | `AuthType` | `authType` | `auth.type` | `AuthenticationPackageName` |
| `LogonId` | `LogonId` | `logonId` | N/A | `LogonId` |

---

## Cross-Platform Detection Examples

### Example 1: Suspicious Process Execution from Temporary Directory

**Information Model Category:** Process Lifecycle

**EDR Query (CrowdStrike FQL):**
```
event_simpleName=ProcessRollup2Event ImageFileName=/tmp/* OR ImageFileName=/var/tmp/*
```

**EDR Query (SentinelOne SOQL):**
```
eventType=Process AND processPath STARTS WITH /tmp/ OR processPath STARTS WITH /var/tmp/
```

**EDR Query (Jamf Protect - Lucene):**
```
event_name:exec AND (Image:/tmp/* OR Image:/var/tmp/*)
```

**EDR Query (Microsoft Sentinel KQL):**
```
DeviceProcessEvents
| where Image startswith "C:\\Windows\\Temp\\" or Image startswith "C:\\Temp\\"
```

**Unified EDR Concept:**
- Event Type: `ProcessCreation` / `ProcessRollup2Event` / `Process`
- Condition: `ProcessPath` starts with temporary directory
- Fields: `ProcessPath`, `CommandLine`, `ProcessId`

---

### Example 2: Unsigned Driver/Kernel Extension Load

**Information Model Category:** Driver/Kernel Extensions

**EDR Query (CrowdStrike FQL):**
```
event_simpleName=KernelExtensionLoadEvent KextTeamId=null
```

**EDR Query (SentinelOne SOQL):**
```
eventType=KernelExtension AND action=load AND teamId IS NULL
```

**EDR Query (Jamf Protect - Lucene):**
```
event_name:kextload AND NOT kext.team_id:*
```

**EDR Query (Microsoft Sentinel KQL):**
```
DeviceDriverEvents
| where ActionType == "DriverLoad"
| where DriverSignature == ""
```

**Unified EDR Concept:**
- Event Type: `DriverLoad` / `KernelExtensionLoadEvent` / `KernelExtension`
- Condition: No valid signature/team ID (`DriverSignature` = null or `TeamId` = null)
- Fields: `DriverPath`, `DriverSignature`/`TeamId`

---

### Example 3: Process Injection Detection

**Information Model Category:** Code Injection & Memory

**EDR Query (CrowdStrike FQL):**
```
event_simpleName=ProcessInjectionEvent
```

**EDR Query (SentinelOne SOQL):**
```
eventType=Process AND action=injection
```

**EDR Query (Jamf Protect - Lucene):**
```
event_name:ptrace
```

**EDR Query (Microsoft Sentinel KQL):**
```
DeviceProcessEvents
| where ActionType == "ProcessInjection"
```

**Unified EDR Concept:**
- Event Type: `ProcessInjection` / `ProcessInjectionEvent` / `Process` (injection)
- Condition: Process injection/trace detected
- Fields: `SourceProcessId`, `TargetProcessId`, `InjectionMethod`

---

### Example 4: Privilege Escalation to Root/Administrator

**Information Model Category:** Privilege Escalation

**EDR Query (CrowdStrike FQL):**
```
event_simpleName=PrivilegeEscalationEvent TargetUid=0 UserId!=0
```

**EDR Query (SentinelOne SOQL):**
```
eventType=Process AND action=setuid AND targetUid=0 AND userId!=0
```

**EDR Query (Jamf Protect - Lucene):**
```
(event_name:setuid OR event_name:setgid) AND TargetUserId:0 AND NOT UserId:0
```

**EDR Query (Microsoft Sentinel KQL):**
```
DeviceProcessEvents
| where ActionType == "PrivilegeEscalation"
| where TargetUserId == 0 and UserId != 0
```

**Unified EDR Concept:**
- Event Type: `PrivilegeEscalation` / `PrivilegeEscalationEvent` / `Process` (setuid/setgid)
- Condition: Transition to root/administrator (UID 0) from non-privileged user
- Fields: `SourceUserId`, `TargetUserId`, `ProcessPath`

---

## Platform-Specific Considerations

### macOS-Specific Events

1. **XPC Connections** - No direct Windows equivalent (closest: Named Pipes)
2. **TCC Modifications** - macOS privacy controls (no Windows equivalent)
3. **Gatekeeper Overrides** - macOS application security (Windows: SmartScreen)
4. **Process Fork** - Unix-style process forking (Windows: no direct equivalent)

### Windows-Specific Events

1. **Registry Modifications** - Windows registry (macOS: plist files)
2. **WMI Events** - Windows Management Instrumentation (no macOS equivalent)
3. **PowerShell Events** - PowerShell execution (macOS: shell scripts)
4. **Scheduled Tasks** - Windows Task Scheduler (macOS: launchd)

### Cross-Platform Equivalents

| macOS Concept | Windows Equivalent | EDR Event Type |
|---------------|-------------------|----------------|
| Launch Agents/Daemons | Scheduled Tasks | `FileCreationEvent` (in persistence paths) |
| Kernel Extensions | Drivers | `DriverLoad` / `KernelExtensionLoadEvent` |
| Property Lists (.plist) | Registry | `FileWrittenEvent` (plist) / `RegistryModification` |
| XPC | Named Pipes/RPC | `XpcConnectionEvent` / `NamedPipe` |
| Gatekeeper | SmartScreen | `GatekeeperOverrideEvent` / `SecurityPolicyBypass` |
| TCC | UAC (partially) | `TccModificationEvent` / `UACElevation` |
| setuid/setgid | UAC Elevation | `PrivilegeEscalationEvent` |

---

## Summary

This information model provides a unified taxonomy for security events across macOS and Windows using **enterprise EDR event types** as the primary abstraction layer, enabling:

1. **Cross-Platform Detection Rules:** Write EDR queries that work conceptually across both platforms
2. **Unified Field Mappings:** Understand how fields translate between EDR platforms
3. **Security Operations:** Correlate events across heterogeneous environments using EDR event types
4. **Detection Engineering:** Develop detection logic that's OS-agnostic using EDR abstractions

**Key Principles:**
- Focus on **EDR event types** as the primary mapping layer
- Use **unified EDR field names** in detection rules where possible
- Understand **platform-specific nuances** for accurate detection
- Reference **OS events** for detailed understanding and troubleshooting

**EDR Platform Coverage:**
- **CrowdStrike Falcon**: Excellent coverage with `ProcessRollup2Event`, `FileCreationEvent`, etc.
- **SentinelOne**: Good coverage with `Process`, `File`, `Network`, etc.
- **Jamf Protect**: Native ESF - uses ESF event names directly (`exec`, `kextload`, etc.)
- **Microsoft Sentinel**: Good coverage via Azure Monitor Agent with normalized event types

---

*Last Updated: 2025-01-15*
*Document Version: 2.0 (EDR-Centric)*
