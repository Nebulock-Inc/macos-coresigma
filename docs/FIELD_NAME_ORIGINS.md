# Field Name Origins and Mapping Reference

This document explains the field naming conventions used in macOS CoreSigma.

## Architecture Overview

```
┌────────────────────┐     ┌────────────────────┐     ┌────────────────────┐
│     eslogger       │     │   esf_collector    │     │   Elasticsearch    │
│  (raw ESF JSON)    │ ──► │                    │ ──► │                    │
│                    │     │  Outputs:          │     │  Indexed fields:   │
│  Native nested     │     │  • esf.* (native)  │     │  • esf.*           │
│  structure         │     │  • ECS fields      │     │  • ECS fields      │
└────────────────────┘     └────────────────────┘     └────────────────────┘
                                                               │
                                                               ▼
                           ┌────────────────────┐     ┌────────────────────┐
                           │   Sigma Rule       │     │   Lucene Query     │
                           │                    │     │                    │
                           │  Uses Sigma        │ ──► │  Targets ECS       │
                           │  taxonomy:         │     │  fields:           │
                           │  Image, User, etc. │     │  process.executable│
                           └────────────────────┘     └────────────────────┘
                                    │
                                    ▼
                           ┌────────────────────┐
                           │   macos.py         │
                           │   Pipeline         │
                           │                    │
                           │  Maps:             │
                           │  Sigma → ECS       │
                           └────────────────────┘
```

## Three Field Namespaces

### 1. Native ESF Fields (`esf.*`)

Original eslogger fields flattened to dot notation. Preserved for:
- Debugging and raw data analysis
- Fields not covered by ECS
- Direct ESF queries

| Native ESF Field | Description |
|------------------|-------------|
| `esf.event_type` | ESF event type number (9, 27, 64, etc.) |
| `esf.event_name` | ESF event name (exec, signal, ptrace) |
| `esf.process.executable.path` | Process executable path |
| `esf.process.audit_token.pid` | Process ID |
| `esf.process.audit_token.euid` | Effective user ID |
| `esf.process.audit_token.egid` | Effective group ID |
| `esf.process.signing_id` | Code signing identifier |
| `esf.process.team_id` | Code signing team ID |
| `esf.event.exec.args` | Command line arguments array |
| `esf.event.signal.sig` | Signal number |
| `esf.event.ptrace.request` | Ptrace request type |

### 2. ECS Fields (Elastic Common Schema)

Standard ECS fields matching Elastic Defend conventions. Used for:
- Compatibility with Elastic Security
- Standard dashboards and detections
- Query targets for Sigma rules

| ECS Field | Description |
|-----------|-------------|
| `process.executable` | Process executable path |
| `process.pid` | Process ID |
| `process.name` | Process name (basename) |
| `process.args` | Arguments array |
| `process.command_line` | Full command line |
| `process.working_directory` | Working directory |
| `process.entity_id` | Unique process identifier |
| `process.parent.executable` | Parent executable |
| `process.parent.pid` | Parent PID |
| `process.user.id` | Effective user ID |
| `process.user.name` | Effective username |
| `process.real_user.id` | Real user ID |
| `process.group.id` | Effective group ID |
| `process.code_signature.signing_id` | Code signing ID |
| `process.code_signature.exists` | Has signature (bool) |
| `file.path` | File path |
| `file.name` | File name |
| `target.process.pid` | Target process PID |
| `target.process.executable` | Target executable |
| `signal.number` | Unix signal number |
| `ptrace.request` | Ptrace request type |

### 3. Sigma Taxonomy Fields

Standard Sigma field names from Windows Sysmon. **NOT output by collector.**
The pipeline translates these to ECS fields.

| Sigma Field | Maps To (ECS) |
|-------------|---------------|
| `Image` | `process.executable` |
| `ProcessId` | `process.pid` |
| `ProcessName` | `process.name` |
| `CommandLine` | `process.command_line` |
| `CurrentDirectory` | `process.working_directory` |
| `ParentImage` | `process.parent.executable` |
| `ParentProcessId` | `process.parent.pid` |
| `User` | `process.user.name` |
| `UserId` | `process.user.id` |
| `TargetFilename` | `file.path` |
| `SourceImage` | `process.executable` |
| `TargetImage` | `target.process.executable` |
| `TargetProcessId` | `target.process.pid` |
| `SignalNumber` | `signal.number` |
| `SigningID` | `process.code_signature.signing_id` |

---

## Native ESF → ECS Mapping Table

| Native ESF Field | ECS Field | Notes |
|------------------|-----------|-------|
| `esf.process.executable.path` | `process.executable` | Full path to executable |
| `esf.process.audit_token.pid` | `process.pid` | Process ID |
| (derived) | `process.name` | Basename of executable |
| `esf.event.exec.args[]` | `process.args` | Arguments array |
| (joined) | `process.command_line` | Args joined with space |
| `esf.event.exec.cwd.path` | `process.working_directory` | Working directory |
| `esf.process.ppid` | `process.parent.pid` | Parent PID |
| `esf.process.parent.executable.path` | `process.parent.executable` | Parent path |
| `esf.process.audit_token.euid` | `process.user.id` | Effective UID |
| (resolved) | `process.user.name` | Username from UID |
| `esf.process.audit_token.uid` | `process.real_user.id` | Real UID |
| `esf.process.audit_token.egid` | `process.group.id` | Effective GID |
| `esf.process.audit_token.gid` | `process.real_group.id` | Real GID |
| `esf.process.signing_id` | `process.code_signature.signing_id` | Signing ID |
| `esf.process.team_id` | `process.code_signature.team_id` | Team ID |
| `esf.event.*.target.path` | `file.path` | Target file path |
| `esf.event.signal.sig` | `signal.number` | Signal number |
| `esf.event.ptrace.request` | `ptrace.request` | Ptrace request |
| `esf.event.signal.target.pid` | `target.process.pid` | Target PID |
| `esf.event.ptrace.target.executable.path` | `target.process.executable` | Target path |

---

## Pipeline Field Mapping (Sigma → ECS)

The `macos.py` pipeline transforms Sigma rule field names to ECS fields:

```python
field_mappings = {
    # Process fields
    "Image": "process.executable",
    "ProcessId": "process.pid",
    "ProcessName": "process.name",
    "CommandLine": "process.command_line",
    "CurrentDirectory": "process.working_directory",
    
    # Parent process
    "ParentImage": "process.parent.executable",
    "ParentProcessId": "process.parent.pid",
    "ParentProcessName": "process.parent.name",
    "ParentCommandLine": "process.parent.command_line",
    
    # User fields
    "User": "process.user.name",
    "UserId": "process.user.id",
    "RealUserId": "process.real_user.id",
    "TargetUser": "user.target.name",
    "TargetUserId": "user.target.id",
    
    # Group fields
    "EffectiveGroupId": "process.group.id",
    "RealGroupId": "process.real_group.id",
    
    # File fields
    "TargetFilename": "file.path",
    "SourceFilename": "file.source.path",
    "DestinationFilename": "file.target.path",
    
    # Code signature
    "SigningID": "process.code_signature.signing_id",
    "TeamID": "process.code_signature.team_id",
    "Signed": "process.code_signature.exists",
    
    # Process injection
    "SourceImage": "process.executable",
    "SourceProcessId": "process.pid",
    "TargetImage": "target.process.executable",
    "TargetProcessId": "target.process.pid",
    
    # Unix-specific
    "SignalNumber": "signal.number",
    "PtraceRequest": "ptrace.request",
}
```

---

## Example: End-to-End Flow

### 1. Raw ESF Event (eslogger output)

```json
{
  "event_type": 9,
  "process": {
    "executable": {
      "path": "/usr/bin/curl"
    },
    "audit_token": {
      "pid": 12345,
      "euid": 501
    }
  },
  "event": {
    "exec": {
      "args": ["curl", "-o", "/tmp/file", "https://example.com"]
    }
  }
}
```

### 2. Collector Output (esf_collector.py)

```json
{
  "@timestamp": "2026-01-09T15:30:00Z",
  "event.action": "exec",
  "event.category": "process",
  
  "esf.event_type": 9,
  "esf.process.executable.path": "/usr/bin/curl",
  "esf.process.audit_token.pid": 12345,
  "esf.event.exec.args": ["curl", "-o", "/tmp/file", "https://example.com"],
  
  "process.executable": "/usr/bin/curl",
  "process.pid": 12345,
  "process.name": "curl",
  "process.args": ["curl", "-o", "/tmp/file", "https://example.com"],
  "process.command_line": "curl -o /tmp/file https://example.com",
  "process.user.id": "501",
  "process.user.name": "alice"
}
```

### 3. Sigma Rule

```yaml
title: Suspicious Download
logsource:
    product: macos
    service: endpointsecurity
    category: process_creation
detection:
    sel:
        Image|endswith: /curl
        CommandLine|contains: /tmp
    condition: sel
```

### 4. Pipeline Transformation

```
Sigma field: Image        → ECS field: process.executable
Sigma field: CommandLine  → ECS field: process.command_line
```

### 5. Final Lucene Query

```
(event.action:exec AND esf.event_type:9) AND 
(process.executable:*\/curl AND process.command_line:*\/tmp*)
```

---

## ECS Compliance Summary

| Category | Standard ECS | Custom Extension |
|----------|-------------|-----------------|
| Process | ✅ 100% | - |
| User/Group | ✅ 100% | - |
| File | ⚠️ 80% | file.source.path, file.target.path |
| Code Signature | ✅ 100% | - |
| Target Process | ⚠️ Custom | target.process.* |
| Unix-specific | ❌ Custom | signal.*, ptrace.* |

---

## References

- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
- [Sigma Taxonomy](https://sigmahq.io/sigma-specification/)
- [Apple ESF Documentation](https://developer.apple.com/documentation/endpointsecurity)
