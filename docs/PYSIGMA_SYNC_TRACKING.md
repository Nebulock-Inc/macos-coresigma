# pySigma Backend Sync Tracking

This document tracks changes made in macos-coresigma that need to be synced to:
1. **pySigma-backend-elasticsearch** - `sigma/pipelines/elasticsearch/macos.py`
2. **sigma-specification** - `specification/sigma-appendix-taxonomy.md`

## Pending Changes

### 2026-01-22: ESF Collector Field Gaps Analysis

**Issue**: Some ECS fields that the pySigma pipeline maps to are not being populated by the ESF collector.

**Analysis of Disabled Rules**:

| Rule | Sigma Field | ECS Field (pySigma mapping) | Collector Status | Action |
|------|-------------|----------------------------|------------------|--------|
| mass_process_termination | `SignalNumber` | `signal.number` | ✅ Outputs correctly | No signal events in test data |
| sigkill_sent_to_security_tools | `SignalNumber`, `TargetImage` | `signal.number`, `target.process.executable` | ✅ Outputs correctly | No signal events in test data |
| macos_esf_suspicious_w_x_memory_mapping | ~~`mprotect.prot`~~ `MemoryProtection` | `memory.protection` | ✅ Outputs correctly | **Rule FIXED** - was using ECS field instead of Sigma taxonomy |
| macos_setuid_setgid_privilege_escalation | `TargetUserId`, `UserId` | `user.target.id`, `process.user.id` | ✅ Outputs correctly | No setuid events in test data |
| process_execution_suspicious | `Image\|re:` | `process.executable` | ✅ N/A | **Rule FIXED** - changed regex to contains modifier |

**Conclusion**: The ESF collector already outputs all required ECS fields correctly. The disabled rules were either:
1. Using incorrect Sigma field names (fixed)
2. Using regex modifiers that EQL doesn't handle well (fixed)
3. Requiring test data that doesn't exist yet (signal, setuid events)

**Files Updated**:
- [x] `macos-coresigma/rules/esf/macos_esf_suspicious_w_x_memory_mapping.yml` - Changed `mprotect.prot` to `MemoryProtection`
- [x] `macos-coresigma/rules/esf/process_execution_suspicious.yml` - Changed `Image|re:` to `Image|contains:`

---

### 2026-01-22: UL Rules Backend Strategy

**Issue**: EQL cannot query text fields (like `message`) which are essential for UL rules.

**Solution**: Use Lucene backend for UL rules instead of EQL:
- **ESF rules**: EQL backend with `ecs_macos_esf()` pipeline (supports structured field queries)
- **UL rules**: Lucene backend with simple field mapping (supports text field queries on `message`)

**UL Field Mapping** (implemented in `deploy_sigma_rules.py`):
| Sigma Field | UL Collector Field |
|-------------|-------------------|
| `subsystem` | `ul.subsystem` |
| `category` | `ul.category` |
| `message` | `message` (text field - no mapping needed) |

**Future PR Consideration**: The `ecs_macos_ul()` pipeline could be submitted to pySigma-backend-elasticsearch as a companion to `ecs_macos_esf()`.

**Files Updated**:
- [x] `macos-coresigma/scripts/deploy_sigma_rules.py` - Added UL pipeline and Lucene backend support

---

### 2026-01-21: Parent Process Fields Now Populated

**Issue**: The ESF collector was not correctly populating parent process fields for EXEC and FORK events.

**Root Cause**: In ESF events:
- For EXEC (9): `process` = parent, `event.exec.target` = child (new process)
- For FORK (11): `process` = parent, `event.fork.child` = child (forked process)

The collector was treating `process` as the current process instead of the parent.

**Fixed Fields**:
| Field | Description | Status |
|-------|-------------|--------|
| `process.parent.pid` | Parent process ID | ✅ Correct |
| `process.parent.executable` | Parent executable path | ✅ Fixed |
| `process.parent.name` | Parent process name | ✅ Fixed |
| `process.parent.command_line` | Parent command line | ✅ Fixed |
| `process.parent.args` | Parent arguments | ✅ Fixed |
| `process.parent.code_signature.signing_id` | Parent signing ID | ✅ Added |
| `process.parent.code_signature.team_id` | Parent team ID | ✅ Added |

**Alignment with pySigma Pipeline**:
- `ParentImage` → `process.parent.executable` ✅
- `ParentProcessId` → `process.parent.pid` ✅
- `ParentProcessName` → `process.parent.name` ✅
- `ParentCommandLine` → `process.parent.command_line` ✅

**Files Updated**:
- [x] `macos-coresigma/collectors/esf_collector.py` - Fixed EXEC and FORK event handling

---

### 2026-01-21: eslogger Event Type Names

**Issue**: The eslogger CLI uses different event names than the internal ESF event type constants.

| ESF Constant | eslogger Name | Current Pipeline | Notes |
|-------------|---------------|------------------|-------|
| `ES_EVENT_TYPE_NOTIFY_PTRACE` (64) | `trace` | ✅ Fixed to `trace` | Updated pipeline |
| Process injection | `remote_thread_create` | Not documented | Add to pipeline documentation |

**Files Updated**:
- [x] `pysigma-backend-elasticsearch/sigma/pipelines/elasticsearch/macos.py` - Changed `ptrace` to `trace`
- [ ] `sigma-specification/specification/sigma-appendix-taxonomy.md` - Update ESF event reference table

**Details**:
```
# Valid eslogger events (from `eslogger --list-events`):
# Process: exec, fork, exit
# File: create, unlink, rename, open, close, write
# Privilege: setuid, setgid, su, sudo  
# Memory: mmap, mprotect
# Security: cs_invalidated, xp_malware_detected, xp_malware_remediated
# TCC: tcc_modify
# Kext: kextload, kextunload
# Injection: signal, trace, remote_thread_create
# IPC: xpc_connect
# Auth: authentication, login_login, login_logout
# Mount: mount, unmount
```

---

## Completed Changes

### 2026-01-21: ESF Event Type Mapping Fixed

Fixed ESF_EVENT_TYPE_MAP in `esf_collector.py`:

| Event Type | Old Mapping | New Mapping | ESF Constant |
|------------|-------------|-------------|--------------|
| 12 | (missing) | `close` | ES_EVENT_TYPE_NOTIFY_CLOSE |
| 15 | `close` | (removed - incorrect) | N/A |
| 23 | (missing) | `unmount` | ES_EVENT_TYPE_NOTIFY_UNMOUNT |
| 64 | `ptrace` | `trace` | ES_EVENT_TYPE_NOTIFY_TRACE |
| 118 | (missing) | `login_login` | ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN |
| 119 | (missing) | `login_logout` | ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT |
| 126 | (missing) | `profile_add` | ES_EVENT_TYPE_NOTIFY_PROFILE_ADD |
| 127 | (missing) | `profile_remove` | ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE |
| 135 | (missing) | `screensharing_attach` | ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH |
| 136 | (missing) | `screensharing_detach` | ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH |
| 141 | (missing) | `od_create_user` | ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER |
| 142 | (missing) | `od_delete_user` | ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER |
| 145 | `thread_create` | `remote_thread_create` | ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE |

---

### 2026-01-21: Sigma Rules Updated to PR #171 Standard

All 38 ESF Sigma rules updated to use correct Sigma taxonomy field names:

| Changed From | Changed To | Count |
|--------------|------------|-------|
| `event_type:` | `esf.event_type:` | 38 rules |
| `event_name:` | `event.action:` | 38 rules |
| `signal.number:` | `SignalNumber:` | 2 rules |
| `target.process.path` | `TargetImage` | 1 rule |
| `process.path` | `Image` | 2 rules |
| `file.path` | `TargetFilename` | 2 rules |
| `xpc.service_name` | `XpcServiceName` | 2 rules |
| `kext.identifier` | `KextIdentifier` | 1 rule |
| `kext.path` | `KextPath` | 1 rule |
| `kext.team_id` | `TeamId` | 1 rule |

---

### 2026-01-21: Initial PRs Submitted

- **pySigma-backend-elasticsearch PR #171** - Added `ecs_macos_esf` pipeline (approved)
- **sigma-specification PR #204** - Added macOS ESF logsource and fields documentation

---

## How to Use This Document

1. When making changes to `esf_collector.py` that affect:
   - Field names/mappings
   - Event type handling
   - Logsource categories
   
2. Add an entry under "Pending Changes" with:
   - Date
   - Description of change
   - Which files need updating
   - Checkbox for tracking completion

3. After submitting PRs, move entries to "Completed Changes"
