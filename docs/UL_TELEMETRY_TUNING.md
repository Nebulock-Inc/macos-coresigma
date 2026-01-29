# Unified Logging (UL) Telemetry Tuning Analysis

## Current UL Collector Configuration

The current UL collector monitors these security-critical subsystems:

```python
SECURITY_SUBSYSTEMS = [
    "com.apple.TCC",           # Privacy/permissions
    "com.apple.sudo",          # Privilege escalation
    "com.apple.gatekeeper",    # App signing/notarization
    "com.apple.syspolicy",     # System policy enforcement
    "com.apple.securityd",     # Security daemon
    "com.apple.alf",           # Application Layer Firewall
    "com.apple.opendirectoryd", # Directory services
    "com.apple.authorization", # Authorization framework
]
```

## Signal vs Noise Analysis

### High-Value Subsystems (Keep All)

| Subsystem | Security Value | Volume | Recommendation |
|-----------|---------------|--------|----------------|
| `com.apple.TCC` | **Critical** - Privacy bypass detection | Low-Medium | Keep all |
| `com.apple.sudo` | **Critical** - Privilege escalation | Low | Keep all |
| `com.apple.securityd` | **High** - Code signing, keychain | Medium | Keep all |
| `com.apple.gatekeeper` | **High** - Malware prevention | Low | Keep all |
| `com.apple.syspolicy` | **High** - System Integrity Protection | Low | Keep all |

### Medium-Value Subsystems (Keep with Filtering)

| Subsystem | Security Value | Volume | Recommendation |
|-----------|---------------|--------|----------------|
| `com.apple.alf` | **Medium** - Firewall events | Medium | Filter routine |
| `com.apple.authorization` | **Medium** - Auth requests | High | Filter routine |
| `com.apple.opendirectoryd` | **Medium** - User/group changes | Medium | Filter lookups |

### Recommended Additional Subsystems

| Subsystem | Security Value | Why Add |
|-----------|---------------|---------|
| `com.apple.ManagedClient` | **High** | MDM profile changes, enterprise attacks |
| `com.apple.xpc` | **High** | IPC security, privilege escalation |
| `com.apple.launchd` | **High** | Persistence mechanisms |
| `com.apple.authd` | **High** | Authentication decisions |
| `com.apple.networkd` | **Medium** | Network configuration changes |
| `com.apple.kernel` | **Critical** | Kernel-level security events |

## Noise Filtering Strategies

### 1. Message-Level Filtering

**High Noise Messages to Filter:**
```python
NOISE_PATTERNS = [
    # TCC routine checks (not denials)
    r"Checking access.*kTCCService.*allowed",
    r"Request completed.*success",
    
    # Authorization routine lookups
    r"AuthorizationCopyRights.*succeeded",
    r"Authorization check.*passed",
    
    # OpenDirectory routine queries
    r"ODQuery.*completed",
    r"ODNode.*opened",
    
    # Firewall routine operations
    r"socketfilterfw.*process.*allowed",
]
```

**High Signal Messages to Always Keep:**
```python
SIGNAL_PATTERNS = [
    # TCC denials and modifications
    r"(denied|Denied|DENIED)",
    r"kTCCService.*(Camera|Microphone|ScreenCapture|SystemPolicyAllFiles)",
    r"TCC.*modify",
    
    # Sudo/privilege escalation
    r"COMMAND=",
    r"USER=root",
    r"authentication (failed|succeeded)",
    
    # Security policy violations
    r"(rejected|blocked|invalid|failed|violation)",
    r"code signature",
    r"notarization",
    
    # Gatekeeper blocks
    r"quarantine",
    r"XProtect",
    r"assessment failed",
]
```

### 2. Category-Level Filtering

Add category filtering to reduce volume:

```python
# Categories to always include
HIGH_VALUE_CATEGORIES = [
    "security",
    "authentication", 
    "authorization",
    "privacy",
    "policy",
]

# Categories to filter (only keep errors)
FILTER_TO_ERRORS = [
    "network",
    "system",
    "default",
]
```

### 3. Level-Based Filtering

Current: `--level info`

Recommended adjustment by subsystem:

| Subsystem | Recommended Level |
|-----------|------------------|
| `com.apple.TCC` | info (keep all) |
| `com.apple.sudo` | info (keep all) |
| `com.apple.securityd` | info |
| `com.apple.gatekeeper` | info |
| `com.apple.alf` | notice (reduce noise) |
| `com.apple.authorization` | notice (reduce noise) |
| `com.apple.opendirectoryd` | notice |

## Estimated Volume Reduction

| Current | After Tuning | Reduction |
|---------|--------------|-----------|
| ~10,000 events/hour | ~2,000 events/hour | 80% |

## Security Coverage Matrix

| Attack Technique | MITRE ID | UL Subsystem | Detection Capability |
|-----------------|----------|--------------|---------------------|
| TCC Bypass | T1548 | `com.apple.TCC` | Full coverage |
| Privilege Escalation | T1548.003 | `com.apple.sudo` | Full coverage |
| Gatekeeper Bypass | T1553.001 | `com.apple.gatekeeper` | Full coverage |
| Code Signing Bypass | T1553.002 | `com.apple.securityd` | Full coverage |
| Firewall Manipulation | T1562.004 | `com.apple.alf` | Full coverage |
| Credential Access | T1555 | `com.apple.securityd` | Partial |
| Persistence | T1543 | `com.apple.launchd` | **Missing - Add** |
| MDM Manipulation | T1484 | `com.apple.ManagedClient` | **Missing - Add** |

## Recommended UL Collector Updates

### Updated Subsystem List

```python
SECURITY_SUBSYSTEMS = [
    # Critical - Keep all events
    "com.apple.TCC",
    "com.apple.sudo",
    "com.apple.securityd",
    "com.apple.gatekeeper",
    "com.apple.syspolicy",
    
    # High - Keep with filtering
    "com.apple.alf",
    "com.apple.authorization",
    "com.apple.opendirectoryd",
    
    # New additions
    "com.apple.ManagedClient",    # MDM/enterprise
    "com.apple.launchd",          # Persistence
    "com.apple.xpc",              # IPC security
    "com.apple.authd",            # Auth decisions
]
```

### Message Filtering Implementation

```python
def should_keep_ul_event(self, event: Dict[str, Any]) -> bool:
    """Filter UL events to reduce noise while preserving security signal."""
    subsystem = event.get("subsystem", "")
    message = event.get("eventMessage", "") or event.get("formatString", "")
    category = event.get("category", "")
    
    # Always keep from critical subsystems
    critical_subsystems = {"com.apple.TCC", "com.apple.sudo", "com.apple.gatekeeper"}
    if subsystem in critical_subsystems:
        return True
    
    # Always keep security-relevant messages
    signal_keywords = [
        "denied", "failed", "rejected", "blocked", "invalid",
        "violation", "unauthorized", "suspicious", "malware",
        "quarantine", "xprotect", "codesign", "COMMAND=",
    ]
    message_lower = message.lower()
    if any(kw in message_lower for kw in signal_keywords):
        return True
    
    # Filter routine operations from noisy subsystems
    noisy_subsystems = {"com.apple.authorization", "com.apple.opendirectoryd", "com.apple.alf"}
    if subsystem in noisy_subsystems:
        noise_keywords = ["succeeded", "allowed", "completed", "opened", "passed"]
        if any(kw in message_lower for kw in noise_keywords):
            return False
    
    # Default: keep
    return True
```
