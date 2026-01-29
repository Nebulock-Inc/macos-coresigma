#!/usr/bin/env python3
"""
ESF Event Collector for Elasticsearch/Kibana

Collects ESF events and outputs them in two field formats:
1. Native ESF fields (dot notation) - Original eslogger structure flattened
2. ECS fields (Elastic Common Schema) - Compatible with Elastic Defend

The Sigma pipeline (macos.py) handles mapping Sigma rule field names to ECS fields.
This collector does NOT output Sigma taxonomy fields - that's the pipeline's job.

Output Field Naming:
- esf.* - Native ESF fields in dot notation (esf.process.executable.path)
- ECS fields - Standard ECS (process.executable, file.path, user.name)
"""
import sys
import json
import subprocess
import signal
import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# ESF Event Type Mapping
# ESF Event Type Mapping - based on Apple's Endpoint Security Framework
# See: https://developer.apple.com/documentation/endpointsecurity/es_event_type_t
ESF_EVENT_TYPE_MAP = {
    # Process events
    9: "exec",           # ES_EVENT_TYPE_NOTIFY_EXEC
    11: "fork",          # ES_EVENT_TYPE_NOTIFY_FORK
    28: "exit",          # ES_EVENT_TYPE_NOTIFY_EXIT
    
    # File events
    10: "open",          # ES_EVENT_TYPE_NOTIFY_OPEN
    12: "close",         # ES_EVENT_TYPE_NOTIFY_CLOSE
    13: "create",        # ES_EVENT_TYPE_NOTIFY_CREATE
    14: "exchangedata",  # ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA
    15: "exit",          # ES_EVENT_TYPE_NOTIFY_EXIT (duplicate - some systems use 15)
    19: "unlink",        # ES_EVENT_TYPE_NOTIFY_UNLINK
    21: "rename",        # ES_EVENT_TYPE_NOTIFY_RENAME
    29: "dup",           # ES_EVENT_TYPE_NOTIFY_DUP
    30: "link",          # ES_EVENT_TYPE_NOTIFY_LINK
    31: "write",         # ES_EVENT_TYPE_NOTIFY_WRITE
    32: "setextattr",    # ES_EVENT_TYPE_NOTIFY_SETEXTATTR
    33: "lookup",        # ES_EVENT_TYPE_NOTIFY_LOOKUP
    34: "chdir",         # ES_EVENT_TYPE_NOTIFY_CHDIR
    35: "getattrlist",   # ES_EVENT_TYPE_NOTIFY_GETATTRLIST
    36: "stat",          # ES_EVENT_TYPE_NOTIFY_STAT
    37: "access",        # ES_EVENT_TYPE_NOTIFY_ACCESS
    38: "chroot",        # ES_EVENT_TYPE_NOTIFY_CHROOT
    39: "utimes",        # ES_EVENT_TYPE_NOTIFY_UTIMES
    40: "clone",         # ES_EVENT_TYPE_NOTIFY_CLONE
    41: "fcntl",         # ES_EVENT_TYPE_NOTIFY_FCNTL
    42: "getextattr",    # ES_EVENT_TYPE_NOTIFY_GETEXTATTR
    43: "listextattr",   # ES_EVENT_TYPE_NOTIFY_LISTEXTATTR
    44: "readdir",       # ES_EVENT_TYPE_NOTIFY_READDIR
    45: "deleteextattr", # ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR
    46: "fsgetpath",     # ES_EVENT_TYPE_NOTIFY_FSGETPATH
    47: "truncate",      # ES_EVENT_TYPE_NOTIFY_TRUNCATE
    48: "readlink",      # ES_EVENT_TYPE_NOTIFY_READLINK
    49: "setattrlist",   # ES_EVENT_TYPE_NOTIFY_SETATTRLIST
    50: "setflags",      # ES_EVENT_TYPE_NOTIFY_SETFLAGS
    51: "setmode",       # ES_EVENT_TYPE_NOTIFY_SETMODE
    52: "setowner",      # ES_EVENT_TYPE_NOTIFY_SETOWNER
    
    # Mount events
    22: "mount",         # ES_EVENT_TYPE_NOTIFY_MOUNT
    23: "unmount",       # ES_EVENT_TYPE_NOTIFY_UNMOUNT
    
    # Kernel extension events
    17: "kextload",      # ES_EVENT_TYPE_NOTIFY_KEXTLOAD
    18: "kextunload",    # ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD
    
    # Privilege/identity events
    24: "setuid",        # ES_EVENT_TYPE_NOTIFY_SETUID
    25: "setgid",        # ES_EVENT_TYPE_NOTIFY_SETGID
    
    # Signal events
    27: "signal",        # ES_EVENT_TYPE_NOTIFY_SIGNAL
    
    # Memory events
    20: "mprotect",      # ES_EVENT_TYPE_NOTIFY_MPROTECT
    
    # Code signature events
    62: "cs_invalidated", # ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
    
    # Process injection/debug events
    64: "trace",         # ES_EVENT_TYPE_NOTIFY_TRACE (ptrace)
    145: "remote_thread_create",  # ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE
    
    # XPC events
    65: "xpc_connect",   # ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
    
    # Authorization events
    103: "authorization_petition",   # ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION
    104: "authorization_judgement",  # ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT
    
    # Authentication events
    111: "authentication",  # ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
    
    # XProtect/malware events
    112: "xp_malware_detected",    # ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
    113: "xp_malware_remediated",  # ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
    
    # System configuration events
    146: "gatekeeper_user_override",  # ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE
    147: "tcc_modify",                # ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
    
    # Login events
    118: "login_login",    # ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
    119: "login_logout",   # ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT
    
    # Profile events
    126: "profile_add",    # ES_EVENT_TYPE_NOTIFY_PROFILE_ADD
    127: "profile_remove", # ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE
    
    # Screen sharing events
    135: "screensharing_attach",  # ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
    136: "screensharing_detach",  # ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
    
    # OpenDirectory events
    141: "od_create_user",     # ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER
    142: "od_delete_user",     # ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER
    143: "od_disable_user",    # ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER
    144: "od_enable_user",     # ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER
    148: "od_modify_password", # ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD
}

# Map ESF event types to ECS event.category and event.type
ESF_TO_ECS_EVENT_CATEGORY = {
    # Process events
    9: ("process", "start"),      # exec
    11: ("process", "start"),     # fork
    28: ("process", "end"),       # exit
    
    # File events
    10: ("file", "access"),       # open
    12: ("file", "access"),       # close
    13: ("file", "creation"),     # create
    14: ("file", "change"),       # exchangedata
    15: ("process", "end"),       # exit (some systems)
    19: ("file", "deletion"),     # unlink
    21: ("file", "change"),       # rename
    29: ("file", "access"),       # dup
    30: ("file", "creation"),     # link
    31: ("file", "change"),       # write
    32: ("file", "change"),       # setextattr
    33: ("file", "access"),       # lookup
    34: ("file", "access"),       # chdir
    35: ("file", "access"),       # getattrlist
    36: ("file", "access"),       # stat
    37: ("file", "access"),       # access
    38: ("file", "change"),       # chroot
    39: ("file", "change"),       # utimes
    40: ("file", "creation"),     # clone
    41: ("file", "access"),       # fcntl
    42: ("file", "access"),       # getextattr
    43: ("file", "access"),       # listextattr
    44: ("file", "access"),       # readdir
    45: ("file", "change"),       # deleteextattr
    46: ("file", "access"),       # fsgetpath
    47: ("file", "change"),       # truncate
    48: ("file", "access"),       # readlink
    49: ("file", "change"),       # setattrlist
    50: ("file", "change"),       # setflags
    51: ("file", "change"),       # setmode
    52: ("file", "change"),       # setowner
    
    # Mount events
    22: ("file", "info"),         # mount
    23: ("file", "info"),         # unmount
    
    # Driver events
    17: ("driver", "load"),       # kextload
    18: ("driver", "unload"),     # kextunload
    
    # Identity events
    24: ("iam", "user"),          # setuid
    25: ("iam", "group"),         # setgid
    
    # Signal events
    27: ("process", "info"),      # signal
    
    # Memory events
    20: ("process", "info"),      # mprotect
    
    # Code signature events
    62: ("intrusion_detection", "info"),  # cs_invalidated
    
    # Process injection/debug events
    64: ("intrusion_detection", "admin"),  # trace (ptrace)
    145: ("intrusion_detection", "admin"), # remote_thread_create
    
    # XPC events
    65: ("process", "info"),      # xpc_connect
    
    # Authorization events
    103: ("authentication", "info"),  # authorization_petition
    104: ("authentication", "info"),  # authorization_judgement
    
    # Authentication events
    111: ("authentication", "info"),  # authentication
    118: ("authentication", "start"), # login_login
    119: ("authentication", "end"),   # login_logout
    
    # Malware events
    112: ("malware", "info"),     # xp_malware_detected
    113: ("malware", "info"),     # xp_malware_remediated
    
    # Configuration events
    126: ("configuration", "creation"),  # profile_add
    127: ("configuration", "deletion"),  # profile_remove
    146: ("configuration", "change"),    # gatekeeper_user_override
    147: ("configuration", "change"),    # tcc_modify
    
    # Screen sharing events
    135: ("session", "start"),    # screensharing_attach
    136: ("session", "end"),      # screensharing_detach
    
    # OpenDirectory events
    141: ("iam", "creation"),     # od_create_user
    142: ("iam", "deletion"),     # od_delete_user
    143: ("iam", "change"),       # od_disable_user
    144: ("iam", "change"),       # od_enable_user
    148: ("iam", "change"),       # od_modify_password
}


class ESFCollector:
    """
    Collects and normalizes ESF events for Elasticsearch.
    
    Output format:
    - Native ESF fields: esf.process.executable.path, esf.process.audit_token.pid, etc.
    - ECS fields: process.executable, process.pid, file.path, user.name, etc.
    
    The Sigma pipeline handles field name translation from Sigma rules to ECS.
    """
    
    ENABLE_FILTERING = True
    
    SECURITY_PATHS = {
        "/Library/LaunchAgents", "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents", "/System/Library/LaunchDaemons",
        "~/Library/LaunchAgents", "/Users/*/Library/LaunchAgents",
        "/Library/StartupItems", "/etc/periodic",
        "/Library/Extensions", "/System/Library/Extensions",
        "/private/etc", "/etc/sudoers", "/etc/pam.d", "/etc/ssh",
        "/Library/Application Support/com.apple.TCC",
        "/Users/*/Library/Application Support/com.apple.TCC",
        "/var/db/auth.db", "/var/db/sudo",
        "/Library/Preferences/com.apple.loginitems.plist",
        "/Users/*/Library/Preferences/com.apple.loginitems.plist",
        "/Library/Managed Preferences",
        "/var/db/ConfigurationProfiles",
        "/Library/Preferences/com.apple.alf.plist",
        "/Library/Preferences/com.apple.security",
    }
    
    ALWAYS_KEEP_EVENT_TYPES = {
        9, 112, 113, 62, 94, 147, 146, 24, 25, 64, 17, 18, 27, 65,
        111, 141, 135, 126, 127, 118, 119, 120, 121, 22,
    }
    
    # Noisy file events that need path-based filtering
    NOISY_FILE_EVENTS = {
        10: "open",     # ~65K events - only keep security paths
        12: "close",    # ~75K events - only keep if modified flag set
        33: "lookup",   # ~143K events - filter almost all (minimal security value)
    }
    
    def __init__(self, output: str = "stdout", es_url: Optional[str] = None):
        self.output = output
        self.es_url = es_url
        self.running = True
        self.es_client = None
        
        self.filter_stats = {
            'mprotect': {'kept': 0, 'filtered': 0},
            'rename': {'kept': 0, 'filtered': 0},
            'fork': {'kept': 0, 'filtered': 0},
            'open': {'kept': 0, 'filtered': 0},
            'close': {'kept': 0, 'filtered': 0},
            'lookup': {'kept': 0, 'filtered': 0},
            'total_events': 0
        }
        self.last_stats_time = None
        import time
        self.start_time = time.time()
        
        self._user_cache = {}
        self._group_cache = {}
        
        if output == "elasticsearch":
            try:
                # Try relative import first (when used as a module)
                try:
                    from .auth import create_elasticsearch_client, AuthenticationError
                except ImportError:
                    # Fall back to direct import (when run as a script)
                    from auth import create_elasticsearch_client, AuthenticationError
                
                es_url_final = es_url if es_url else 'http://localhost:9200'
                try:
                    self.es_client = create_elasticsearch_client(es_url_final)
                    info = self.es_client.info()
                    print(f"✅ Connected to Elasticsearch: {es_url_final} (cluster: {info['cluster_name']})", file=sys.stderr)
                except AuthenticationError as e:
                    print(f"❌ Authentication error: {e}", file=sys.stderr)
                    self.es_client = None
                except Exception as e:
                    print(f"⚠️  Elasticsearch connection failed: {e}", file=sys.stderr)
                    self.es_client = None
            except ImportError as e:
                print(f"❌ ERROR: {e}", file=sys.stderr)
                self.es_client = None
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        self.running = False
    
    def _print_filter_stats(self):
        import time
        elapsed = time.time() - self.start_time
        stats = self.filter_stats
        tracked_types = ['mprotect', 'rename', 'fork', 'open', 'close', 'lookup']
        total_processed = sum(
            stats[k]['kept'] + stats[k]['filtered'] 
            for k in tracked_types
        )
        if total_processed == 0:
            return
        
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"Filter Statistics (after {int(elapsed)}s)", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        
        for event_type in tracked_types:
            total = stats[event_type]['kept'] + stats[event_type]['filtered']
            if total > 0:
                pct = (stats[event_type]['kept'] / total * 100)
                print(f"{event_type}: {stats[event_type]['kept']:,} kept, "
                      f"{stats[event_type]['filtered']:,} filtered ({pct:.1f}% kept)", 
                      file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
    
    def should_keep_event(self, esf_event: Dict[str, Any]) -> bool:
        if not self.ENABLE_FILTERING:
            return True
        
        event_type = esf_event.get("event_type")
        event_name = ESF_EVENT_TYPE_MAP.get(event_type, "unknown")
        
        if event_type in self.ALWAYS_KEEP_EVENT_TYPES:
            return True
        
        if event_name == "mprotect":
            event_data = esf_event.get("event", {})
            mprotect_data = event_data.get("mmap", {}) or event_data.get("mprotect", {})
            protection = mprotect_data.get("protection", 0)
            if protection & 0x6 == 0x6:
                self.filter_stats['mprotect']['kept'] += 1
                return True
            self.filter_stats['mprotect']['filtered'] += 1
            return False
        
        elif event_name == "rename":
            source_path = self._extract_file_path(esf_event, "source")
            dest_path = self._extract_file_path(esf_event, "destination")
            if not source_path and not dest_path:
                process_path = esf_event.get("process", {}).get("executable", {}).get("path", "")
                noisy = ["/usr/bin/log", "/usr/bin/tr", "/usr/bin/sed", "/usr/bin/jq", "/usr/bin/wc"]
                if any(p in process_path for p in noisy):
                    self.filter_stats['rename']['filtered'] += 1
                    return False
                self.filter_stats['rename']['kept'] += 1
                return True
            should_keep = self._is_security_path(source_path) or self._is_security_path(dest_path)
            if should_keep:
                self.filter_stats['rename']['kept'] += 1
            else:
                self.filter_stats['rename']['filtered'] += 1
            return should_keep
        
        elif event_name == "fork":
            process_path = esf_event.get("process", {}).get("executable", {}).get("path", "")
            security_procs = ["bash", "sh", "zsh", "python", "perl", "ruby", "node",
                            "curl", "wget", "nc", "ssh", "scp", "sudo", "su", "launchd"]
            if any(p in process_path.lower() for p in security_procs):
                self.filter_stats['fork']['kept'] += 1
                return True
            import random
            should_keep = random.random() < 0.1
            if should_keep:
                self.filter_stats['fork']['kept'] += 1
            else:
                self.filter_stats['fork']['filtered'] += 1
            return should_keep
        
        elif event_name == "create":
            return self._is_security_path(self._extract_file_path(esf_event, "target"))
        
        elif event_name == "setextattr":
            file_path = self._extract_file_path(esf_event, "target")
            extattr = esf_event.get("event", {}).get("setextattr", {}).get("extattr", "")
            return "quarantine" in extattr.lower() or self._is_security_path(file_path)
        
        # ================================================================
        # NOISY FILE EVENT FILTERING (open, close, lookup)
        # ================================================================
        
        elif event_name == "open":
            # Keep opens to security-relevant paths (used in Sigma rules)
            event_data = esf_event.get("event", {})
            open_data = event_data.get("open", {})
            file_info = open_data.get("file", {})
            file_path = file_info.get("path", "")
            
            if self._is_security_path(file_path):
                self.filter_stats['open']['kept'] += 1
                return True
            self.filter_stats['open']['filtered'] += 1
            return False
        
        elif event_name == "close":
            # Keep closes only if the file was modified (has security relevance)
            event_data = esf_event.get("event", {})
            close_data = event_data.get("close", {})
            modified = close_data.get("modified", False)
            
            if modified:
                # File was actually changed - potentially interesting
                file_info = close_data.get("target", {})
                file_path = file_info.get("path", "")
                if self._is_security_path(file_path):
                    self.filter_stats['close']['kept'] += 1
                    return True
            self.filter_stats['close']['filtered'] += 1
            return False
        
        elif event_name == "lookup":
            # Lookup events have minimal security value - filter almost all
            # Only keep lookups to very sensitive paths
            event_data = esf_event.get("event", {})
            lookup_data = event_data.get("lookup", {})
            
            # Get file path from various possible locations
            file_info = lookup_data.get("target", {}) or lookup_data.get("source_dir", {})
            file_path = file_info.get("path", "")
            relative_target = lookup_data.get("relative_target", "")
            
            # Build full path if we have directory + relative
            if file_path and relative_target:
                full_path = f"{file_path}/{relative_target}"
            else:
                full_path = file_path or relative_target
            
            # Very restrictive - only keep lookups to critical auth/config files
            critical_paths = {
                "/etc/sudoers", "/etc/pam.d", "/var/db/auth.db",
                "/Library/Preferences/com.apple.TCC",
                "/private/var/db/TCC/TCC.db",
            }
            if any(cp in full_path for cp in critical_paths):
                self.filter_stats['lookup']['kept'] += 1
                return True
            self.filter_stats['lookup']['filtered'] += 1
            return False
        
        return True
    
    def _extract_file_path(self, esf_event: Dict[str, Any], path_key: str) -> str:
        try:
            event_data = esf_event.get("event", {})
            if path_key == "source":
                return event_data.get("source", {}).get("file", {}).get("path", "")
            elif path_key == "destination":
                dest = event_data.get("destination", {})
                return dest.get("path", "") or dest.get("filename", "")
            elif path_key == "target":
                target = event_data.get("target", {})
                return target.get("file", {}).get("path", "") or target.get("path", "")
        except (KeyError, TypeError, AttributeError):
            pass
        return ""
    
    def _is_security_path(self, file_path: str) -> bool:
        if not file_path:
            return False
        for sec_path in self.SECURITY_PATHS:
            if file_path.startswith(sec_path.replace("~", "/Users")) or \
               sec_path.replace("*", "") in file_path:
                return True
        return False
    
    def _get_username(self, uid: Optional[int]) -> Optional[str]:
        if uid is None:
            return None
        if uid in self._user_cache:
            return self._user_cache[uid]
        try:
            import pwd
            name = pwd.getpwuid(uid).pw_name
            self._user_cache[uid] = name
            return name
        except (KeyError, OSError):
            return str(uid)
    
    def _get_groupname(self, gid: Optional[int]) -> Optional[str]:
        if gid is None:
            return None
        if gid in self._group_cache:
            return self._group_cache[gid]
        try:
            import grp
            name = grp.getgrgid(gid).gr_name
            self._group_cache[gid] = name
            return name
        except (KeyError, OSError):
            return str(gid)
    
    def _generate_entity_id(self, pid: int, start_time: str) -> str:
        unique_str = f"{pid}_{start_time}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, v))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def normalize_event(self, esf_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize ESF event to output:
        1. Native ESF fields (dot notation) - prefixed with esf.*
        2. ECS fields - matching Elastic Defend conventions
        
        Does NOT output Sigma taxonomy fields - the pipeline handles that translation.
        """
        event_type = esf_event.get("event_type")
        event_name = ESF_EVENT_TYPE_MAP.get(event_type, "unknown")
        timestamp = esf_event.get("time", datetime.now(timezone.utc).isoformat())
        
        ecs_category, ecs_type = ESF_TO_ECS_EVENT_CATEGORY.get(event_type, ("process", "info"))
        
        # ====================================================================
        # BASE EVENT STRUCTURE
        # ====================================================================
        normalized = {
            # ECS base fields
            "@timestamp": timestamp,
            "event.kind": "event",
            "event.category": ecs_category,
            "event.type": ecs_type,
            "event.action": event_name,
            "event.module": "endpoint",
            "event.dataset": f"endpoint.events.{ecs_category}",
            
            # Host info
            "host.os.family": "darwin",
            "host.os.type": "macos",
            
            # Data stream - use consistent dataset for all events in same index
            # The specific event type is in event.category and event.dataset
            "data_stream.type": "logs",
            "data_stream.dataset": "macos.esf",
            "data_stream.namespace": "default",
        }
        
        # ====================================================================
        # NATIVE ESF FIELDS (dot notation) - prefixed with esf.*
        # ====================================================================
        # Flatten the entire native ESF structure
        if "process" in esf_event:
            flattened = self._flatten_dict(esf_event["process"], parent_key="esf.process")
            normalized.update(flattened)
        if "event" in esf_event:
            flattened = self._flatten_dict(esf_event["event"], parent_key="esf.event")
            normalized.update(flattened)
        if "thread" in esf_event:
            flattened = self._flatten_dict(esf_event["thread"], parent_key="esf.thread")
            normalized.update(flattened)
        
        # Store raw event type/name in esf namespace
        normalized["esf.event_type"] = event_type
        normalized["esf.event_name"] = event_name
        
        # ====================================================================
        # ECS PROCESS FIELDS (matches Elastic Defend)
        # ====================================================================
        if "process" in esf_event:
            process = esf_event["process"]
            audit_token = process.get("audit_token", {})
            executable = process.get("executable", {})
            
            pid = audit_token.get("pid") or process.get("pid")
            ppid = process.get("ppid")
            executable_path = executable.get("path", "")
            process_name = os.path.basename(executable_path) if executable_path else ""
            entity_id = self._generate_entity_id(pid, timestamp) if pid else None
            
            # ECS process.* fields
            normalized["process.pid"] = pid
            normalized["process.executable"] = executable_path
            normalized["process.name"] = process_name
            normalized["process.entity_id"] = entity_id
            normalized["process.parent.pid"] = ppid
            
            # Process arguments
            args = process.get("args", [])
            if args:
                normalized["process.args"] = args
                normalized["process.args_count"] = len(args)
                normalized["process.command_line"] = " ".join(args)
            
            # Working directory
            cwd = process.get("cwd", {})
            if cwd:
                normalized["process.working_directory"] = cwd.get("path", "")
            
            # ECS user fields (from audit_token)
            euid = audit_token.get("euid")
            egid = audit_token.get("egid")
            uid = audit_token.get("uid") or audit_token.get("ruid")
            gid = audit_token.get("gid") or audit_token.get("rgid")
            svuid = audit_token.get("svuid")
            svgid = audit_token.get("svgid")
            
            # process.user.* (effective user)
            if euid is not None:
                normalized["process.user.id"] = str(euid)
                normalized["process.user.name"] = self._get_username(euid)
            
            # process.real_user.* (real user)
            if uid is not None:
                normalized["process.real_user.id"] = str(uid)
                normalized["process.real_user.name"] = self._get_username(uid)
            
            # process.saved_user.*
            if svuid is not None:
                normalized["process.saved_user.id"] = str(svuid)
                normalized["process.saved_user.name"] = self._get_username(svuid)
            
            # process.group.* (effective group)
            if egid is not None:
                normalized["process.group.id"] = str(egid)
                normalized["process.group.name"] = self._get_groupname(egid)
            
            # process.real_group.*
            if gid is not None:
                normalized["process.real_group.id"] = str(gid)
                normalized["process.real_group.name"] = self._get_groupname(gid)
            
            # process.saved_group.*
            if svgid is not None:
                normalized["process.saved_group.id"] = str(svgid)
                normalized["process.saved_group.name"] = self._get_groupname(svgid)
            
            # ECS code signature
            signing_id = process.get("signing_id", "")
            team_id = process.get("team_id", "")
            if signing_id or team_id:
                normalized["process.code_signature.exists"] = True
                if signing_id:
                    normalized["process.code_signature.signing_id"] = signing_id
                if team_id:
                    normalized["process.code_signature.team_id"] = team_id
            else:
                normalized["process.code_signature.exists"] = False
            
            # Parent process
            parent = process.get("parent", {})
            if parent:
                parent_exec = parent.get("executable", {})
                parent_path = parent_exec.get("path", "")
                parent_name = os.path.basename(parent_path) if parent_path else ""
                parent_args = parent.get("args", [])
                
                normalized["process.parent.executable"] = parent_path
                normalized["process.parent.name"] = parent_name
                if parent_args:
                    normalized["process.parent.args"] = parent_args
                    normalized["process.parent.args_count"] = len(parent_args)
                    normalized["process.parent.command_line"] = " ".join(parent_args)
        
        # ====================================================================
        # EVENT-SPECIFIC ECS FIELDS
        # ====================================================================
        
        # EXEC events (9)
        # In ESF exec events:
        #   - "process" is the PARENT (the process calling exec)
        #   - "event.exec.target" is the CHILD (new process being executed)
        # We need to copy the process.* fields to process.parent.* and
        # populate process.* from the target
        if event_type == 9 and "event" in esf_event:
            exec_data = esf_event.get("event", {}).get("exec", {})
            
            # The responsible "process" is actually the parent for exec events
            # Copy current process.* values to process.parent.*
            if "process" in esf_event:
                parent_proc = esf_event["process"]
                parent_exec = parent_proc.get("executable", {})
                parent_path = parent_exec.get("path", "")
                parent_name = os.path.basename(parent_path) if parent_path else ""
                parent_audit = parent_proc.get("audit_token", {})
                parent_pid = parent_audit.get("pid") or parent_proc.get("pid")
                parent_args = parent_proc.get("args", [])
                
                # Set parent process fields
                normalized["process.parent.pid"] = parent_pid
                normalized["process.parent.executable"] = parent_path
                normalized["process.parent.name"] = parent_name
                if parent_args:
                    normalized["process.parent.args"] = parent_args
                    normalized["process.parent.args_count"] = len(parent_args)
                    normalized["process.parent.command_line"] = " ".join(parent_args)
                
                # Parent code signature
                parent_signing_id = parent_proc.get("signing_id", "")
                parent_team_id = parent_proc.get("team_id", "")
                if parent_signing_id:
                    normalized["process.parent.code_signature.signing_id"] = parent_signing_id
                if parent_team_id:
                    normalized["process.parent.code_signature.team_id"] = parent_team_id
            
            # Now get the NEW process info from event.exec.target
            target = exec_data.get("target", {})
            if target:
                target_exec = target.get("executable", {})
                target_path = target_exec.get("path", "")
                target_name = os.path.basename(target_path) if target_path else ""
                target_audit = target.get("audit_token", {})
                target_pid = target_audit.get("pid") or target.get("pid")
                
                # Override process.* with the new/child process info
                normalized["process.pid"] = target_pid
                normalized["process.executable"] = target_path
                normalized["process.name"] = target_name
                normalized["process.entity_id"] = self._generate_entity_id(target_pid, timestamp) if target_pid else None
                
                # Also set as file.path for detection rules
                if target_path:
                    normalized["file.path"] = target_path
                    normalized["file.name"] = target_name
                
                # Target code signature
                target_signing_id = target.get("signing_id", "")
                target_team_id = target.get("team_id", "")
                if target_signing_id or target_team_id:
                    normalized["process.code_signature.exists"] = True
                    if target_signing_id:
                        normalized["process.code_signature.signing_id"] = target_signing_id
                    if target_team_id:
                        normalized["process.code_signature.team_id"] = target_team_id
            
            # Command line args from exec_data (the actual exec arguments)
            args = exec_data.get("args", [])
            if args:
                normalized["process.args"] = args
                normalized["process.args_count"] = len(args)
                normalized["process.command_line"] = " ".join(args)
            
            # Working directory
            cwd = exec_data.get("cwd", {})
            if cwd:
                normalized["process.working_directory"] = cwd.get("path", "")
        
        # FORK events (11)
        # In ESF fork events:
        #   - "process" is the PARENT (the process calling fork)
        #   - "event.fork.child" is the CHILD (newly forked process)
        elif event_type == 11 and "event" in esf_event:
            fork_data = esf_event.get("event", {}).get("fork", {})
            
            # The responsible "process" is the parent
            if "process" in esf_event:
                parent_proc = esf_event["process"]
                parent_exec = parent_proc.get("executable", {})
                parent_path = parent_exec.get("path", "")
                parent_name = os.path.basename(parent_path) if parent_path else ""
                parent_audit = parent_proc.get("audit_token", {})
                parent_pid = parent_audit.get("pid") or parent_proc.get("pid")
                parent_args = parent_proc.get("args", [])
                
                # Set parent process fields
                normalized["process.parent.pid"] = parent_pid
                normalized["process.parent.executable"] = parent_path
                normalized["process.parent.name"] = parent_name
                if parent_args:
                    normalized["process.parent.args"] = parent_args
                    normalized["process.parent.args_count"] = len(parent_args)
                    normalized["process.parent.command_line"] = " ".join(parent_args)
                
                # Parent code signature
                parent_signing_id = parent_proc.get("signing_id", "")
                parent_team_id = parent_proc.get("team_id", "")
                if parent_signing_id:
                    normalized["process.parent.code_signature.signing_id"] = parent_signing_id
                if parent_team_id:
                    normalized["process.parent.code_signature.team_id"] = parent_team_id
            
            # Get child process info from event.fork.child
            child = fork_data.get("child", {})
            if child:
                child_exec = child.get("executable", {})
                child_path = child_exec.get("path", "")
                child_name = os.path.basename(child_path) if child_path else ""
                child_audit = child.get("audit_token", {})
                child_pid = child_audit.get("pid") or child.get("pid")
                
                # Override process.* with child process info
                normalized["process.pid"] = child_pid
                normalized["process.executable"] = child_path
                normalized["process.name"] = child_name
                normalized["process.entity_id"] = self._generate_entity_id(child_pid, timestamp) if child_pid else None
                
                # Child code signature (inherits from parent initially)
                child_signing_id = child.get("signing_id", "")
                child_team_id = child.get("team_id", "")
                if child_signing_id or child_team_id:
                    normalized["process.code_signature.exists"] = True
                    if child_signing_id:
                        normalized["process.code_signature.signing_id"] = child_signing_id
                    if child_team_id:
                        normalized["process.code_signature.team_id"] = child_team_id
        
        # FILE events (10, 13, 19, 21)
        elif event_type in [10, 13, 19, 21]:
            event_data = esf_event.get("event", {})
            
            target = event_data.get("target", {})
            target_file = target.get("file", target)
            target_path = target_file.get("path", "")
            
            if target_path:
                normalized["file.path"] = target_path
                normalized["file.name"] = os.path.basename(target_path)
                normalized["file.directory"] = os.path.dirname(target_path)
            
            # Rename events
            if event_type == 21:
                source = event_data.get("source", {})
                source_file = source.get("file", source)
                source_path = source_file.get("path", "")
                
                dest = event_data.get("destination", {})
                dest_path = dest.get("path", "") or dest.get("filename", "")
                
                if source_path:
                    normalized["file.source.path"] = source_path
                if dest_path:
                    normalized["file.target.path"] = dest_path
        
        # SIGNAL events (27)
        elif event_type == 27:
            event_data = esf_event.get("event", {})
            signal_data = event_data.get("signal", {})
            
            normalized["signal.number"] = signal_data.get("sig", 0)
            
            target = signal_data.get("target", {})
            if target:
                target_proc = target.get("process", {})
                target_pid = target_proc.get("pid")
                target_exec = target_proc.get("executable", {})
                target_path = target_exec.get("path", "")
                
                normalized["target.process.pid"] = target_pid
                normalized["target.process.executable"] = target_path
                normalized["target.process.name"] = os.path.basename(target_path) if target_path else ""
        
        # PTRACE events (64)
        elif event_type == 64:
            event_data = esf_event.get("event", {})
            ptrace_data = event_data.get("ptrace", {})
            
            normalized["ptrace.request"] = ptrace_data.get("request", 0)
            
            target = ptrace_data.get("target", {})
            if target:
                target_proc = target.get("process", target)
                target_audit = target_proc.get("audit_token", {})
                target_pid = target_proc.get("pid") or target_audit.get("pid")
                target_exec = target_proc.get("executable", {})
                target_path = target_exec.get("path", "")
                
                normalized["target.process.pid"] = target_pid
                normalized["target.process.executable"] = target_path
                normalized["target.process.name"] = os.path.basename(target_path) if target_path else ""
        
        # SETUID/SETGID events (24, 25)
        elif event_type in [24, 25]:
            event_data = esf_event.get("event", {})
            
            if event_type == 24:
                setuid_data = event_data.get("setuid", {})
                target_uid = setuid_data.get("uid")
                if target_uid is not None:
                    normalized["user.target.id"] = str(target_uid)
                    normalized["user.target.name"] = self._get_username(target_uid)
            
            elif event_type == 25:
                setgid_data = event_data.get("setgid", {})
                target_gid = setgid_data.get("gid")
                if target_gid is not None:
                    normalized["group.target.id"] = str(target_gid)
                    normalized["group.target.name"] = self._get_groupname(target_gid)
        
        # MPROTECT events (20)
        elif event_type == 20:
            event_data = esf_event.get("event", {})
            mprotect_data = event_data.get("mmap", {}) or event_data.get("mprotect", {})
            
            protection = mprotect_data.get("protection", 0)
            prot_flags = []
            if protection & 0x1:
                prot_flags.append('r')
            if protection & 0x2:
                prot_flags.append('w')
            if protection & 0x4:
                prot_flags.append('x')
            prot_str = ''.join(prot_flags) if prot_flags else 'none'
            
            normalized["memory.protection"] = protection
            normalized["memory.protection_string"] = prot_str
        
        # KEXT events (17, 18)
        elif event_type in [17, 18]:
            event_data = esf_event.get("event", {})
            kext_key = "kextload" if event_type == 17 else "kextunload"
            kext_data = event_data.get(kext_key, {})
            kext_info = kext_data.get("kext", {})
            
            normalized["driver.name"] = kext_info.get("identifier", "")
            normalized["file.path"] = kext_info.get("path", "")
            if kext_info.get("team_id"):
                normalized["process.code_signature.team_id"] = kext_info.get("team_id")
        
        # AUTHENTICATION events (111)
        elif event_type == 111:
            event_data = esf_event.get("event", {}).get("authentication", {})
            
            auth_success = event_data.get("success")
            normalized["event.outcome"] = "success" if auth_success else "failure"
            normalized["authentication.type"] = event_data.get("type")
            
            # Top-level user fields for authentication context
            if normalized.get("process.user.name"):
                normalized["user.name"] = normalized["process.user.name"]
            if normalized.get("process.user.id"):
                normalized["user.id"] = normalized["process.user.id"]
        
        # XPC_CONNECT events (65)
        elif event_type == 65:
            event_data = esf_event.get("event", {})
            xpc_data = event_data.get("xpc", {})
            normalized["xpc.service_name"] = xpc_data.get("service_name", "")
        
        # MOUNT events (22)
        elif event_type == 22:
            event_data = esf_event.get("event", {})
            mount_data = event_data.get("mount", {})
            statfs = mount_data.get("statfs", {})
            
            mount_path = statfs.get("f_mntonname", "")
            mount_type = statfs.get("f_fstypename", "")
            
            if mount_path:
                normalized["file.path"] = mount_path
                normalized["file.type"] = mount_type
        
        return normalized
    
    def send_to_elasticsearch(self, event: Dict[str, Any]):
        if not self.es_client:
            return
        try:
            # Use custom index name to avoid conflict with Elastic Defend templates
            index_name = f"macos-telemetry-esf-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
            self.es_client.index(index=index_name, body=event)
            
            if not hasattr(self, '_indexed_count'):
                self._indexed_count = 0
            self._indexed_count += 1
            
            if self._indexed_count % 100 == 0:
                print(f"[DEBUG] Indexed {self._indexed_count} events", file=sys.stderr)
        except Exception as e:
            print(f"❌ ERROR: {e}", file=sys.stderr)
    
    def collect(self):
        process = None
        try:
            if os.geteuid() == 0:
                eslogger_cmd = ["eslogger", "--format", "json"]
            else:
                eslogger_cmd = ["sudo", "eslogger", "--format", "json"]
                print("[DEBUG] Running with sudo", file=sys.stderr)
            
            # Event types supported by eslogger (use `eslogger --list-events` to see all)
            # Note: 'trace' is the ptrace equivalent, 'remote_thread_create' is process injection
            events = [
                # Process events
                "exec", "fork", "exit",
                # File events  
                "create", "unlink", "rename", "open", "close", "write",
                # Privilege events
                "setuid", "setgid", "su", "sudo",
                # Memory events
                "mmap", "mprotect",
                # Mount events
                "mount", "unmount",
                # Authentication
                "authentication", "login_login", "login_logout",
                # Code signing / security
                "cs_invalidated", "xp_malware_detected", "xp_malware_remediated",
                # TCC / privacy
                "tcc_modify",
                # Kernel extensions
                "kextload", "kextunload",
                # Process injection / debugging
                "signal", "trace", "remote_thread_create",
                # IPC
                "xpc_connect",
            ]
            eslogger_cmd.extend(events)
            
            print(f"[DEBUG] Running: {' '.join(eslogger_cmd)}", file=sys.stderr)
            
            process = subprocess.Popen(
                eslogger_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=0
            )
            
            print(f"Started eslogger (PID: {process.pid})", file=sys.stderr)
            
            import time
            time.sleep(2)
            
            if process.poll() is not None:
                stderr_output = process.stderr.read()
                print(f"❌ eslogger exited (code: {process.returncode})", file=sys.stderr)
                print(f"Error: {stderr_output}", file=sys.stderr)
                return
            
            print("Collecting events... (Ctrl+C to stop)", file=sys.stderr)
            
            import threading
            def read_stderr():
                try:
                    for line in process.stderr:
                        if line.strip():
                            print(f"[eslogger] {line.strip()}", file=sys.stderr)
                except (IOError, ValueError):
                    pass
            
            threading.Thread(target=read_stderr, daemon=True).start()
            
            event_count = 0
            last_heartbeat = time.time()
            
            for line in process.stdout:
                if not self.running:
                    break
                
                current_time = time.time()
                if current_time - last_heartbeat >= 5:
                    print(f"[DEBUG] {event_count} events collected", file=sys.stderr)
                    last_heartbeat = current_time
                
                if not line.strip():
                    continue
                
                try:
                    raw_event = json.loads(line.strip())
                    event_count += 1
                    self.filter_stats['total_events'] += 1
                    
                    if event_count == 1:
                        print("✅ First event received!", file=sys.stderr)
                    
                    if current_time - (self.last_stats_time or 0) >= 30:
                        self._print_filter_stats()
                        self.last_stats_time = current_time
                    
                    if not self.should_keep_event(raw_event):
                        continue
                    
                    normalized = self.normalize_event(raw_event)
                    
                    if self.output == "stdout":
                        print(json.dumps(normalized))
                    elif self.output == "elasticsearch":
                        self.send_to_elasticsearch(normalized)
                    elif self.output == "file":
                        print(json.dumps(normalized))
                
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error: {e}", file=sys.stderr)
                    continue
            
            if process.poll() is not None:
                print(f"\n⚠️  eslogger exited (code: {process.returncode})", file=sys.stderr)
            
            process.terminate()
            process.wait()
            
        except KeyboardInterrupt:
            print("\nShutting down...", file=sys.stderr)
            if process:
                process.terminate()
                process.wait()
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            if process:
                process.terminate()
                process.wait()


def daemonize(pid_file: str, log_file: str):
    """
    Daemonize the current process.
    
    Args:
        pid_file: Path to write PID file
        log_file: Path to redirect stdout/stderr
    """
    import atexit
    
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Parent exits
    except OSError as e:
        print(f"Fork #1 failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)
    
    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Parent exits
    except OSError as e:
        print(f"Fork #2 failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Open log file
    log_fd = open(log_file, 'a+')
    
    # Redirect stdin to /dev/null, stdout/stderr to log
    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())
    
    # Write PID file
    pid = os.getpid()
    with open(pid_file, 'w') as f:
        f.write(str(pid))
    
    # Remove PID file on exit
    def cleanup():
        try:
            os.remove(pid_file)
        except OSError:
            pass
    
    atexit.register(cleanup)
    
    print(f"[{datetime.now().isoformat()}] Daemon started (PID: {pid})", file=sys.stderr)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="ESF Collector (ESF + ECS output)")
    parser.add_argument("--output", choices=["stdout", "elasticsearch", "file"], 
                       default="stdout")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--no-filtering", action="store_true",
                       help="Disable intelligent filtering")
    parser.add_argument("--daemon", action="store_true",
                       help="Run as background daemon")
    parser.add_argument("--pid-file", default="/var/run/coresigma-esf.pid",
                       help="PID file path (daemon mode)")
    parser.add_argument("--log-file", default="/var/log/coresigma-esf.log",
                       help="Log file path (daemon mode)")
    
    args = parser.parse_args()
    
    # Daemon mode
    if args.daemon:
        # Check if already running
        if os.path.exists(args.pid_file):
            try:
                with open(args.pid_file, 'r') as f:
                    old_pid = int(f.read().strip())
                # Check if process is actually running
                os.kill(old_pid, 0)
                print(f"Daemon already running (PID: {old_pid})", file=sys.stderr)
                sys.exit(1)
            except (OSError, ValueError):
                # Process not running, remove stale PID file
                os.remove(args.pid_file)
        
        print(f"Starting daemon (log: {args.log_file})...", file=sys.stderr)
        daemonize(args.pid_file, args.log_file)
    
    collector = ESFCollector(output=args.output, es_url=args.es_url)
    
    if args.no_filtering:
        collector.ENABLE_FILTERING = False
        print(f"[{datetime.now().isoformat()}] ⚠️  Filtering DISABLED", file=sys.stderr)
    else:
        print(f"[{datetime.now().isoformat()}] ℹ️  Filtering ENABLED", file=sys.stderr)
    
    # Run collector with auto-restart on failure
    while True:
        try:
    collector.collect()
            if not args.daemon:
                break  # Normal exit in non-daemon mode
        except Exception as e:
            print(f"[{datetime.now().isoformat()}] Collector error: {e}", file=sys.stderr)
            if not args.daemon:
                raise
            # In daemon mode, wait and restart
            import time
            print(f"[{datetime.now().isoformat()}] Restarting in 5 seconds...", file=sys.stderr)
            time.sleep(5)


if __name__ == "__main__":
    main()
