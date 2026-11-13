"""macOS taxonomy - single source of truth for categories and field mappings."""

from __future__ import annotations  # collectors load this on stock macOS python3 (3.9)

from dataclasses import dataclass


@dataclass
class EsfCategory:
    events: tuple[str, ...]
    # The query scope (fields ANDed, a tuple value is any of); its single values are what the collector stamps.
    ecs: dict[str, str | tuple[str, ...]]
    # The query scope instead, where it differs from the stamp; a list of such dicts is ORed.
    scope: dict[str, str | tuple[str, ...]] | list[dict[str, str | tuple[str, ...]]] | None = None


@dataclass
class UlCategory:
    raw: list[tuple[str, str, str]]


@dataclass
class EsfField:
    raw: dict[str, str | list[str]]
    ecs: str  # the collector writes it as one document key


@dataclass
class UlField:
    raw: str
    ecs: str


ESF_CATEGORIES: dict[str, EsfCategory] = {
    # Defend writes forks as process + start too, so the scope also takes event.action exec
    "process_creation": EsfCategory(
        events=("exec",),
        ecs={"event.category": "process", "event.type": "start"},
        scope={"event.category": "process", "event.type": "start", "event.action": "exec"}
    ),
    # Creates plus the rename destination (TargetFilename is the new path, as in Defend's rename). Creates by
    # event.type creation, the collector's create. Elastic Defend on macOS reports a new file only as a modification
    # (seen on 9.5.6), so this scope misses Defend's creates (README, Known limitations). Renames, which have
    # no event.type here, take file_rename's stamp: the collector stamps an event with the last category listing it,
    # so file_rename stays after file_event.
    "file_event": EsfCategory(
        events=("create", "rename"),
        ecs={"event.category": "file", "event.type": "creation"},
        scope=[{"event.category": "file", "event.type": "creation"}, {"event.category": "file", "event.action": "rename"}]
    ),
    "file_delete": EsfCategory(
        events=("unlink",),
        ecs={"event.category": "file", "event.type": "deletion"}
    ),
    "file_rename": EsfCategory(
        events=("rename",),
        ecs={"event.category": "file", "event.action": "rename"}
    ),
    "file_access": EsfCategory(
        events=("open",),
        ecs={"event.category": "file", "event.action": "open"}
    ),
    # event.action does the scoping: file + change alone also matches content writes
    "file_attribute_change": EsfCategory(
        events=("setextattr", "deleteextattr", "setmode", "setowner", "setflags"),
        ecs={"event.category": "file", "event.type": "change",
             "event.action": ("setextattr", "deleteextattr", "setmode", "setowner", "setflags")}
    ),
    "process_access": EsfCategory(
        events=("get_task", "trace"),
        ecs={"event.category": "process", "event.action": ("get_task", "trace")}
    ),
    "create_remote_thread": EsfCategory(
        events=("remote_thread_create",),
        ecs={"event.action": "remote_thread_create"}
    ),
    "process_signal": EsfCategory(
        events=("signal",),
        ecs={"event.action": "signal"}
    ),
    "memory_protection": EsfCategory(
        events=("mprotect",),
        ecs={"event.action": "mprotect"}
    ),
    "driver_load": EsfCategory(
        events=("kextload",),
        ecs={"event.action": "kextload"}
    ),
    "xpc_connection": EsfCategory(
        events=("xpc_connect",),
        ecs={"event.action": "xpc_connect"}
    ),
    "tcc_modification": EsfCategory(
        events=("tcc_modify",),
        ecs={"event.action": "tcc_modify"}
    ),
    "background_task": EsfCategory(
        events=("btm_launch_item_add", "btm_launch_item_remove"),
        ecs={"event.action": ("btm_launch_item_add", "btm_launch_item_remove")}
    ),
    "privilege_change": EsfCategory(
        events=("setuid", "setgid", "seteuid", "setreuid", "setegid", "setregid"),
        ecs={"event.action": ("setuid", "setgid", "seteuid", "setreuid", "setegid", "setregid")}
    ),
    "authentication": EsfCategory(
        events=("authentication",),
        ecs={"event.category": "authentication"}
    ),
    "gatekeeper_override": EsfCategory(
        events=("gatekeeper_user_override",),
        ecs={"event.action": "gatekeeper_user_override"}
    ),
    "configuration_profile": EsfCategory(
        events=("profile_add", "profile_remove"),
        ecs={"event.action": ("profile_add", "profile_remove")}
    ),
    "screen_sharing": EsfCategory(
        events=("screensharing_attach", "screensharing_detach"),
        ecs={"event.action": ("screensharing_attach", "screensharing_detach")}
    ),
    "user_account_change": EsfCategory(
        events=("od_create_user", "od_delete_user", "od_modify_password", "od_disable_user", "od_enable_user",
                "od_attribute_value_add", "od_attribute_value_remove", "od_attribute_set",
                "od_create_group", "od_delete_group", "od_group_add", "od_group_remove", "od_group_set"),
        ecs={"event.category": "iam",
             "event.action": ("od_create_user", "od_delete_user", "od_modify_password", "od_disable_user",
                              "od_enable_user", "od_attribute_value_add", "od_attribute_value_remove",
                              "od_attribute_set", "od_create_group", "od_delete_group", "od_group_add",
                              "od_group_remove", "od_group_set")}
    ),
    "sudo": EsfCategory(
        events=("sudo", "su"),
        ecs={"event.action": ("sudo", "su")}
    ),
    "xprotect": EsfCategory(
        events=("xp_malware_detected", "xp_malware_remediated"),
        ecs={"event.action": ("xp_malware_detected", "xp_malware_remediated")}
    ),
}

# Open Directory events: every one reports its instigator (the XPC caller) and an error code (0 is success)
OD_EVENTS = ESF_CATEGORIES["user_account_change"].events

ESF_FIELDS: dict[str, EsfField] = {
    "Image": EsfField(
        raw={
            "exec": "event.exec.target.executable.path",
            "*": "process.executable.path"
        },
        ecs="process.executable"
    ),
    "CommandLine": EsfField(
        raw={"exec": "event.exec.args"},
        ecs="process.command_line"
    ),
    "ParentImage": EsfField(
        raw={"exec": "process.executable.path"},
        ecs="process.parent.executable"
    ),
    "ProcessId": EsfField(
        raw={
            "exec": "process.audit_token.pid",
            "*": "process.audit_token.pid"
        },
        ecs="process.pid"
    ),
    "ParentProcessId": EsfField(
        raw={
            "exec": "process.ppid",
            "*": "process.ppid"
        },
        ecs="process.parent.pid"
    ),
    "SigningID": EsfField(
        raw={
            "exec": "event.exec.target.signing_id",
            "*": "process.signing_id"
        },
        ecs="process.code_signature.signing_id"
    ),
    "TeamID": EsfField(
        raw={
            "exec": "event.exec.target.team_id",
            "*": "process.team_id"
        },
        ecs="process.code_signature.team_id"
    ),
    "TargetFilename": EsfField(
        raw={
            "create": ["event.create.destination.existing_file.path",
                      "event.create.destination.new_path.filename"],
            "unlink": "event.unlink.target.path",
            "open": "event.open.file.path",
            "rename": ["event.rename.destination.existing_file.path",
                      "event.rename.destination.new_path.filename"],
            "setextattr": "event.setextattr.target.path",
            "deleteextattr": "event.deleteextattr.target.path",
            "setmode": "event.setmode.target.path",
            "setowner": "event.setowner.target.path",
            "setflags": "event.setflags.target.path",
            # xp_malware_* and gatekeeper_user_override: from the ESF headers; not observed in captures
            "xp_malware_detected": "event.xp_malware_detected.detected_path",
            "xp_malware_remediated": "event.xp_malware_remediated.remediated_path",
            # file is a union: an es_file_t, or the bare path string when ESF couldn't resolve the file. The arm-nested
            # forms (file.file.path, file.file_path) come before the bare file, so an object never lands in file.path.
            "gatekeeper_user_override": ["event.gatekeeper_user_override.file.path",
                                         "event.gatekeeper_user_override.file.file.path",
                                         "event.gatekeeper_user_override.file.file_path",
                                         "event.gatekeeper_user_override.file"]
        },
        ecs="file.path"
    ),
    "SourceFilename": EsfField(
        raw={"rename": "event.rename.source.path"},
        ecs="file.Ext.original.path"
    ),
    "TargetDirectory": EsfField(
        raw={
            "create": "event.create.destination.new_path.dir.path",
            "rename": "event.rename.destination.new_path.dir.path"
        },
        ecs="file.directory"
    ),
    "ExtendedAttribute": EsfField(
        raw={
            "setextattr": "event.setextattr.extattr",
            "deleteextattr": "event.deleteextattr.extattr"
        },
        ecs="file.Ext.extattr"
    ),
    "TargetImage": EsfField(
        raw={
            "signal": "event.signal.target.executable.path",
            "get_task": "event.get_task.target.executable.path",
            # the program sudo and su run: sudo's resolved command path (no arguments), su's shell
            "sudo": "event.sudo.command",
            "su": "event.su.shell"
        },
        ecs="Target.process.executable"
    ),
    "SignalNumber": EsfField(
        raw={"signal": "event.signal.sig"},
        ecs="signal.number"
    ),
    "MemoryProtection": EsfField(
        raw={"mprotect": "event.mprotect.protection"},
        ecs="memory.protection"
    ),
    "XpcServiceName": EsfField(
        raw={"xpc_connect": "event.xpc_connect.service_name"},
        ecs="xpc.service_name"
    ),
    "TccService": EsfField(
        raw={"tcc_modify": "event.tcc_modify.service"},
        ecs="tcc.service"
    ),
    "TccIdentity": EsfField(
        raw={"tcc_modify": "event.tcc_modify.identity"},
        ecs="tcc.identity"
    ),
    "TccRight": EsfField(
        raw={"tcc_modify": "event.tcc_modify.right"},
        ecs="tcc.right"
    ),
    "TccReason": EsfField(
        raw={"tcc_modify": "event.tcc_modify.reason"},
        ecs="tcc.reason"
    ),
    "InstigatorImage": EsfField(
        raw={
            "tcc_modify": "event.tcc_modify.instigator.executable.path",
            "btm_launch_item_add": "event.btm_launch_item_add.instigator.executable.path",
            "btm_launch_item_remove": "event.btm_launch_item_remove.instigator.executable.path",
            # opendirectoryd and mdmclient report these; the instigator is the process that asked (dscl, sysadminctl)
            "authentication": "event.authentication.data.od.instigator.executable.path",  # OD logins only
            "profile_add": "event.profile_add.instigator.executable.path",
            "profile_remove": "event.profile_remove.instigator.executable.path",
            **{event: f"event.{event}.instigator.executable.path" for event in OD_EVENTS}
        },
        ecs="process.parent.executable"
    ),
    "BtmItemUrl": EsfField(
        raw={"btm_launch_item_add": "event.btm_launch_item_add.item.item_url"},
        ecs="btm.item.url"
    ),
    "BtmItemType": EsfField(
        raw={"btm_launch_item_add": "event.btm_launch_item_add.item.item_type"},
        ecs="btm.item.type"
    ),
    "BtmExecutable": EsfField(
        raw={"btm_launch_item_add": "event.btm_launch_item_add.executable_path"},
        ecs="btm.executable_path"
    ),
    "TargetUserId": EsfField(
        raw={"setuid": "event.setuid.uid", "sudo": "event.sudo.to_uid", "su": "event.su.to_uid"},
        ecs="user.target.id"
    ),
    "TargetGroupId": EsfField(
        raw={"setgid": "event.setgid.gid"},
        ecs="user.target.group.id"
    ),
    "KextIdentifier": EsfField(
        raw={"kextload": "event.kextload.identifier"},
        ecs="kext.identifier"
    ),
    # user.* stays the acting process's user (User, UserId), as in Elastic Defend: for these events that's the process
    # reporting them (sudo, su, opendirectoryd), so the users the event is about get their own fields.
    # SourceUser -> source.user.name, who ran sudo or su: a coreSigma convention. ECS would put the requester in user.*,
    # which here stays the acting process's user; source.user.* is ECS's other nesting for a user the event comes from.
    "SourceUser": EsfField(
        raw={"sudo": "event.sudo.from_username", "su": "event.su.from_username"},
        ecs="source.user.name"
    ),
    # TargetUser -> user.target.name, the account the event targets: for sudo and su the run-as user (a coreSigma
    # convention, as TargetUserId for setuid; ECS would say user.effective), the account authenticated or logged in to
    # by screen sharing, the account an OD change is about (ECS IAM). For od_group_add/od_group_remove
    # (member.member_value) and the od_attribute_* events (record_name) it can be a UUID or a group name instead:
    # member_type and record_type, which aren't mapped, say which.
    "TargetUser": EsfField(
        raw={
            "sudo": "event.sudo.to_username",
            "su": "event.su.to_username",
            "authentication": "event.authentication.data.od.record_name",  # OD logins only
            # the account used to authenticate (null for a VNC-password session); session_username is the session's user
            "screensharing_attach": "event.screensharing_attach.authentication_username",
            "od_create_user": "event.od_create_user.user_name",
            "od_delete_user": "event.od_delete_user.user_name",
            "od_disable_user": "event.od_disable_user.user_name",
            "od_enable_user": "event.od_enable_user.user_name",
            "od_modify_password": "event.od_modify_password.account_name",
            "od_group_add": "event.od_group_add.member.member_value",
            "od_group_remove": "event.od_group_remove.member.member_value",
            "od_attribute_value_add": "event.od_attribute_value_add.record_name",
            "od_attribute_value_remove": "event.od_attribute_value_remove.record_name",
            "od_attribute_set": "event.od_attribute_set.record_name"
        },
        ecs="user.target.name"
    ),
    "TargetGroup": EsfField(
        raw={event: f"event.{event}.group_name" for event in
             ("od_group_add", "od_group_remove", "od_group_set", "od_create_group", "od_delete_group")},
        ecs="user.target.group.name"
    ),
    # A boolean in Sigma; the collector writes ECS event.outcome values (success, failure). OD events report an
    # error code instead, 0 for success.
    "Success": EsfField(
        raw={
            "sudo": "event.sudo.success",
            "su": "event.su.success",
            "authentication": "event.authentication.success",
            "screensharing_attach": "event.screensharing_attach.success",
            "xp_malware_remediated": "event.xp_malware_remediated.success",  # from the ESF headers
            **{event: f"event.{event}.error_code" for event in OD_EVENTS}
        },
        ecs="event.outcome"
    ),
    # Observed: a non-sudoer's rejected sudo has reject_info {plugin_name, plugin_type, failure_message}; su's key
    # is observed (null on success)
    "FailureReason": EsfField(
        raw={"sudo": "event.sudo.reject_info.failure_message", "su": "event.su.failure_message"},
        ecs="event.reason"
    ),
    # Not ECS (no authentication field set there): ESF's es_authentication_type_t, 0 OD, 1 Touch ID, 2 token,
    # 3 Auto Unlock
    "AuthenticationType": EsfField(
        raw={"authentication": "event.authentication.type"},
        ecs="authentication.type"
    ),
    # source.address, not source.ip: ESF's address can also be a named socket, and ECS keeps the raw address there
    "SourceAddress": EsfField(
        raw={"screensharing_attach": "event.screensharing_attach.source_address",
             "screensharing_detach": "event.screensharing_detach.source_address"},
        ecs="source.address"
    ),
    # Not ECS: screen sharing specifics, under screensharing.* as TCC's are under tcc.*
    "ViewerAppleID": EsfField(
        raw={"screensharing_attach": "event.screensharing_attach.viewer_appleid",
             "screensharing_detach": "event.screensharing_detach.viewer_appleid"},
        ecs="screensharing.viewer_appleid"
    ),
    "ExistingSession": EsfField(
        raw={"screensharing_attach": "event.screensharing_attach.existing_session"},
        ecs="screensharing.existing_session"
    ),
    # Not ECS (no configuration profile field set there): profile.*, ESF's es_profile_t member names
    "ProfileIdentifier": EsfField(
        raw={"profile_add": "event.profile_add.profile.identifier",
             "profile_remove": "event.profile_remove.profile.identifier"},
        ecs="profile.identifier"
    ),
    "ProfileDisplayName": EsfField(
        raw={"profile_add": "event.profile_add.profile.display_name",
             "profile_remove": "event.profile_remove.profile.display_name"},
        ecs="profile.display_name"
    ),
    # es_profile_source_t: 0 managed (MDM), 1 installed manually
    "ProfileInstallSource": EsfField(
        raw={"profile_add": "event.profile_add.profile.install_source",
             "profile_remove": "event.profile_remove.profile.install_source"},
        ecs="profile.install_source"
    ),
    "ProfileScope": EsfField(
        raw={"profile_add": "event.profile_add.profile.scope",
             "profile_remove": "event.profile_remove.profile.scope"},
        ecs="profile.scope"
    ),
    # Not ECS: Open Directory attribute changes, under od.*
    "OdAttributeName": EsfField(
        raw={event: f"event.{event}.attribute_name" for event in
             ("od_attribute_value_add", "od_attribute_value_remove", "od_attribute_set")},
        ecs="od.attribute_name"
    ),
    "OdAttributeValue": EsfField(
        raw={
            "od_attribute_value_add": "event.od_attribute_value_add.attribute_value",
            "od_attribute_value_remove": "event.od_attribute_value_remove.attribute_value",
            # od_attribute_set reports a list of values: the collector writes them joined with spaces
            "od_attribute_set": "event.od_attribute_set.attribute_values"
        },
        ecs="od.attribute_value"
    ),
    # xprotect: from the ESF headers; not observed in captures. Not ECS: under xprotect.*, ESF's member names.
    "MalwareIdentifier": EsfField(
        raw={"xp_malware_detected": "event.xp_malware_detected.malware_identifier",
             "xp_malware_remediated": "event.xp_malware_remediated.malware_identifier"},
        ecs="xprotect.malware_identifier"
    ),
    "MalwareIncidentIdentifier": EsfField(
        raw={"xp_malware_detected": "event.xp_malware_detected.incident_identifier",
             "xp_malware_remediated": "event.xp_malware_remediated.incident_identifier"},
        ecs="xprotect.incident_identifier"
    ),
    "RemediationAction": EsfField(
        raw={"xp_malware_remediated": "event.xp_malware_remediated.action_type"},
        ecs="xprotect.action_type"
    ),
    # gatekeeper_user_override: from the ESF headers; not observed in captures. The file the user let run.
    "FileSha256": EsfField(
        raw={"gatekeeper_user_override": "event.gatekeeper_user_override.sha256"},
        ecs="file.hash.sha256"
    ),
    "FileSigningID": EsfField(
        raw={"gatekeeper_user_override": "event.gatekeeper_user_override.signing_info.signing_id"},
        ecs="file.code_signature.signing_id"
    ),
    "FileTeamID": EsfField(
        raw={"gatekeeper_user_override": "event.gatekeeper_user_override.signing_info.team_id"},
        ecs="file.code_signature.team_id"
    ),
    "User": EsfField(
        raw={},
        ecs="user.name"
    ),
    "UserId": EsfField(
        raw={},
        ecs="user.id"
    ),
    "Signed": EsfField(
        raw={},
        ecs="process.code_signature.exists"
    ),
    "Trusted": EsfField(
        raw={},
        ecs="process.code_signature.trusted"
    ),
}

# Unified Log category predicates: (field, modifier, value) tuples, ORed within a category.
# Modifier spellings used below, with Sigma semantics (string matching is case-insensitive
# unless the modifier carries "|cased"):
#   "="           exact match           (Sigma: field: value)
#   "startswith"  prefix match          (Sigma: field|startswith: value)
#   "endswith"    suffix match          (Sigma: field|endswith: value)
# No predicate needs "|cased": subsystem identifiers and image paths are matched the same
# whatever their case (APFS is case-insensitive by default), including xprotect. If one ever does, spell it "startswith|cased", "=|cased" or
# "endswith|cased". The Unified Log collector must therefore emit case-insensitive NSPredicate comparisons ([c]).
# Other table semantics: a tuple of values in an ESF ecs condition means "any of", and a list of
# raw paths in ESF_FIELDS means "any of these paths".
UL_CATEGORIES: dict[str, UlCategory] = {
    "tcc": UlCategory(
        raw=[("subsystem", "startswith", "com.apple.TCC")]
    ),
    "authorization": UlCategory(
        raw=[("subsystem", "=", "com.apple.Authorization")]
    ),
    "sudo": UlCategory(
        raw=[("processImagePath", "=", "/usr/bin/sudo")]
    ),
    "firewall": UlCategory(
        raw=[("subsystem", "startswith", "com.apple.ALF")]
    ),
    "gatekeeper": UlCategory(
        raw=[
            ("subsystem", "startswith", "com.apple.syspolicy"),
            ("processImagePath", "=", "/usr/libexec/syspolicyd")
        ]
    ),
    "launchd": UlCategory(
        raw=[("processImagePath", "=", "/sbin/launchd")]
    ),
    "xprotect": UlCategory(
        raw=[("subsystem", "startswith", "com.apple.xprotect")]
    ),
    "securityd": UlCategory(
        raw=[("subsystem", "=", "com.apple.securityd")]
    ),
    "opendirectory": UlCategory(
        raw=[("subsystem", "startswith", "com.apple.opendirectoryd")]
    ),
    "mdm": UlCategory(
        raw=[("processImagePath", "endswith", "/mdmclient")]
    ),
}

# Aliases (message, Message, Image) map to the native ndjson key in raw; `log` emits no such keys.
UL_FIELDS: dict[str, UlField] = {
    "subsystem": UlField(raw="subsystem", ecs="unified_log.subsystem"),
    "category": UlField(raw="category", ecs="unified_log.category"),
    "eventMessage": UlField(raw="eventMessage", ecs="message"),
    "message": UlField(raw="eventMessage", ecs="message"),
    "Message": UlField(raw="eventMessage", ecs="message"),
    "processImagePath": UlField(raw="processImagePath", ecs="process.executable"),
    "Image": UlField(raw="processImagePath", ecs="process.executable"),
    "senderImagePath": UlField(raw="senderImagePath", ecs="unified_log.sender_image_path"),
    "messageType": UlField(raw="messageType", ecs="log.level"),
    "processID": UlField(raw="processID", ecs="process.pid"),
    "userID": UlField(raw="userID", ecs="user.id"),
}

# Native ndjson keys the UL collector's ECS documents don't carry: macos_ul_raw passes them through, macos_ul_ecs fails
# them. Not in UL_FIELDS, every entry of which the UL collector copies into its documents.
UL_RAW_ONLY_FIELDS: tuple[str, ...] = ("eventType",)
