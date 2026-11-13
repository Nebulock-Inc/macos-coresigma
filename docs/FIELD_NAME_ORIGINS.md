# Field Names and Mappings

Every field name in coreSigma comes from one table: `pipelines/pysigma-pipeline-macos/sigma/pipelines/macos/taxonomy.py`. The collectors read it to build their documents, and the plugin's pipelines read it to map Sigma rules onto those documents, so the two agree. The tables below are generated from it; if they ever differ, `taxonomy.py` is right.

## How an ESF event becomes a document

```
eslogger --format json  ->  esf_collector.py  ->  flat ECS document  <-  query from macos_esf_ecs  <-  Sigma rule
 (nested raw event)          normalize_event       (Elastic Defend's       (scope + field mapping)     (Image, TargetFilename,
                                                    field names)                                         logsource category)
```

- `event.action` is eslogger's event name (`exec`, `create`, `tcc_modify`, ...). No event numbers are used anywhere.
- `event.category` and `event.type` are stamped from the event's category, Defend-style (`process`/`start` for `exec`, `file`/`creation` for `create`).
- For `exec`, `process.*` describes the new image and `process.parent.*` the image that called exec. For every other event, `process.*` is the acting process.
- `user.id` and `user.name` come from the effective uid of the process the document describes. `host.name` is the collecting host's name. `process.entity_id` is the pid and pidversion.
- A destination given as a directory plus a new file name (`new_path`) is joined into one `file.path`.
- Nothing else from the raw event is copied: there are no `esf.*` fields, and exec environments aren't indexed.

## ESF categories

A rule's `logsource` category selects the events; the pipeline adds the scope below to the query. The collector subscribes eslogger to the events listed here, plus `fork` and `exit`, that this macOS release's eslogger lists (`eslogger --list-events`); it names the ones it skips at startup.

| Category | eslogger events | Query scope the pipeline adds |
|---|---|---|
| `process_creation` | `exec` | `event.category`: `process`, `event.type`: `start`, `event.action`: `exec` |
| `file_event` | `create`, `rename` | (`event.category`: `file`, `event.type`: `creation`) OR (`event.category`: `file`, `event.action`: `rename`) |
| `file_delete` | `unlink` | `event.category`: `file`, `event.type`: `deletion` |
| `file_rename` | `rename` | `event.category`: `file`, `event.action`: `rename` |
| `file_access` | `open` | `event.category`: `file`, `event.action`: `open` |
| `file_attribute_change` | `setextattr`, `deleteextattr`, `setmode`, `setowner`, `setflags` | `event.category`: `file`, `event.type`: `change`, `event.action`: `setextattr` or `deleteextattr` or `setmode` or `setowner` or `setflags` |
| `process_access` | `get_task`, `trace` | `event.category`: `process`, `event.action`: `get_task` or `trace` |
| `create_remote_thread` | `remote_thread_create` | `event.action`: `remote_thread_create` |
| `process_signal` | `signal` | `event.action`: `signal` |
| `memory_protection` | `mprotect` | `event.action`: `mprotect` |
| `driver_load` | `kextload` | `event.action`: `kextload` |
| `xpc_connection` | `xpc_connect` | `event.action`: `xpc_connect` |
| `tcc_modification` | `tcc_modify` | `event.action`: `tcc_modify` |
| `background_task` | `btm_launch_item_add`, `btm_launch_item_remove` | `event.action`: `btm_launch_item_add` or `btm_launch_item_remove` |
| `privilege_change` | `setuid`, `setgid`, `seteuid`, `setreuid`, `setegid`, `setregid` | `event.action`: `setuid` or `setgid` or `seteuid` or `setreuid` or `setegid` or `setregid` |
| `authentication` | `authentication` | `event.category`: `authentication` |
| `gatekeeper_override` | `gatekeeper_user_override` | `event.action`: `gatekeeper_user_override` |
| `configuration_profile` | `profile_add`, `profile_remove` | `event.action`: `profile_add` or `profile_remove` |
| `screen_sharing` | `screensharing_attach`, `screensharing_detach` | `event.action`: `screensharing_attach` or `screensharing_detach` |
| `user_account_change` | `od_create_user`, `od_delete_user`, `od_modify_password`, `od_disable_user`, `od_enable_user`, `od_attribute_value_add`, `od_attribute_value_remove`, `od_attribute_set`, `od_create_group`, `od_delete_group`, `od_group_add`, `od_group_remove`, `od_group_set` | `event.category`: `iam`, `event.action`: `od_create_user` or `od_delete_user` or `od_modify_password` or `od_disable_user` or `od_enable_user` or `od_attribute_value_add` or `od_attribute_value_remove` or `od_attribute_set` or `od_create_group` or `od_delete_group` or `od_group_add` or `od_group_remove` or `od_group_set` |
| `sudo` | `sudo`, `su` | `event.action`: `sudo` or `su` |
| `xprotect` | `xp_malware_detected`, `xp_malware_remediated` | `event.action`: `xp_malware_detected` or `xp_malware_remediated` |

`file_event` takes renames as well as creates: `TargetFilename` is then the rename's destination. The ESF collector keeps only some renames (see [FILTERING_CONFIGURATION.md](FILTERING_CONFIGURATION.md)).

## ESF fields

| Sigma field | ECS field | eslogger path |
|---|---|---|
| `Image` | `process.executable` | exec: `event.exec.target.executable.path`; other events: `process.executable.path` |
| `CommandLine` | `process.command_line` | exec: `event.exec.args` |
| `ParentImage` | `process.parent.executable` | exec: `process.executable.path` |
| `ProcessId` | `process.pid` | all events: `process.audit_token.pid` |
| `ParentProcessId` | `process.parent.pid` | all events: `process.ppid` |
| `SigningID` | `process.code_signature.signing_id` | exec: `event.exec.target.signing_id`; other events: `process.signing_id` |
| `TeamID` | `process.code_signature.team_id` | exec: `event.exec.target.team_id`; other events: `process.team_id` |
| `TargetFilename` | `file.path` | create: `event.create.destination.existing_file.path`, `event.create.destination.new_path.filename`; unlink: `event.unlink.target.path`; open: `event.open.file.path`; rename: `event.rename.destination.existing_file.path`, `event.rename.destination.new_path.filename`; setextattr: `event.setextattr.target.path`; deleteextattr: `event.deleteextattr.target.path`; setmode: `event.setmode.target.path`; setowner: `event.setowner.target.path`; setflags: `event.setflags.target.path`; xp_malware_detected: `event.xp_malware_detected.detected_path`; xp_malware_remediated: `event.xp_malware_remediated.remediated_path`; gatekeeper_user_override: `event.gatekeeper_user_override.file.path`, `event.gatekeeper_user_override.file.file.path`, `event.gatekeeper_user_override.file` |
| `SourceFilename` | `file.Ext.original.path` | rename: `event.rename.source.path` |
| `TargetDirectory` | `file.directory` | create: `event.create.destination.new_path.dir.path`; rename: `event.rename.destination.new_path.dir.path` |
| `ExtendedAttribute` | `file.Ext.extattr` | setextattr: `event.setextattr.extattr`; deleteextattr: `event.deleteextattr.extattr` |
| `TargetImage` | `Target.process.executable` | signal: `event.signal.target.executable.path`; get_task: `event.get_task.target.executable.path`; sudo: `event.sudo.command`; su: `event.su.shell` |
| `SignalNumber` | `signal.number` | signal: `event.signal.sig` |
| `MemoryProtection` | `memory.protection` | mprotect: `event.mprotect.protection` |
| `XpcServiceName` | `xpc.service_name` | xpc_connect: `event.xpc_connect.service_name` |
| `TccService` | `tcc.service` | tcc_modify: `event.tcc_modify.service` |
| `TccIdentity` | `tcc.identity` | tcc_modify: `event.tcc_modify.identity` |
| `TccRight` | `tcc.right` | tcc_modify: `event.tcc_modify.right` |
| `TccReason` | `tcc.reason` | tcc_modify: `event.tcc_modify.reason` |
| `InstigatorImage` | `process.parent.executable` | tcc_modify: `event.tcc_modify.instigator.executable.path`; btm_launch_item_add: `event.btm_launch_item_add.instigator.executable.path`; btm_launch_item_remove: `event.btm_launch_item_remove.instigator.executable.path`; authentication: `event.authentication.data.od.instigator.executable.path`; profile_add: `event.profile_add.instigator.executable.path`; profile_remove: `event.profile_remove.instigator.executable.path`; od_create_user: `event.od_create_user.instigator.executable.path`; od_delete_user: `event.od_delete_user.instigator.executable.path`; od_modify_password: `event.od_modify_password.instigator.executable.path`; od_disable_user: `event.od_disable_user.instigator.executable.path`; od_enable_user: `event.od_enable_user.instigator.executable.path`; od_attribute_value_add: `event.od_attribute_value_add.instigator.executable.path`; od_attribute_value_remove: `event.od_attribute_value_remove.instigator.executable.path`; od_attribute_set: `event.od_attribute_set.instigator.executable.path`; od_create_group: `event.od_create_group.instigator.executable.path`; od_delete_group: `event.od_delete_group.instigator.executable.path`; od_group_add: `event.od_group_add.instigator.executable.path`; od_group_remove: `event.od_group_remove.instigator.executable.path`; od_group_set: `event.od_group_set.instigator.executable.path` |
| `BtmItemUrl` | `btm.item.url` | btm_launch_item_add: `event.btm_launch_item_add.item.item_url` |
| `BtmItemType` | `btm.item.type` | btm_launch_item_add: `event.btm_launch_item_add.item.item_type` |
| `BtmExecutable` | `btm.executable_path` | btm_launch_item_add: `event.btm_launch_item_add.executable_path` |
| `TargetUserId` | `user.target.id` | setuid: `event.setuid.uid`; sudo: `event.sudo.to_uid`; su: `event.su.to_uid` |
| `TargetGroupId` | `user.target.group.id` | setgid: `event.setgid.gid` |
| `KextIdentifier` | `kext.identifier` | kextload: `event.kextload.identifier` |
| `SourceUser` | `source.user.name` | sudo: `event.sudo.from_username`; su: `event.su.from_username` |
| `TargetUser` | `user.target.name` | sudo: `event.sudo.to_username`; su: `event.su.to_username`; authentication: `event.authentication.data.od.record_name`; screensharing_attach: `event.screensharing_attach.authentication_username`; od_create_user: `event.od_create_user.user_name`; od_delete_user: `event.od_delete_user.user_name`; od_disable_user: `event.od_disable_user.user_name`; od_enable_user: `event.od_enable_user.user_name`; od_modify_password: `event.od_modify_password.account_name`; od_group_add: `event.od_group_add.member.member_value`; od_group_remove: `event.od_group_remove.member.member_value`; od_attribute_value_add: `event.od_attribute_value_add.record_name`; od_attribute_value_remove: `event.od_attribute_value_remove.record_name`; od_attribute_set: `event.od_attribute_set.record_name` |
| `TargetGroup` | `user.target.group.name` | od_group_add: `event.od_group_add.group_name`; od_group_remove: `event.od_group_remove.group_name`; od_group_set: `event.od_group_set.group_name`; od_create_group: `event.od_create_group.group_name`; od_delete_group: `event.od_delete_group.group_name` |
| `Success` | `event.outcome` | sudo: `event.sudo.success`; su: `event.su.success`; authentication: `event.authentication.success`; screensharing_attach: `event.screensharing_attach.success`; xp_malware_remediated: `event.xp_malware_remediated.success`; od_create_user: `event.od_create_user.error_code`; od_delete_user: `event.od_delete_user.error_code`; od_modify_password: `event.od_modify_password.error_code`; od_disable_user: `event.od_disable_user.error_code`; od_enable_user: `event.od_enable_user.error_code`; od_attribute_value_add: `event.od_attribute_value_add.error_code`; od_attribute_value_remove: `event.od_attribute_value_remove.error_code`; od_attribute_set: `event.od_attribute_set.error_code`; od_create_group: `event.od_create_group.error_code`; od_delete_group: `event.od_delete_group.error_code`; od_group_add: `event.od_group_add.error_code`; od_group_remove: `event.od_group_remove.error_code`; od_group_set: `event.od_group_set.error_code` |
| `FailureReason` | `event.reason` | sudo: `event.sudo.reject_info.failure_message`; su: `event.su.failure_message` |
| `AuthenticationType` | `authentication.type` | authentication: `event.authentication.type` |
| `SourceAddress` | `source.address` | screensharing_attach: `event.screensharing_attach.source_address`; screensharing_detach: `event.screensharing_detach.source_address` |
| `ViewerAppleID` | `screensharing.viewer_appleid` | screensharing_attach: `event.screensharing_attach.viewer_appleid`; screensharing_detach: `event.screensharing_detach.viewer_appleid` |
| `ExistingSession` | `screensharing.existing_session` | screensharing_attach: `event.screensharing_attach.existing_session` |
| `ProfileIdentifier` | `profile.identifier` | profile_add: `event.profile_add.profile.identifier`; profile_remove: `event.profile_remove.profile.identifier` |
| `ProfileDisplayName` | `profile.display_name` | profile_add: `event.profile_add.profile.display_name`; profile_remove: `event.profile_remove.profile.display_name` |
| `ProfileInstallSource` | `profile.install_source` | profile_add: `event.profile_add.profile.install_source`; profile_remove: `event.profile_remove.profile.install_source` |
| `ProfileScope` | `profile.scope` | profile_add: `event.profile_add.profile.scope`; profile_remove: `event.profile_remove.profile.scope` |
| `OdAttributeName` | `od.attribute_name` | od_attribute_value_add: `event.od_attribute_value_add.attribute_name`; od_attribute_value_remove: `event.od_attribute_value_remove.attribute_name`; od_attribute_set: `event.od_attribute_set.attribute_name` |
| `OdAttributeValue` | `od.attribute_value` | od_attribute_value_add: `event.od_attribute_value_add.attribute_value`; od_attribute_value_remove: `event.od_attribute_value_remove.attribute_value`; od_attribute_set: `event.od_attribute_set.attribute_values` |
| `MalwareIdentifier` | `xprotect.malware_identifier` | xp_malware_detected: `event.xp_malware_detected.malware_identifier`; xp_malware_remediated: `event.xp_malware_remediated.malware_identifier` |
| `MalwareIncidentIdentifier` | `xprotect.incident_identifier` | xp_malware_detected: `event.xp_malware_detected.incident_identifier`; xp_malware_remediated: `event.xp_malware_remediated.incident_identifier` |
| `RemediationAction` | `xprotect.action_type` | xp_malware_remediated: `event.xp_malware_remediated.action_type` |
| `FileSha256` | `file.hash.sha256` | gatekeeper_user_override: `event.gatekeeper_user_override.sha256` |
| `FileSigningID` | `file.code_signature.signing_id` | gatekeeper_user_override: `event.gatekeeper_user_override.signing_info.signing_id` |
| `FileTeamID` | `file.code_signature.team_id` | gatekeeper_user_override: `event.gatekeeper_user_override.signing_info.team_id` |
| `User` | `user.name` | set by the collector from the effective uid of the process the document describes |
| `UserId` | `user.id` | set by the collector from the effective uid of the process the document describes |
| `Signed` | `process.code_signature.exists` | not written by the coreSigma collector |
| `Trusted` | `process.code_signature.trusted` | not written by the coreSigma collector |

`Signed` and `Trusted` are mapped for data that has them (such as Elastic Defend's); a rule on them matches nothing in coreSigma's own collected data. pid values are converted to strings in queries, which matches the collector's keyword-mapped pids but not Elastic Defend's long-typed pids.

`user.*` is always the acting process's user, also where the process is a daemon reporting for someone else (`sudo`, `su`, `opendirectoryd`, `screensharingd`, `mdmclient`). The users the event is about have their own fields:

- `SourceUser` (`source.user.name`) is who ran sudo or su. ECS would put this requester in `user.*`, but here `user.*` stays the acting process's user.
- `TargetUser` (`user.target.name`) is the run-as user for sudo and su. ECS would say `user.effective`; coreSigma uses `user.target`, as `TargetUserId` does for setuid. `TargetUser` is also the account authenticated, logged in to by screen sharing, or changed by an OD event.
- For `od_group_add` and `od_group_remove` (the member) and the `od_attribute_*` events (the record), `TargetUser` can be a UUID or a group name. ESF's `member_type` and `record_type` say which, and they aren't mapped.

`Success` is a boolean in rules (`Success: false`), and documents carry it as ECS `event.outcome`, `success` or `failure`. The collector derives it from ESF's success flag, or for the OD events from the error code (0 is success), and the pipeline converts the rule's value to match. `OdAttributeValue` for `od_attribute_set` is the list of values joined with spaces. `FileSha256` is written in lowercase hex.

Some of these paths are from Apple's `ESMessage.h`, not from captured events:

- `xp_malware_detected`, `xp_malware_remediated` and `gatekeeper_user_override` were never captured. For `gatekeeper_user_override`, `file` is an `es_file_t`, or the bare path when ESF couldn't resolve the file.
- `profile_remove` and these OD events weren't captured either: `od_create_group`, `od_delete_group`, `od_group_remove`, `od_group_set`, `od_disable_user`, `od_enable_user`, `od_attribute_value_remove` and `od_attribute_set`. Their member names match the captured events of the same family.

## Unified Log categories

A UL rule's category selects lines by subsystem or process. The UL collector's `log stream` predicate is all of these, ORed.

| Category | `log` predicate (case-insensitive) |
|---|---|
| `tcc` | `subsystem` startswith `com.apple.TCC` |
| `authorization` | `subsystem` = `com.apple.Authorization` |
| `sudo` | `processImagePath` = `/usr/bin/sudo` |
| `firewall` | `subsystem` startswith `com.apple.ALF` |
| `gatekeeper` | `subsystem` startswith `com.apple.syspolicy` or `processImagePath` = `/usr/libexec/syspolicyd` |
| `launchd` | `processImagePath` = `/sbin/launchd` |
| `xprotect` | `subsystem` startswith `com.apple.xprotect` |
| `securityd` | `subsystem` = `com.apple.securityd` |
| `opendirectory` | `subsystem` startswith `com.apple.opendirectoryd` |
| `mdm` | `processImagePath` endswith `/mdmclient` |

## Unified Log fields

| Sigma field | ECS field (`macos_ul_ecs`) | `log --style ndjson` key (`macos_ul_raw`) |
|---|---|---|
| `subsystem` | `unified_log.subsystem` | `subsystem` |
| `category` | `unified_log.category` | `category` |
| `eventMessage` | `message` | `eventMessage` |
| `message` | `message` | `eventMessage` |
| `Message` | `message` | `eventMessage` |
| `processImagePath` | `process.executable` | `processImagePath` |
| `Image` | `process.executable` | `processImagePath` |
| `senderImagePath` | `unified_log.sender_image_path` | `senderImagePath` |
| `messageType` | `log.level` | `messageType` |
| `processID` | `process.pid` | `processID` |
| `userID` | `user.id` | `userID` |

`macos_ul_raw` also passes `eventType` through; `macos_ul_ecs` fails it, because the collector doesn't keep it.

## Falcon

`macos_falcon` maps `process_creation` rules onto Falcon's process telemetry (`ProcessRollup2`): `Image` to `ImageFileName`, `CommandLine` to `CommandLine`, and `ParentImage` to `ParentBaseFileName`, which holds only the parent's file name: exact and `endswith` values are reduced to their file name, and other modifiers fail. Other fields, and keyword searches, fail conversion.
