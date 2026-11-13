"""Regression checks for specific rule fixes: shipped rule files, converted with the macOS pipelines."""
import re
import sys
from pathlib import Path

import pytest
import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.macos import macos_esf_ecs, macos_ul_ecs

RULES = Path(__file__).resolve().parent.parent / "rules"


def lucene(path, pipeline=macos_esf_ecs):
    return LuceneBackend(pipeline()).convert(SigmaCollection.load_ruleset([str(RULES / path)]))[0]


def test_rename_to_hidden_dotfile_anchors_on_file_name():
    path = "esf/macos_esf_rename_to_hidden_dotfile.yml"
    det = yaml.safe_load((RULES / path).read_text())["detection"]
    hidden, already = det["selection_hidden_name"]["TargetFilename|re"], det["filter_already_hidden"]["SourceFilename|re"]

    def fires(src, dst):  # Sigma re is PCRE, unanchored unless the pattern anchors
        return bool(re.search(hidden, dst)) and not re.search(already, src)

    assert fires("/Users/u/.config/x", "/Users/u/.config/.x")  # missed before the fix
    assert fires("/tmp/payload", "/Users/u/.agent")
    assert not fires("/Users/u/Documents/a.txt", "/Users/u/.Trash/a.txt")  # Move to Trash fired before
    assert not fires("/Users/u/.zsh_history.new", "/Users/u/.zsh_history")
    q = lucene(path)
    assert "file.path:/" in q and "NOT file.Ext.original.path:/" in q


def test_tcc_unusual_access_uses_tccd_service_names():
    q = lucene("ul/tcc_unusual_access.yml", macos_ul_ecs)
    for s in ("kTCCServiceSystemPolicyAllFiles", "kTCCServiceScreenCapture", r"\/Volumes\/", r"\/AppTranslocation\/"):
        assert s in q
    for s in ("Full", "Recording", ".dmg"):
        assert s not in q


def _regexes(path):
    det = yaml.safe_load((RULES / path).read_text())["detection"]
    found = [v for sel in det.values() if isinstance(sel, dict) for k, v in sel.items() if "|re" in k]
    return [rx for v in found for rx in (v if isinstance(v, list) else [v])]


DITTO = "esf/macos_ditto_archive_staging.yml"
DITTO_BASE = "esf/macos_launchdaemon_load_or_ditto_staging.yml"


@pytest.mark.parametrize("path,cmdline,hit", [
    (DITTO, "ditto -c -k --sequesterRsrc --keepParent /tmp/x /tmp/x.zip", True),
    (DITTO, "ditto -ck --sequesterRsrc --keepParent /tmp/x /tmp/x.zip", True),  # combined flags evaded ' -c '
    (DITTO, "ditto -k -c /tmp/x /tmp/x.zip", True),
    (DITTO_BASE, "/usr/bin/ditto -kc --keepParent /tmp/x /tmp/x.zip", True),
    (DITTO, "ditto -x -k /tmp/x.zip /tmp/out", False),  # extracting
    (DITTO, "ditto --keepParent /tmp/a /tmp/b", False),
    ("esf/macos_xattr_quarantine_removal.yml", "xattr -d com.apple.quarantine /tmp/x", True),
    ("esf/macos_xattr_quarantine_removal.yml", "/usr/bin/xattr -rd com.apple.quarantine /Applications/X.app", True),
    ("esf/macos_xattr_quarantine_removal.yml", "xattr -cr /tmp/X.app", True),
    ("esf/macos_xattr_quarantine_removal.yml", "xattr -p com.apple.quarantine /tmp/x", False),
    ("esf/macos_xattr_quarantine_removal.yml", "xattr -l /tmp/x", False),
    ("esf/macos_codesign_adhoc_signature.yml", "codesign --force --deep -s - /tmp/X.app", True),
    ("esf/macos_codesign_adhoc_signature.yml", "codesign -fs - /tmp/X.app", True),
    ("esf/macos_codesign_adhoc_signature.yml", "codesign -s Developer /tmp/X.app", False),
    ("esf/macos_codesign_adhoc_signature.yml", "codesign -dv --verbose=4 /tmp/X.app", False),
])
def test_command_line_regexes(path, cmdline, hit):
    """Each rule regex gives the same answer anchored (Lucene, EQL) and unanchored (PCRE, Splunk)."""
    assert _regexes(path)
    for rx in _regexes(path):
        assert bool(re.fullmatch(rx, cmdline)) == bool(re.search(rx, cmdline))
    combine = all if "ditto" in path else any  # ditto's two flag regexes are ANDed, the others are alternatives
    assert combine(re.search(rx, cmdline) for rx in _regexes(path)) is hit


def test_osascript_hidden_prompt_from_pr5():
    """hidden answer (AppleScript) or hiddenAnswer (JXA) alone, osascript by path or signing ID, scoped by category."""
    assert lucene("esf/macos_osascript_hidden_password_prompt.yml") == (
        "(event.category:process AND event.type:start AND event.action:exec) AND ((process.executable:*\\/osascript OR "
        "process.code_signature.signing_id:com.apple.osascript) AND (process.command_line:(*hidden\\ answer* OR "
        "*hiddenAnswer*)))"
    )


def test_hidden_answer_selection_same_in_all_three_rules():
    """The standalone #5 rule and the two correlation base rules match the same hidden-answer terms."""
    def terms(path, selection):
        value = yaml.safe_load((RULES / path).read_text())["detection"][selection]["CommandLine|contains"]
        return sorted(value if isinstance(value, list) else [value])
    expected = ["hidden answer", "hiddenAnswer"]
    assert terms("esf/macos_osascript_hidden_password_prompt.yml", "selection_cmd") == expected
    assert terms("esf/macos_osascript_hidden_answer_dialog.yml", "selection_cmd") == expected
    assert terms("esf/macos_password_prompt_or_check.yml", "selection_hidden_answer") == expected


def test_terminal_paste_forms():
    """A one-liner pasted into Terminal: curl and base64 run as children of the interactive shell."""
    path = "esf/macos_shell_download_exec_from_script_editor_or_paste.yml"
    det = yaml.safe_load((RULES / path).read_text())["detection"]

    def paste(parent, image, cmd):  # the rule's direct-parent branch; Sigma contains is case-insensitive
        return parent in det["selection_shell_parent"]["ParentImage"] and any(
            image.endswith(sel["Image|endswith"]) and any(s.lower() in cmd.lower() for s in sel["CommandLine|contains"])
            for name, sel in det.items() if name.startswith("selection_paste_")
        )

    assert paste("/bin/zsh", "/usr/bin/curl", "curl -fsSL https://x.example/install.sh")  # curl ... | bash
    assert paste("/bin/zsh", "/usr/bin/base64", "base64 -D")  # echo ... | base64 -D | bash
    assert paste("/bin/bash", "/usr/bin/base64", "base64 --decode")
    assert not paste("/bin/zsh", "/usr/bin/base64", "base64 -i in.bin -o out.txt")  # encoding
    assert not paste("/usr/bin/make", "/usr/bin/curl", "curl https://x.example")  # parent isn't a shell
    assert ("(process.parent.executable:(\\/bin\\/zsh OR \\/bin\\/bash OR \\/bin\\/sh)) AND "
            "((process.executable:*\\/curl AND (process.command_line:(*http\\:\\/\\/* OR *https\\:\\/\\/*)))") in lucene(path)


def test_ssh_connection_skips_sshd_config_test():
    """sshd -t / -T tests or prints the configuration and exits (the simulations' only hits were `sshd -T`)."""
    path = "esf/macos_ssh_connection_detection.yml"
    det = yaml.safe_load((RULES / path).read_text())["detection"]

    def fires(image, cmd):
        def matches(sel):
            if "CommandLine|endswith" in sel:
                return any(cmd.endswith(s) for s in sel["CommandLine|endswith"])
            return any(s in cmd for s in sel["CommandLine|contains"])
        filtered = any(image.endswith(f["Image|endswith"]) and matches(f)
                       for name, f in det.items() if name.startswith("filter_sshd_config_test_"))
        return any(image.endswith(s) for s in det["selection_process"]["Image|endswith"]) and not filtered

    assert not fires("/usr/sbin/sshd", "sshd -T")  # the real event
    assert not fires("/usr/sbin/sshd", "/usr/sbin/sshd -t -f /etc/ssh/sshd_config")
    assert fires("/usr/sbin/sshd", "/usr/sbin/sshd -i")
    assert fires("/usr/sbin/sshd", "sshd -D -p 2222")
    assert fires("/usr/bin/ssh", "ssh -t host top")  # the client's -t forces a tty: still a connection
    assert fires("/usr/libexec/sshd-session", "sshd-session: user [priv]")
    assert "NOT" in lucene(path) and "*\\ \\-T" in lucene(path)


@pytest.mark.parametrize("path", ["esf/macos_dscl_authonly_password_check.yml", "esf/macos_password_prompt_or_check.yml"])
@pytest.mark.parametrize("cmd,hit", [
    ("dscl . authonly user wrong-password", True),  # the paste simulation's form: dscl's leading dashes are optional
    ("dscl /Local/Default -authonly user pw", True),
    ("dscl . -read /Users/user", False),
    ("dscl . read /Users/user AuthenticationAuthority", False),
])
def test_dscl_authonly_with_or_without_dash(path, cmd, hit):
    authonly = yaml.safe_load((RULES / path).read_text())["detection"]["selection_authonly"]["CommandLine|contains"]
    authonly = [authonly] if isinstance(authonly, str) else authonly
    assert any(s.lower() in cmd.lower() for s in authonly) is hit


@pytest.mark.parametrize("path,subsystem,line,hit", [
    # the lines macOS 26.7 logged in the firewall toggle and broken-signature simulations
    ("ul/firewall_disabled.yml", "com.apple.ALF.ApplicationFirewall", "FilterMessageHandler turning firewall off", True),
    ("ul/firewall_disabled.yml", "com.apple.ALF.ApplicationFirewall", "FilterMessageHandler turning firewall on", False),
    ("ul/macos_uls_securityd_codesignature_failure.yml", "com.apple.securityd", "MacOS error: -67061", True),
    ("ul/macos_uls_securityd_codesignature_failure.yml", "com.apple.securityd", "MacOS error: -67062", False),  # unsigned
    ("ul/macos_uls_securityd_codesignature_failure.yml", "com.apple.syspolicy.exec", "Code=-67061", False),  # not securityd
])
def test_ul_rules_match_macos_26_lines(path, subsystem, line, hit):
    sys.path.insert(0, str(RULES.parent / "scripts"))
    import sample_private_baseline  # Sigma's semantics with the pipelines' category conditions

    assert sample_private_baseline.matcher(yaml.safe_load((RULES / path).read_text()))(
        {"unified_log.subsystem": subsystem, "message": line}) is hit
