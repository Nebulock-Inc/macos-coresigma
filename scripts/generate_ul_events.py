#!/usr/bin/env python3
"""
Generate Unified Log lines that trigger coreSigma's UL rules, with harmless local actions.

Run it while the UL collector is running (python3 collectors/ul_collector.py --output elasticsearch).
generate_test_events.py covers the ESF rules; this covers the UL rules a safe local action can reach.

Each step is a trimmed copy of a simulation under simulations/atomics/, and the rule it
fires on was verified there on macOS 26.7:

  broken signature  (default)   macOS ULS securityd CodeSignature Failure
                                T1553.002-tampered-apple-binary-exec: needs the Xcode Command Line Tools
  firewall toggle   (--firewall) Firewall Disabled
                                T1686-firewall-toggle-restore: asks for your sudo password and switches the
                                application firewall the other way for about 2 seconds, then back

Most UL rules can't be reached this way (sudo logging, TCC denials, launchd, XPC): see docs/TROUBLESHOOTING.md.
An EDR on this Mac may alert on the broken-signature step. Run it on a Mac you may test on.

    python3 scripts/generate_ul_events.py [--firewall] [--dry-run]
"""
import argparse
import errno
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FIREWALL = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def run(cmd, dry_run, **kw):
    print("    $ " + " ".join(str(c) for c in cmd))
    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def text_offset(otool_output):
    """File offset of the __text section in `otool -l` output."""
    match = re.search(r"sectname __text\b.*?\boffset (\d+)", otool_output, re.S)
    if not match:
        raise RuntimeError("no __text section in otool -l output")
    return int(match.group(1))


def broken_signature(dry_run):
    print("\n[1] Broken code signature -> macOS ULS securityd CodeSignature Failure")
    print("    Expect: `MacOS error: -67061` from codesign and syspolicyd, subsystem com.apple.securityd")
    if not dry_run and run(["xcode-select", "-p"], False).returncode != 0:
        print("    skipped: needs the Xcode Command Line Tools (xcode-select --install)")
        return
    # --dry-run writes nothing, not even the temp directory
    work = Path(tempfile.gettempdir(), "cs_gen_badsig_DRYRUN") if dry_run else Path(tempfile.mkdtemp(prefix="cs_gen_badsig_"))
    killed = 0
    copy = work / "cs_gen_echo"
    try:
        # a copy of /bin/echo with one byte of its code flipped: the signature no longer matches
        if run(["lipo", "/bin/echo", "-thin", "arm64e", "-output", copy], dry_run).returncode != 0:
            print("    skipped: /bin/echo has no arm64e slice here (this step needs an Apple silicon Mac)")
            return
        if not dry_run:
            offset = text_offset(run(["otool", "-l", copy], False).stdout)
            with open(copy, "r+b") as f:
                f.seek(offset)
                byte = f.read(1)
                f.seek(offset)
                f.write(bytes([byte[0] ^ 0xFF]))
        run(["codesign", "--verify", "--verbose=2", copy], dry_run)
        try:
            killed = run([copy, "coresigma-gen"], dry_run).returncode  # the kernel kills it during exec; that is the point
        except OSError as e:
            if e.errno == errno.EBADARCH:  # an Intel Mac can thin /bin/echo to arm64e but can't run it ("Bad CPU type")
                print("    skipped: can't run the arm64e copy here; this step needs an Apple silicon Mac")
            else:  # e.g. the kernel refused the exec outright: the log line may still have been written
                print(f"    the tampered copy didn't start ({e.strerror}); check the log for the CodeSignature Failure line")
            killed = 1  # so the crash-report cleanup below still runs
    finally:
        if not dry_run:
            shutil.rmtree(work, ignore_errors=True)
        if not dry_run and killed != 0:  # the kill can leave a crash report a few seconds later
            reports = Path.home() / "Library/Logs/DiagnosticReports"
            for _ in range(10):
                if list(reports.glob("cs_gen_echo*")):
                    break
                time.sleep(1)
            for report in reports.glob("cs_gen_echo*"):
                report.unlink()


def firewall_toggle(dry_run):
    print("\n[2] Firewall switched off and back -> Firewall Disabled")
    print("    Expect: `FilterMessageHandler turning firewall off`, subsystem com.apple.ALF.ApplicationFirewall")
    out = run(["sudo", FIREWALL, "--getglobalstate"], dry_run).stdout
    state = re.search(r"State = (\d)", out)
    if not dry_run and not state:
        print("    skipped: couldn't read the firewall state (needs sudo)")
        return
    state = state.group(1) if state else "1"
    if state not in ("0", "1"):
        print(f"    skipped: global state {state} is not handled")
        return
    other, original = ("off", "on") if state == "1" else ("on", "off")
    try:
        run(["sudo", FIREWALL, "--setglobalstate", other], dry_run)
        # starting off, this turns it on and the restore turns it off again: the off line comes from the restore
        if not dry_run:
            now = re.search(r"State = (\d)", run(["sudo", FIREWALL, "--getglobalstate"], False).stdout)
            if not now:
                print("    couldn't read the firewall state after the toggle (sudo?); check the log for a Firewall Disabled line")
            elif now.group(1) == state:
                print("    the firewall didn't switch (sudo refused, or MDM manages it): no Firewall Disabled line will be logged")
            else:
                time.sleep(2)
    finally:
        run(["sudo", FIREWALL, "--setglobalstate", original], dry_run)
    if not dry_run:
        back = re.search(r"State = (\d)", run(["sudo", FIREWALL, "--getglobalstate"], False).stdout)
        print(f"    firewall state restored: {'yes' if back and back.group(1) == state else 'CHECK System Settings'}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--firewall", action="store_true", help="also toggle the application firewall (asks for sudo)")
    parser.add_argument("--dry-run", action="store_true", help="print the commands without running them")
    args = parser.parse_args(argv)
    if sys.platform != "darwin" and not args.dry_run:
        sys.exit("macOS only: these actions produce macOS Unified Log lines")
    print("Generating Unified Log events. Make sure the UL collector is running.")
    broken_signature(args.dry_run)
    if args.firewall:
        firewall_toggle(args.dry_run)
    print("\nDone. In Kibana, look at the macos-telemetry-ul-* index (last 5 minutes).")


if __name__ == "__main__":
    main()
