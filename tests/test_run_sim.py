"""simulations/run_sim.sh end to end with a stub `aws` on PATH: no AWS, no test host."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

RUN_SIM = Path(__file__).resolve().parent.parent / "simulations" / "run_sim.sh"
COMMAND = 'xcode-select -p >/dev/null 2>&1 || exit 1\nrm -rf /tmp/cs_t && mkdir -p /tmp/cs_t'
CLEANUP = 'rm -rf /tmp/cs_t && echo "Cleanup complete" 2>&1'
ATOMIC = """attack_technique: T0000
atomic_tests:
  - name: Ampersand Test
    executor:
      name: bash
      command: |
{command}
      cleanup_command: |
{cleanup}
"""
# Answers the four aws calls run_sim.sh makes; keeps send-command's --parameters for the test to decode.
AWS_STUB = """#!/bin/bash
case "$1 $2" in
  "sts get-caller-identity") echo 000000000000 ;;
  "ssm send-command")
    while [ $# -gt 0 ]; do [ "$1" = --parameters ] && printf '%s' "$2" > "$STUB_DIR/params.json"; shift; done
    echo cmd-1 ;;
  "ssm get-command-invocation")
    case "$*" in *"--query Status"*) echo Success ;; *) cat "$STUB_DIR/invocation.json" ;; esac ;;
esac
"""


def _indent(block):
    return "\n".join("        " + line for line in block.splitlines())


def run_sim(tmp_path, host_stdout, **env_extra):
    """Runs a copy of run_sim.sh (so REPO_ROOT, and reports/sim_windows.json, is tmp_path, not this checkout) with
    the stub aws answering host_stdout; returns (its sim_windows.json entries, the host script it sent)."""
    (tmp_path / "simulations" / "atomics").mkdir(parents=True)
    shutil.copy(RUN_SIM, tmp_path / "simulations" / "run_sim.sh")
    (tmp_path / "simulations" / "atomics" / "T0000-amp.yaml").write_text(
        ATOMIC.format(command=_indent(COMMAND), cleanup=_indent(CLEANUP)))
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "aws").write_text(AWS_STUB)
    (tmp_path / "bin" / "aws").chmod(0o755)
    (tmp_path / "invocation.json").write_text(json.dumps(
        {"Status": "Success", "ResponseCode": 0, "StandardOutputContent": host_stdout, "StandardErrorContent": ""}))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "CORESIGMA_", "DRY_RUN"))}
    env.update(PATH=f"{tmp_path / 'bin'}:{env['PATH']}", STUB_DIR=str(tmp_path),
               CORESIGMA_TEST_INSTANCE="i-test", CORESIGMA_TEST_ACCOUNT="000000000000", **env_extra)
    result = subprocess.run(["bash", str(tmp_path / "simulations" / "run_sim.sh"), "T0000-amp", "0"],
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    windows = json.loads((tmp_path / "reports" / "sim_windows.json").read_text())
    assert len(windows) == 1 and set(windows[0]) == {"name", "start", "end", "status"}  # shape unchanged
    assert windows[0]["name"] == "Ampersand Test"
    params = json.loads((tmp_path / "params.json").read_text())
    hex_script = re.search(r"echo '([0-9a-f]+)'", params["commands"][0]).group(1)
    return windows[0], bytes.fromhex(hex_script).decode()


needs_tools = pytest.mark.skipif(not (shutil.which("jq") and shutil.which("xxd")), reason="run_sim.sh needs jq and xxd")


@needs_tools
def test_run_sim_keeps_ampersands_and_takes_the_window_from_the_host(tmp_path):
    window, script = run_sim(tmp_path, "CS_SIM_START=2026-01-02T03:03:58Z\nSimulation completed successfully in 4s\n"
                                       "CS_SIM_END=2026-01-02T03:04:05Z\nCleanup complete\n"
                                       "Simulation and cleanup complete (status: success)\n")
    assert window["status"] == "success"
    # Both ends on the host's clock: not this machine's time before send-command, nor after the cleanup and polling.
    assert (window["start"], window["end"]) == ("2026-01-02T03:03:58Z", "2026-01-02T03:04:05Z")

    # The host script carries the command and cleanup byte for byte (bash 5.2+ patsub_replacement turned & into
    # the placeholder), prints the start just before the launch and the end before it runs the cleanup.
    assert f"EXIT\n{COMMAND}\nCOMMAND_EOF\n" in script
    assert f"#!/bin/bash\n{CLEANUP}\nCLEANUP_EOF\n" in script
    assert script.index('echo "CS_SIM_START=') < script.index("launchctl asuser")
    assert script.index('echo "CS_SIM_END=') < script.index("sudo -u ec2-user -H /bin/bash /tmp/cs_sim_cleanup.sh")
    # The end is rounded up a second, so the host waits it out: else the cleanup's first commands are in the window
    assert re.search(r'^echo "CS_SIM_END=[^\n]*\nsleep 1\b', script, re.M)
    assert "\nTIMEOUT=120\n" in script  # the default wait


@needs_tools
def test_run_sim_timeout_override(tmp_path):
    """SIM_TIMEOUT sets the host's wait (a hands-on recording window); past 540 s the cleanup would miss SSM's 600 s."""
    _, script = run_sim(tmp_path, "CS_SIM_START=2026-01-02T03:03:58Z\nCS_SIM_END=2026-01-02T03:09:05Z\n",
                        SIM_TIMEOUT="420")
    assert "\nTIMEOUT=420\n" in script
    for bad in ("541", "5m", ""):
        env = {**os.environ, "SIM_TIMEOUT": bad, "DRY_RUN": "true", "CORESIGMA_TEST_INSTANCE": "i-test",
               "CORESIGMA_TEST_ACCOUNT": "000000000000"}
        result = subprocess.run(["bash", str(RUN_SIM), "T1070.004-delete-file-in-etc", "0"], env=env,
                                capture_output=True, text=True, timeout=30)
        assert (result.returncode, "SIM_TIMEOUT" in result.stderr) == ((1, True) if bad else (0, False)), bad


@needs_tools
@pytest.mark.parametrize("host_stdout", [
    "host script failed before the launch\n",
    "CS_SIM_START=2026-01-02T03:03:58Z\nno end line\n",  # one clock each would make a meaningless window
    "CS_SIM_END=2026-01-02T03:04:05Z\n",
])
def test_run_sim_falls_back_to_local_times_for_both(tmp_path, host_stdout):
    before = time.time()
    window, _ = run_sim(tmp_path, host_stdout)
    start, end = (datetime.strptime(window[k], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
                  for k in ("start", "end"))
    assert before - 1 <= start <= end <= time.time()
    assert window["status"] == "clock_fallback"  # rule_matrix counts only success


@pytest.mark.skipif(sys.platform != "darwin", reason="the host is a Mac: BSD date's -v")
def test_host_window_lines_cover_the_whole_last_second():
    """rule_matrix counts @timestamp from start to end inclusive: the start may be truncated to its second, the end
    must not be, or events later in the last second (05.400 with an end of 05.000) fall outside."""
    text = RUN_SIM.read_text()
    lines = {k: re.search(rf'^echo "{k}=.*$', text, re.M).group(0) for k in ("CS_SIM_START", "CS_SIM_END")}
    before = time.time()
    out = {k: subprocess.run(["/bin/bash", "-c", line], capture_output=True, text=True, check=True).stdout
           for k, line in lines.items()}
    after = time.time()
    start, end = (datetime.strptime(out[k].strip().split("=", 1)[1], "%Y-%m-%dT%H:%M:%SZ")
                  .replace(tzinfo=timezone.utc).timestamp() for k in ("CS_SIM_START", "CS_SIM_END"))
    assert start <= after and end > before  # whole seconds: before and after are a few ms apart


def test_run_sim_quotes_placeholder_replacements():
    """macOS /bin/bash 3.2 has no patsub_replacement, so the test above can't catch an unquoted & there."""
    assert not re.search(r"_PLACEHOLDER/\$", RUN_SIM.read_text())
