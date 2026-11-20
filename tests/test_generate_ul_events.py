"""scripts/generate_ul_events.py: nothing runs on --dry-run, and the __text offset is read the way the atomic reads it."""
import importlib.util
import subprocess
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("gen_ul", Path(__file__).resolve().parent.parent / "scripts" / "generate_ul_events.py")
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)

OTOOL = """Section
  sectname __text
   segname __TEXT
      addr 0x0000000100003f00
      size 0x0000000000000018
    offset 16128
     align 2^2 (4)
"""


def test_text_offset():
    assert gen.text_offset(OTOOL) == 16128


def test_dry_run_runs_nothing(monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("a command ran during --dry-run")
    monkeypatch.setattr(subprocess, "run", boom)
    gen.main(["--dry-run", "--firewall"])
    out = capsys.readouterr().out
    assert "codesign --verify" in out and "--setglobalstate" in out


def test_firewall_step_is_opt_in(capsys):
    gen.main(["--dry-run"])
    assert "--setglobalstate" not in capsys.readouterr().out


def test_dry_run_makes_no_temp_dir(monkeypatch):
    monkeypatch.setattr(gen.tempfile, "mkdtemp", lambda *a, **k: (_ for _ in ()).throw(AssertionError("mkdtemp during --dry-run")))
    gen.main(["--dry-run"])


def fake_run(handlers):
    """gen.run stand-in: the first handler whose key is in the command line answers; the rest return 0."""
    def run(cmd, dry_run, **kw):
        line = " ".join(str(c) for c in cmd)
        for key, handler in handlers.items():
            if key in line:
                return handler(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return run


def test_intel_mac_skips_instead_of_crashing(monkeypatch, capsys):
    # lipo can thin /bin/echo to arm64e on an Intel Mac, but running the copy raises "Bad CPU type"
    def lipo(cmd):
        Path(cmd[-1]).write_bytes(b"\0" * 16200)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    def exec_copy(cmd):
        raise OSError(86, "Bad CPU type in executable")
    monkeypatch.setattr(gen, "run", fake_run({"lipo": lipo, "otool": lambda c: subprocess.CompletedProcess(c, 0, OTOOL, ""),
                                              "coresigma-gen": exec_copy}))
    gen.broken_signature(False)
    assert "needs an Apple silicon Mac" in capsys.readouterr().out


def test_firewall_that_does_not_switch_is_reported(monkeypatch, capsys):
    # MDM-managed firewall, or sudo refused: the state stays 1, so no "turning firewall off" line will appear
    monkeypatch.setattr(gen, "run", fake_run({"--getglobalstate": lambda c: subprocess.CompletedProcess(c, 0, "Firewall is enabled. (State = 1)", "")}))
    monkeypatch.setattr(gen.time, "sleep", lambda s: (_ for _ in ()).throw(AssertionError("waited for a toggle that didn't happen")))
    gen.firewall_toggle(False)
    out = capsys.readouterr().out
    assert "didn't switch" in out and "restored: yes" in out
