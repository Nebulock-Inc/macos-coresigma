"""scripts/generate_test_events.py: --dry-run runs and writes nothing, and unknown arguments stop it before anything runs."""
import importlib.util
import subprocess
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("gen_esf", Path(__file__).resolve().parent.parent / "scripts" / "generate_test_events.py")
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)


def boom(*a, **k):
    raise AssertionError("a command ran")


def test_dry_run_runs_and_writes_nothing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "Library" / "LaunchAgents").mkdir(parents=True)
    gen.main(["--dry-run"])
    out = capsys.readouterr().out
    assert "curl -s -o /dev/null https://example.com" in out and "LaunchAgents/.test_sigma_" in out
    assert not any((tmp_path / "Library" / "LaunchAgents").iterdir())


def test_unknown_argument_runs_nothing(monkeypatch):
    # before argparse, `--dryrun` (or any typo) was ignored and every step ran for real
    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(SystemExit):
        gen.main(["--dryrun"])


def test_missing_launchagents_skips_only_that_step(monkeypatch, tmp_path, capsys):
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: ran.append(cmd))
    monkeypatch.setenv("HOME", str(tmp_path))  # no ~/Library/LaunchAgents on a fresh account
    monkeypatch.setattr(gen.time, "sleep", lambda s: None)
    gen.main([])
    assert "skipped:" in capsys.readouterr().out
    assert any("curl" in c for c in ran) and any(c.startswith("rm -f /tmp/test_exec_") for c in ran)
