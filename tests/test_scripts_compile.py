"""Every script and collector the docs tell users to run at least compiles."""
import py_compile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("path", sorted((ROOT / "scripts").glob("*.py")) + sorted((ROOT / "collectors").glob("*.py")),
                         ids=lambda p: p.name)
def test_compiles(path, tmp_path):
    py_compile.compile(str(path), cfile=str(tmp_path / "out.pyc"), doraise=True)
