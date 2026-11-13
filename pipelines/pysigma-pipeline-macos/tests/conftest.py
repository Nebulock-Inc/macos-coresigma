"""Import the plugin from this checkout, not the editable install from another one."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
