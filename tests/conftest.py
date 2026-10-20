import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["ATL4S_DATA_DIR"] = tempfile.mkdtemp(prefix="atl4s-tests-")
