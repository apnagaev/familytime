import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))
os.environ.setdefault("TEST_DATABASE_URL", "postgresql://ft:ft@127.0.0.1:55433/ft")
