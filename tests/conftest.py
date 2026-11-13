"""Put src/ on the import path (lm's base_spoke comes from PYTHONPATH, as in CI)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
