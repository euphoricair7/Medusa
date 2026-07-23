import sys
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[2] / "services" / "api"
sys.path.insert(0, str(API_ROOT))