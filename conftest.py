import sys
from pathlib import Path

# Ensure the project root is importable when pytest is invoked directly,
# regardless of how (or whether) the editable install resolves on this machine.
_ROOT = str(Path(__file__).parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
