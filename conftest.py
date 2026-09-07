import os
import sys

# 1. Compatibility patch for scipy referencing removed np.long/np.ulong in NumPy 1.24+
try:
    import numpy as np
    if not hasattr(np, "long"):
        np.long = int  # type: ignore[attr-defined]
    if not hasattr(np, "ulong"):
        np.ulong = np.uint  # type: ignore[attr-defined]
except Exception:
    pass

# 2. Set default POSTGRES_DSN for test runner if running on host
if "POSTGRES_DSN" not in os.environ:
    # Default to localhost if reachable, or container IP
    os.environ["POSTGRES_DSN"] = "postgresql://app:app_dev_only@172.26.0.2:5432/ciphcrest"
