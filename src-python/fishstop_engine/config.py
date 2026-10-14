"""Runtime configuration for the desktop engine.

Secrets are read only from the process environment. The desktop app never
stores API tokens in source code or browser storage.
"""

import os


def get_secret(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()
