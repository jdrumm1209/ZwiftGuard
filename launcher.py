# Copyright (c) 2026 Jason Drummond. All rights reserved.
# Proprietary software: see the "Proprietary License" file in this
# repository. No use, copying, or redistribution without written consent.
"""PyInstaller entry point for the standalone zwiftguard.exe build."""

import sys

from zwiftguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
