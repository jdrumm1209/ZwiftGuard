"""PyInstaller entry point for the standalone zwiftguard.exe build."""

import sys

from zwiftguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
