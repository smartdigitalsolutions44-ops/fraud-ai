#!/usr/bin/env python
"""SENTINEL local tooling entry point (Stage 14). Use the wrappers in ``scripts/``:

    setup-local.ps1 / setup-local.sh
    sentinel-start.ps1 -Mode Demo|Dev|StagingLike   /  sentinel-start.sh --mode demo|dev|staginglike
    sentinel-status, sentinel-stop, sentinel-reset-demo

or run ``python scripts/sentinel.py <setup|start|stop|status|reset> --help`` directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from localrun.cli import main

if __name__ == "__main__":
    sys.exit(main())
