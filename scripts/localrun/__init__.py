"""SENTINEL local tooling (Stage 14): one implementation behind the PowerShell and shell
wrappers in ``scripts/`` (setup-local, sentinel-start, -stop, -status, -reset-demo).

Everything it creates lives under ``.runtime/`` (git-ignored) or in ``sentinel.local.env``
(git-ignored, created once from ``sentinel.local.env.example``). It only ever stops
processes and containers it started itself, and it never touches a database other than the
demo world (through the existing guarded ``fraud-ai demo reset``) or its own Docker volumes.
"""
