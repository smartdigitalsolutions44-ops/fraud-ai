# Low-context AI development workflow

How to keep developing SENTINEL with a local coding agent, and use a remote model (Claude)
only for the hard parts, without sending it the whole history. Read
[HANDOFF.md](../HANDOFF.md) first; it is the context a new agent needs.

## The loop

```text
local agent  →  local tests  →  local retries (bounded)  →  compressed escalation packet  →  Claude
     ↑                                                                                          │
     └──────────────────── apply the small answer, re-run the same tests ◄───────────────────────┘
```

1. **Local agent first.** A local model (or you) makes the change with the repository open.
   It reads HANDOFF.md, the relevant `*.md` for the area, and the tests for the files it
   touches. Nothing leaves the machine.
2. **Run the narrowest tests that prove the change**, then the area's suite:

   | Area | Fast check |
   |---|---|
   | backend module | `python -m pytest -q tests/test_<area>.py` |
   | lint and types | `python -m ruff check . && python -m mypy` |
   | console | `cd sentinel-console && npm run lint && npm run typecheck && npm test` |
   | local tooling | `python -m pytest -q tests/test_localrun.py tests/test_windows_files.py` |
   | before pushing | `scripts/check.sh` and, for console changes, `npm run build` |

3. **Retry locally, with a limit.** At most three attempts per failure. Each attempt must
   change something specific and be re-tested. Never "fix" a failure by skipping,
   disabling, loosening or deleting a test, or by weakening a security check.
4. **Escalate only when stuck** (three failed attempts), or for a design decision, a
   security-relevant change, or a final review. Build the packet below.
5. **Apply the answer locally** and re-run exactly the tests from the packet. If they still
   fail, send one follow-up with the *new* failure only.

## What not to send

* Full logs, full test output, or whole files. Send the failing assertion and at most
  ~20 relevant lines of traceback.
* Secrets of any kind: `.runtime/`, `sentinel.local.env`, `data/demo/keys/`,
  `deploy/staging/secrets/`, API keys (`fak_…`), signing secrets, operator keys,
  database URLs with passwords. The demo's synthetic data is fine to quote.
* Old conversation history. HANDOFF.md replaces it.

## Escalation template

Copy, fill in, and keep it under about 150 lines.

```markdown
## Task
<one or two sentences: what should be true when this is done>

## Current commit
<git rev-parse --short HEAD> on <branch>; working tree: <clean | N files changed>

## Failure
<the exact failing command>
<the assertion or error message, and at most ~20 lines of traceback>

## Relevant tests
<test file::test name>, and what each checks

## Relevant files
<path:line-range> — <why it matters> (3–6 files at most)

## Attempts already made
1. <what I changed> → <what happened>
2. …
3. …

## Small diff
<git diff of the current attempt, trimmed to the relevant hunks>

## Question for Claude
<one specific question, e.g. "Why does X still fail after Y?" or
 "Is this change safe for the security invariant Z in HANDOFF.md?">
```

## When Claude is worth it

* a failure the local agent cannot explain after three attempts;
* anything touching a security invariant in HANDOFF.md (signing, replay, model loading,
  audit, operator authentication, the demo reset guard);
* review and polish of user-facing text and docs before a release;
* a design choice with several plausible answers.

For everything else, the local loop is faster and keeps the remote context small.
