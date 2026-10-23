# Contributing to EACP

Thanks for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/mrschneider/eacp.git
cd eacp
pip install -e .
pip install cryptography
```

## Running Tests

```bash
python -m unittest discover tests -v
```

All 35 tests must pass. CI runs the suite on Python 3.10–3.13 across
Linux, macOS and Windows — new code must not break any matrix cell.

## Pull Request Checklist

- [ ] Tests added/updated for the change (`tests/`)
- [ ] `ARCHITECTURE.md` updated if the wire format, error codes or semantics changed
- [ ] `CHANGELOG.md` updated under an *Unreleased* section
- [ ] No secrets, tokens or internal hostnames in commits
- [ ] Wire-format changes are backward-compatible or bump the protocol version byte

## Design Rules

1. **Fail closed.** Any unknown/unregistered action is denied by default.
2. **Capabilities before compute.** Never invoke handlers or LLMs before PlatSec validation.
3. **No unbounded memory.** Every allocation guarded by declared payload limits.
4. **Deterministic rollback.** Resources opened inside `RunL()` must be pushed to the `CleanupStack`.
5. **Hardware/cloud agnostic.** No assumptions about local hosts, paths or topologies.
