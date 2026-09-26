# Testing

[Documentation home](index.md)

## Backend suite

After [Getting Started](getting-started.md), run from the repository root:

```bash
source .venv/bin/activate
python -m pytest -q
```

`pytest.ini` supplies package paths. Tests cover cryptographic bindings, protocol profiles, constraint enforcement, replay, concurrent grant claims, and uncertain-execution recovery. The demo guide's test count is historical; the current test run is authoritative.

## Web checks

```bash
cd apps/web
npm ci
npm run typecheck
npm run build
```

## Behavioral walkthrough

Run [Demos A–E](demo/README.md) with synthetic participants. Verify the expected diagnostic, grant state, processor result, and evidence view together. A request returning HTTP 200 is not sufficient proof of a successful authorized purchase.

The AP2, VI, and TAP notes record pinned revisions and fixture provenance. Passing these tests establishes behavior within this fixture environment; it is not external network certification.
