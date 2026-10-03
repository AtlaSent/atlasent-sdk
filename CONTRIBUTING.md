# Contributing to atlasent-sdk

Thanks for your interest in contributing. This repo holds the Python
(`atlasent`) and TypeScript (`@atlasent/sdk`) client SDKs for AtlaSent,
plus their framework-integration packages (LangChain, LlamaIndex,
Cursor, Enforce, Behavior, etc.).

## Filing issues

Use [GitHub Issues](https://github.com/AtlaSent-Systems-Inc/atlasent-sdk/issues)
for bugs and feature requests. Please include:

- The SDK/package and version affected (e.g. `atlasent 2.15.0`,
  `@atlasent/sdk 2.20.0`, `@atlasent/enforce 1.0.0`).
- A minimal reproduction — a short code snippet is far more useful than
  a description.
- Expected vs. actual behavior.

Security vulnerabilities should **not** be filed as public issues — see
[`SECURITY.md`](./SECURITY.md).

## Local development

### TypeScript (`typescript/`, `typescript/packages/*`)

```bash
cd typescript
npm ci
npm run typecheck          # TypeScript 7 tsc --noEmit
npm test                   # vitest run
npm run build              # tsup (JS) + scripts/build-dts.mjs (declarations)
```

The root package builds with TypeScript 7. Run the compiler through the npm
scripts, not `npx tsc`: the declaration bundler needs the TypeScript 6 API
(`@typescript/typescript6`), whose dependency links its own `tsc` into
`node_modules/.bin`, so a bare `tsc` there is TypeScript 6. The scripts call
`node_modules/typescript/bin/tsc` directly.

Each sub-package under `typescript/packages/<name>/` has its own
`package.json` with equivalent `typecheck` / `test` / `build` scripts —
run them from that package's directory when working on a single
integration (e.g. `cd typescript/packages/enforce && npm test`).

### Python (`python/`, `python/atlasent_*`)

```bash
cd python
pip install -e ".[dev]"
ruff check atlasent/ tests/     # lint
black --check atlasent/ tests/  # formatting
pytest tests/ -v --cov          # tests (with coverage)
```

Sub-packages (`python/atlasent_langchain`, `python/atlasent_enforce`,
etc.) follow the same pattern from their own directory.

### Contract

Anything touching `/v1-evaluate` or `/v1-verify-permit` wire shapes goes
through [`contract/`](./contract/) first — see "Contract-first for wire
changes" in `CLAUDE.md`. The drift detector
(`contract/tools/drift.py`) blocks CI if SDK types drift from the
contract.

## Coding standards

- TypeScript: keep line coverage ≥ 95% (`vitest.config.ts` thresholds);
  code must pass `npm run typecheck` and `npm test` before review.
- Python: keep coverage ≥ 95% (`pyproject.toml`
  `[tool.coverage.report] fail_under`); code must pass `ruff check` and
  `black --check` before review. `atlasent-enforce` specifically holds
  itself to a 100% coverage floor as an enforcement primitive.
- Match the existing style in the file you're editing — this repo does
  not use a single monorepo-wide formatter config, each package's CI
  job is the source of truth for what it enforces.
- Do not add fail-open fallbacks to any authorization path. Fail-closed
  behavior (deny on error, timeout, or malformed response) is a hard
  invariant across every package here.

## Pull request process

1. Branch off `main` using this org's convention: `claude/<topic>` (or
   a descriptive `<lang>-sdk-<topic>` variant for SDK-scoped work —
   see `CLAUDE.md`).
2. Keep the PR focused — one logical change per PR. If a change touches
   both a contract schema and generated SDK code, that's one PR; unrelated
   cleanups belong in a separate one.
3. Fill out the PR template (Summary + Test plan). Note any wire-shape
   or contract changes explicitly.
4. Open the PR against `main`. CI (`typescript-ci.yml`, `python-ci.yml`,
   `contract-ci.yml`, and any package-specific workflow your change
   touches) must pass before merge.
5. Address review feedback with new commits; avoid force-pushing over
   history a reviewer is actively looking at.

By contributing, you agree your contributions are licensed under this
repository's [Apache License, Version 2.0](./LICENSE).
