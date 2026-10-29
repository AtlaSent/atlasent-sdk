# Releasing the AtlaSent SDKs

Publish procedure for the Python (`atlasent` on PyPI) and TypeScript
(`@atlasent/sdk` on npm) SDKs. The two packages version independently;
each has its own git-tag prefix and its own publish workflow.

## Who may release

Only the people listed by numeric user id in
[`.github/production-dispatchers.json`](.github/production-dispatchers.json).
Every job bound to the `npm`, `npm-enforce` or `pypi` environment, and every
job in `publish-go.yml`, first runs `.github/actions/production-dispatcher-check`.
It refuses unless the tag pusher or dispatcher, and anyone re-running the
attempt, is on that list, so a tag pushed by anyone else publishes nothing.
`production-dispatcher-guard.yml` fails the build if a publish job lacks the
check. Adding a person is a reviewed change to that file plus a
DECISION_LEDGER entry in `atlasent-internal`.

## Tag convention

### v1 stable packages

| Package         | Tag format               | Workflow                              |
|-----------------|--------------------------|---------------------------------------|
| `atlasent` (py) | `python-v<semver>`       | `.github/workflows/publish-pypi.yml`  |
| `@atlasent/sdk` | `typescript-v<semver>`   | `.github/workflows/publish-npm.yml`   |

### v2-alpha packages

| Package                    | Tag format                        | Workflow                                    |
|----------------------------|-----------------------------------|---------------------------------------------|
| `atlasent-v2-alpha` (py)   | `python-v2-alpha-v<pep440>`       | `.github/workflows/publish-pypi-v2alpha.yml`|
| `@atlasent/sdk-v2-alpha`   | `typescript-v2-alpha-v<semver>`   | `.github/workflows/publish-npm-v2alpha.yml` |

Alpha tags use PEP 440 / npm pre-release versions (e.g. `2.0.0a1` /
`2.0.0-alpha.1`). The v2-alpha packages publish to the `alpha` dist-tag
on npm so `npm install @atlasent/sdk-v2-alpha` does not accidentally
install an alpha unless the user explicitly passes `@alpha`.

A single push can trigger **one** workflow per tag-prefix. Push all
four tags in a single command if releasing all four packages at once.

All four tag-prefix filters are mutually exclusive.

### Framework integration packages (Python)

| Package               | Tag format              | Workflow                                     |
|------------------------|--------------------------|-----------------------------------------------|
| `atlasent-langchain`   | `langchain-py-v<semver>` | `.github/workflows/publish-pypi-langchain.yml`|
| `atlasent-llamaindex`  | `llamaindex-py-v<semver>`| `.github/workflows/publish-pypi-llamaindex.yml`|

These are standalone PyPI distributions (see `python/atlasent_langchain/`
and `python/atlasent_llamaindex/`), versioned independently of `atlasent`
itself via a static `version` field in each package's own `pyproject.toml`
(not a `_version.py` module). Bump that field, then:

```sh
git tag langchain-py-v1.5.2
git push origin langchain-py-v1.5.2
```

(substitute `llamaindex-py-v<semver>` for the other package). Each tag
fires exactly one publisher — the tag prefix is the whole dispatch
mechanism, same as the tables above. This section documents only the
langchain/llamaindex pair; other sibling packages under `python/` follow
the same `<name>-py-v*` / `publish-pypi-<name>.yml` shape where such a
workflow exists (check `.github/workflows/` for the current list — this
file does not enumerate every one).

## Pre-flight (both languages)

Before tagging:

1. The CHANGELOG entry for the release is on `main` under the right
   version heading (e.g. `## 1.2.0 — 2026-04-23`).
2. The version in the source matches the CHANGELOG heading:
   - Python: `python/atlasent/_version.py` → `__version__`.
   - TypeScript: `typescript/package.json` → `"version"`.
3. The contract suite is green on `main`
   (`contract/tools/drift.py` — runs in CI).
4. Per-language CI is green on `main` (`python-ci.yml` /
   `typescript-ci.yml`).

The publish workflows refuse to publish if the git tag version and
the in-source version disagree, but catching the mismatch locally is
cheaper than failing a workflow.

## Python release

```bash
# Bump python/atlasent/_version.py and python/CHANGELOG.md; land via PR.
# Once merged to main:
git checkout main && git pull
git tag python-v1.2.0
git push origin python-v1.2.0
```

The `publish-pypi.yml` workflow then:

1. Runs `pytest` across Python 3.10 / 3.11 / 3.12.
2. Verifies `python-v<semver>` matches `atlasent._version.__version__`.
3. `python -m build` → sdist + wheel.
4. `twine check dist/*`.
5. Installs the freshly-built wheel in a clean venv and smoke-imports
   the public surface (`protect`, `authorize`, `AtlaSentClient`,
   `AsyncAtlaSentClient`, `AtlaSentError`, `AtlaSentDeniedError`).
6. Publishes via **PyPI trusted publishing (OIDC)** — PEP 740
   attestations are generated and uploaded automatically. No
   `PYPI_TOKEN` secret.

First-time setup (once per project): configure the trusted publisher
at <https://pypi.org/manage/account/publishing/> pointing at this
repo and the `publish-pypi.yml` workflow. The `environment: pypi`
gate in the workflow is the GitHub Environment name PyPI expects.

Post-publish: check the release on PyPI
(<https://pypi.org/project/atlasent/>) and that
`pip install atlasent==<version>` resolves from a clean cache.

## TypeScript release

```bash
# Bump typescript/package.json ("version") and typescript/CHANGELOG.md;
# land via PR. Once merged to main:
git checkout main && git pull
git tag typescript-v1.2.0
git push origin typescript-v1.2.0
```

The `publish-npm.yml` workflow then:

1. Runs `npm run typecheck`, `npm test`, and `npm run build` across
   Node 20 and 22.
2. Verifies `typescript-v<semver>` matches `package.json` `"version"`.
3. `npm pack --dry-run` — the exact file list that will ship is
   logged in the Actions output. Inspect it on first release.
4. `npm publish --access public --provenance` — Sigstore attestations
   link the tarball to this workflow run.

First-time setup (once per package): npm publishes use **trusted
publishing** (OIDC) — there is no `NPM_TOKEN`. On npmjs.com →
the package → Settings → Trusted Publisher → GitHub Actions, set
organization `Atlasent`, repository `atlasent-sdk`, the workflow file
that publishes the package (e.g. `publish-npm.yml` for `@atlasent/sdk`),
and that job's environment (`npm`; `npm-enforce` for `publish-npm-enforce.yml`),
and check **Allow npm publish**. The job's `id-token: write` (already set)
is what npm authenticates, and it also signs the provenance attestation.
The workflow upgrades npm to >= 11.5.1, which trusted publishing requires.

The AtlaSent release gate authenticates with the repo secret
`ATLASENT_API_KEY`; it must belong to the organization whose
`package.release` bundle carries this workflow's template, or every
publish denies with `No template condition matched` (see the comment on
the gate step in `publish-npm.yml`).

Post-publish: check the release on npm
(<https://www.npmjs.com/package/@atlasent/sdk>) and that
`npm view @atlasent/sdk@<version>` resolves. The provenance badge on
the npm page confirms the Sigstore attestation.

## v2-alpha packages

The `atlasent-v2-alpha` and `@atlasent/sdk-v2-alpha` packages follow
alpha-release semantics — **no semver discipline between alpha
releases**. Callers who depend on them from production code should
pin to an exact version.

### Pre-flight (v2-alpha)

Before tagging:

1. `python/atlasent_v2_alpha/pyproject.toml` `version` and
   `atlasent_v2_alpha/__init__.__version__` agree.
2. `typescript/packages/v2-alpha/package.json` `"version"` is correct.
3. `RELEASE_NOTES.md` has an entry for the release.
4. `python/atlasent_v2_alpha/tests/` pass: `cd python/atlasent_v2_alpha && pytest`.
5. `typescript/packages/v2-alpha` tests pass:
   `cd typescript/packages/v2-alpha && npm test && npm run typecheck && npm run build`.

### Python v2-alpha release

```bash
# Bump pyproject.toml version + __init__.__version__; land via PR.
# Once merged to main:
git checkout main && git pull
git tag python-v2-alpha-v2.0.0a1
git push origin python-v2-alpha-v2.0.0a1
```

The `publish-pypi-v2alpha.yml` workflow:

1. `pytest` across Python 3.10 / 3.11 / 3.12.
2. Verifies tag version matches `pyproject.toml` `version`.
3. `python -m build` + `twine check`.
4. Smoke-installs the wheel and imports the public surface.
5. Publishes via PyPI trusted publishing (OIDC).

Post-publish: `pip install atlasent-v2-alpha==2.0.0a1`.

### TypeScript v2-alpha release

```bash
# Bump typescript/packages/v2-alpha/package.json "version"; land via PR.
# Once merged to main:
git checkout main && git pull
git tag typescript-v2-alpha-v2.0.0-alpha.1
git push origin typescript-v2-alpha-v2.0.0-alpha.1
```

The `publish-npm-v2alpha.yml` workflow:

1. `npm run typecheck`, `npm test`, `npm run build` across Node 20 and 22.
2. Verifies tag version matches `package.json` `"version"`.
3. `npm pack --dry-run` — inspect file list in Actions output.
4. `npm publish --access public --provenance --tag alpha` — tagged `alpha`
   so `npm install @atlasent/sdk-v2-alpha` doesn't accidentally
   pull an alpha.

Post-publish: `npm install @atlasent/sdk-v2-alpha@2.0.0-alpha.1`.

### Coordinated v2-alpha release (both languages)

```bash
git tag python-v2-alpha-v2.0.0a1
git tag typescript-v2-alpha-v2.0.0-alpha.1
git push origin python-v2-alpha-v2.0.0a1 typescript-v2-alpha-v2.0.0-alpha.1
```

## If a publish fails

- **Tag / version mismatch**: delete the tag locally
  (`git tag -d <tag>`) and on origin
  (`git push origin :refs/tags/<tag>`), land a follow-up PR that
  fixes the version in source, re-tag.
- **Tests fail after tag**: same procedure — fix on `main`, re-tag.
  Never skip the tests to force a publish.
- **Publish succeeds but artifact is broken**: bump the patch
  version and release again. Both PyPI and npm forbid republishing
  the same version number, and yanking / deprecating is a weaker
  signal than a clean patch release.

## Coordinated cross-language release

When `atlasent` and `@atlasent/sdk` ship together (e.g. a new
primitive added to both), push both tags in the same command so the
workflows run side-by-side:

```bash
git tag python-v1.2.0
git tag typescript-v1.2.0
git push origin python-v1.2.0 typescript-v1.2.0
```

Update `RELEASE_NOTES.md` at the repo root with the combined surface
before tagging.
