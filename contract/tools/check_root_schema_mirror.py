#!/usr/bin/env python3
"""Cross-repo schema-mirror check for the approval surface.

The wire schemas are published in two places:

  atlasent-sdk/contract/schemas/<name>.schema.json   (canonical)
  atlasent/schemas/v1_1/<name>.schema.json           (mirror)

Producers (signing services) and verifiers (Deno edge functions in
atlasent-console / atlasent-api) read the same shape. Drift between
the two files is silent — both repos still build, but a producer
written against one schema and a verifier written against the other
will disagree on what fields are required.

This script asserts that the *normative* slice of every paired file
is identical: top-level $id is allowed to differ (different host
namespaces), description / $comment are documentation, but
everything else (type, required, properties, additionalProperties,
enum, const, pattern, length bounds, format, items) IS normative
and must agree byte-for-byte after canonical JSON normalization.

Usage:
  python contract/tools/check_root_schema_mirror.py \\
      --root /path/to/atlasent

Exits 0 on parity, 1 on drift. Designed for cross-repo CI: the
atlasent-sdk repo cannot import files from the atlasent repo at
import time, so we take the path explicitly.

The atlasent-sdk-side tests (typescript/test/approval-artifact-vectors.test.ts)
cover schema-against-fixtures drift; this script covers schema-
against-schema drift across the published surface.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_SCHEMAS_DIR = REPO_ROOT / "contract" / "schemas"

# Schemas that MUST be mirrored in atlasent/schemas/v1_1/ with the
# same filename. Adding a new schema to the approval surface? Add
# the filename here and ship the mirror in the same release.
MIRRORED = (
    "approval-artifact.schema.json",
    "identity-assertion.schema.json",
    "approver-grant-assertion.schema.json",
    "entra-provenance.schema.json",
    "org-authority-assertion.schema.json",
    "approval-quorum.schema.json",
    "trusted-issuers-config.schema.json",
    "identity-trusted-issuers-config.schema.json",
)

# Fields that may legitimately differ between the two files.
#   $id          — different host namespaces (atlasent.io vs schemas.atlasent.io)
#   title        — atlasent root tags titles with " (v1.1)" for the v1.1 namespace
#   description  — wordsmithing across repos; not normative
#   $comment     — JSON Schema's documentation slot; not normative
NON_NORMATIVE_KEYS = {"$id", "title", "description", "$comment"}


def canonical_normative_slice(schema: dict) -> dict:
    """Strip non-normative keys + sort recursively for stable diff."""
    out: dict = {}
    for k, v in schema.items():
        if k in NON_NORMATIVE_KEYS:
            continue
        if isinstance(v, dict):
            out[k] = canonical_normative_slice(v)
        else:
            out[k] = v
    return out


def check_pair(sdk_path: Path, root_path: Path) -> bool:
    """Returns True when the pair has parity (or both files are absent)."""
    if not sdk_path.exists() and not root_path.exists():
        return True
    if not sdk_path.exists():
        print(f"ERROR: SDK schema missing: {sdk_path}", file=sys.stderr)
        return False
    if not root_path.exists():
        print(f"ERROR: root schema missing: {root_path}", file=sys.stderr)
        return False

    sdk = json.loads(sdk_path.read_text(encoding="utf-8"))
    root = json.loads(root_path.read_text(encoding="utf-8"))

    sdk_norm = canonical_normative_slice(sdk)
    root_norm = canonical_normative_slice(root)

    if sdk_norm != root_norm:
        rel = sdk_path.relative_to(REPO_ROOT)
        print(f"DRIFT: {rel}", file=sys.stderr)
        print(
            "  sdk:  " + json.dumps(sdk_norm, sort_keys=True, indent=2),
            file=sys.stderr,
        )
        print(
            "  root: " + json.dumps(root_norm, sort_keys=True, indent=2),
            file=sys.stderr,
        )
        return False

    print(f"OK: {sdk_path.relative_to(REPO_ROOT)} == {root_path}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        required=True,
        help="Path to a checkout of the atlasent (root) repo.",
    )
    args = parser.parse_args()
    root_dir = Path(args.root).resolve() / "schemas" / "v1_1"

    drift = False
    for name in MIRRORED:
        sdk_path = SDK_SCHEMAS_DIR / name
        root_path = root_dir / name
        if not check_pair(sdk_path, root_path):
            drift = True

    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
