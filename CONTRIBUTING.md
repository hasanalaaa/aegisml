# Contributing to AegisML

AegisML accepts focused bug fixes, defensive format parsers, threat rules,
tests, and documentation improvements. Discuss large behavior or schema changes
in an issue before implementation.

## Core scanner setup

```bash
git clone https://github.com/hasanalaaa/aegisml.git
cd aegisml
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

The distribution name is `aegisml-scanner`, the Python package is
`aegisml_scanner`, and the executable is `aegisml`. The unrelated PyPI package
named `aegisml` must never be installed by project tooling or examples.

Run the dependency-light checks first:

```bash
python -m pytest -q \
  tests/test_cli.py \
  tests/test_local_scanner.py \
  tests/test_release_security.py
python -m build
aegisml doctor
```

## Backend and web checks

The FastAPI service has a separate dependency set:

```bash
python -m pip install -r services/scan-engine/requirements.txt
python -m pytest -q
```

For the web application:

```bash
cd apps/web
pnpm install
pnpm test
pnpm lint
pnpm typecheck
pnpm audit --prod --audit-level=high
pnpm build
```

Run the full applicable test suite before requesting review. If a check cannot
run in your environment, record that fact in the pull request instead of
describing it as passed.

## Adding a threat rule

Local deterministic rules live in `aegisml_scanner/scanner.py`. Format-aware
logic lives in `aegisml_scanner/formats.py`.

A new rule should include a stable ID, severity, CVSS score, narrow evidence,
plain-language description, remediation, and regression tests. Avoid generic
words such as `exec` or `socket` without serialization or byte context: tensor
data can contain ordinary text, and broad matches create false confidence and
alert fatigue.

Format parsers must treat lengths, counts, offsets, and decompressed content as
attacker-controlled. They must not import model code, deserialize Pickle, or
extract archives. Any resource cap must be exposed as incomplete coverage.

## Pull requests

1. Create a focused branch and keep unrelated changes out of the diff.
2. Add or update tests for observable behavior.
3. Preserve stable JSON fields, rule IDs, exit codes, and coverage semantics, or
   document an intentional breaking change.
4. Update user-facing documentation when commands or guarantees change.
5. Include the exact verification commands and results in the pull request.

Use conventional commit prefixes when practical (`feat:`, `fix:`, `docs:`,
`test:`, `chore:`). Never commit models, credentials, private reports, generated
databases, or vulnerability proof-of-concept payloads containing live secrets.
