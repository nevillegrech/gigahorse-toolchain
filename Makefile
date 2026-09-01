# Python tooling for gigahorse-toolchain.
#
# ruff and mypy are uv-managed dev dependencies (see [dependency-groups] in
# pyproject.toml), so everything runs through `uv run --frozen` — no manual venv
# activation required, and the exact locked tool versions are used. souffle-addon
# is excluded from ruff via [tool.ruff] extend-exclude (it's a native C++ submodule
# with its own Makefile for building the functors).
.PHONY: format lint typecheck ty check

# Auto-fix import ordering and apply the ruff formatter across the codebase.
format:
	uv run --frozen ruff check --select I --fix .
	uv run --frozen ruff format .

# Report lint + formatting issues without modifying files (mirrors CI).
lint:
	uv run --frozen ruff check .
	uv run --frozen ruff format --check .

# Static type checking over the paths configured in [tool.mypy].
typecheck:
	uv run --frozen mypy

# Astral's ty (preview) over the paths configured in [tool.ty.src]. Advisory only:
# it mirrors the continue-on-error CI job, so mypy stays the blocking type gate.
ty:
	uv run --frozen ty check

# Full local gate: lint + format check + type check. ty is prefixed with `-` so a
# preview-checker complaint reports but never fails the gate (as in CI).
check: lint typecheck
	-$(MAKE) ty
