# Python tooling for gigahorse-toolchain.
#
# ruff and ty are uv-managed dev dependencies (see [dependency-groups] in
# pyproject.toml), so everything runs through `uv run --frozen` — no manual venv
# activation required, and the exact locked tool versions are used. souffle-addon
# is excluded from ruff via [tool.ruff] extend-exclude (it's a native C++ submodule
# with its own Makefile for building the functors).
.PHONY: format lint typecheck check

# Auto-fix import ordering and apply the ruff formatter across the codebase.
format:
	uv run --frozen ruff check --select I --fix .
	uv run --frozen ruff format .

# Report lint + formatting issues without modifying files (mirrors CI).
lint:
	uv run --frozen ruff check .
	uv run --frozen ruff format --check .

# Static type checking with ty over the paths configured in [tool.ty.src].
# --error-on-warning matches CI: warn-level diagnostics fail too.
typecheck:
	uv run --frozen ty check --error-on-warning

# Full local gate: lint + format check + type check. Mirrors CI exactly.
check: lint typecheck
