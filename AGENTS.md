# AGENTS.md - Infra Export Kit

Guidelines for AI agents working on this codebase.

## Project Overview

Python CLI tool that exports Azure resource groups to best-practices Terraform code. Wraps Microsoft's `aztfexport` and applies transformations for production-ready output.

## Build/Lint/Test Commands

```bash
# Install dependencies with uv
uv sync --dev

# Run all checks
make check

# Individual commands
make lint          # Run ruff linter
make lint-fix      # Auto-fix lint issues
make format        # Format with ruff
make type-check    # Run mypy

# Tests
make test          # Run all tests
make test-fast     # Stop on first failure
make test-cov      # With coverage report

# Run single test
make test-single TEST=tests/test_transformer.py::TestTerraformTransformer::test_transform_empty_state
# Or directly:
uv run pytest tests/test_transformer.py::TestTerraformTransformer::test_transform_empty_state -v
uv run pytest tests/test_models.py -v -k "test_category"
```

## Project Structure

```
src/infra_export_kit/
├── __init__.py
├── cli.py           # Typer CLI entry point
├── exporter.py      # Main orchestrator
├── aztfexport.py    # aztfexport CLI wrapper
├── parser.py        # HCL2 parser for .tf files
├── transformer.py   # Best practices transformation
├── writer.py        # Terraform file writer
├── models.py        # Pydantic/dataclass models
└── version.py       # Version string
tests/
├── test_models.py
├── test_transformer.py
└── ...
```

## Code Style Guidelines

### Imports

Order (enforced by ruff isort):
1. Standard library
2. Third-party packages
3. Local imports

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from infra_export_kit.models import ExportConfig
```

### Type Hints

- **Required** on all function signatures
- Use `from __future__ import annotations` for forward references
- Use `|` for unions: `str | None` not `Optional[str]`
- Use lowercase generics: `list[str]` not `List[str]`

```python
def process_resources(
    resources: list[TerraformResource],
    config: ExportConfig | None = None,
) -> dict[str, Any]:
    ...
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Classes | PascalCase | `TerraformTransformer` |
| Functions/methods | snake_case | `parse_directory` |
| Constants | UPPER_SNAKE | `SENSITIVE_PATTERNS` |
| Private | Leading underscore | `_extract_variables` |
| Type aliases | PascalCase | `ResourceMap = dict[str, TerraformResource]` |

### Error Handling

- Define custom exceptions in the module where they're raised
- Inherit from `Exception` for domain errors
- Include context in error messages

```python
class AztfExportError(Exception):
    pass

def export_resource_group(self, rg: str) -> Path:
    try:
        result = subprocess.run(cmd, ...)
        if result.returncode != 0:
            raise AztfExportError(f"aztfexport failed for {rg}: {result.stderr}")
    except subprocess.TimeoutExpired as e:
        raise AztfExportError(f"aztfexport timed out for {rg}") from e
```

### Dataclasses

Use `@dataclass` for data containers. Use `field(default_factory=...)` for mutable defaults:

```python
@dataclass
class TerraformState:
    resources: list[TerraformResource] = field(default_factory=list)
    variables: list[TerraformVariable] = field(default_factory=list)
```

### String Formatting

- Use f-strings for interpolation
- Use triple quotes for multi-line HCL templates
- Escape braces in HCL: `{{` and `}}`

```python
content = f'''resource "{resource.resource_type}" "{resource.name}" {{
  name     = "{attrs.get('name')}"
  location = var.location
}}
'''
```

## Testing Patterns

### Test Structure

```python
class TestTerraformTransformer:
    def test_transform_empty_state(self, transformer: TerraformTransformer) -> None:
        state = TerraformState()
        result = transformer.transform(state)
        assert result.state.resources == []
```

### Fixtures

Define reusable fixtures in `conftest.py` or test files:

```python
@pytest.fixture
def config() -> ExportConfig:
    return ExportConfig(
        resource_groups=["test-rg"],
        output_dir=Path("/tmp/output"),
    )
```

### Test Naming

- `test_<method>_<scenario>` or `test_<behavior>`
- Be descriptive: `test_warns_on_sensitive_attributes`

### Test Data Policy

- Test fixtures and sample data must always be generic and domain-neutral.
- Do not use customer/company/product/person-specific names, IDs, emails, URLs, or secrets in tests.
- Prefer neutral placeholders such as `example-*`, `sample-*`, `test-*`, `resource-a`, and `service-endpoint-url`.

## Key Patterns

### CLI with Typer

```python
@app.command()
def export(
    resource_groups: Annotated[list[str], typer.Argument(help="...")],
    output_dir: Annotated[Path, typer.Option("--output", "-o")] = Path("./output"),
) -> None:
    ...
```

### External Process Execution

Always use subprocess with timeout and capture:

```python
result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=600,
)
if result.returncode != 0:
    raise AztfExportError(f"Command failed: {result.stderr}")
```

### Resource Categories

Resources are categorized by type in `models.py`:

```python
RESOURCE_TYPE_CATEGORIES: dict[str, ResourceCategory] = {
    "azurerm_virtual_network": ResourceCategory.NETWORK,
    "azurerm_storage_account": ResourceCategory.STORAGE,
    ...
}
```

## External Dependencies

### Required CLI Tools

- `aztfexport` - Microsoft's Azure Terraform Export tool
- `terraform` - HashiCorp Terraform

### Python Dependencies

- `typer` - CLI framework
- `rich` - Terminal formatting
- `python-hcl2` - HCL parser
- `pydantic` - Data validation (optional, using dataclasses)

## Common Tasks

### Adding a New Resource Category

1. Add enum value to `ResourceCategory` in `models.py`
2. Add resource type mappings to `RESOURCE_TYPE_CATEGORIES`

### Adding a New CLI Command

1. Add command function in `cli.py` with `@app.command()`
2. Use type annotations for all parameters

### Modifying Terraform Output

1. Update `TerraformWriter` methods in `writer.py`
2. Ensure HCL syntax is valid (test with `terraform fmt`)

## Debugging

```bash
# Verbose pytest output
uv run pytest tests -v --tb=long

# Run with print output
uv run pytest tests -v -s

# Debug specific test
uv run pytest tests/test_transformer.py::TestTerraformTransformer::test_transform_empty_state -v --pdb
```

## Pre-commit Hooks

```bash
# Install hooks
uv run pre-commit install

# Run manually
uv run pre-commit run --all-files
```

## Terraform Best Practices Applied

The transformer applies these patterns to exported code:

1. **Variable extraction** - Common values (location, resource_group_name) → variables
2. **File organization** - Resources grouped by category (network.tf, storage.tf)
3. **Naming normalization** - Consistent snake_case naming
4. **Output generation** - IDs of key resources exported
5. **Import blocks** - Terraform 1.5+ import blocks for state management
6. **Sensitive detection** - Warnings for hardcoded secrets
7. **Migrate support** - Convert flat aztfexport output into category modules

## Known Gotchas

### Migrate command

- `migrate` reads flat `aztfexport` output and rewrites imports for module paths.
- Category modules use `for_each` with per-type maps and typed variables.
- Secrets are managed resources; secret values will be stored in state if included.

### aztfexport CLI

- **Command structure**: Options MUST come before the resource group name:
  ```bash
  # Correct
  aztfexport resource-group -o /path -n --plain-ui "my-rg"
  
  # Wrong - causes "More than one resource groups specified" error
  aztfexport resource-group my-rg -o /path -n
  ```
- **Non-TTY environments**: Add `--plain-ui` flag or aztfexport fails with `/dev/tty` errors
- **Large provider downloads**: The azurerm provider is ~500MB; ensure sufficient disk space

### Avoid /tmp for Terraform Operations

`/tmp` is often tmpfs (RAM-based) with limited space. Terraform downloads providers there by default.

```python
# Set TMPDIR so Terraform uses disk, not tmpfs
env = os.environ.copy()
env["TMPDIR"] = str(output_dir)
subprocess.run(cmd, env=env, ...)
```

### python-hcl2 Parser Output Format

The hcl2 library returns resources as dicts, not lists. Handle both formats:

```python
# hcl2 returns: {'resource': [{'azurerm_rg': {'name': {...}}}]}
# NOT: {'resource': [{'azurerm_rg': [{'name': {...}}]}]}

for resource_type, instances in resource_block.items():
    if isinstance(instances, dict):
        for name, attrs in instances.items():
            # process directly
    elif isinstance(instances, list):
        for instance in instances:
            for name, attrs in instance.items():
                # process nested
```
