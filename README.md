# Infra Export Kit

Export infrastructure to best-practices Terraform code.

## Features

- Export entire Azure resource groups to Terraform
- Apply best practices transformations:
  - Extract common variables (location, resource_group_name)
  - Organize resources by category (network.tf, storage.tf, etc.)
  - Generate outputs for key resources
  - Create Terraform 1.5+ import blocks
  - Detect and warn about sensitive attributes
- Migrate flat `aztfexport` output into category modules with rewritten imports

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [aztfexport](https://github.com/Azure/aztfexport) installed
- [Terraform](https://developer.hashicorp.com/terraform/install) installed
- Azure CLI authenticated (`az login`)

## Installation

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone <repo>
cd azure_tool
uv sync --dev
```

## Usage

### Export resource groups

```bash
uv run infra-export-kit export my-resource-group --output ./terraform
```

### Export multiple resource groups

```bash
uv run infra-export-kit export rg1 rg2 rg3 --output ./terraform
```

### Options

```bash
uv run infra-export-kit export --help

Options:
  -o, --output PATH           Output directory [default: ./terraform-output]
  -s, --subscription TEXT     Azure subscription ID
  --no-modules                Disable module generation
  --no-variables              Disable variable extraction
  --flat                      Don't group by resource category
  --naming TEXT               Naming: snake_case, kebab-case, camelCase
  --tf-version TEXT           Terraform version constraint
  --azurerm-version TEXT      AzureRM provider version
```

### Migrate flat aztfexport output

Use `export` when you want the tool to run `aztfexport` against live resource groups.
Use `migrate` when you already have flat Terraform and want it reorganized into modules with
import blocks rewritten to match the new module addresses.

```bash
uv run infra-export-kit migrate ./path/to/aztfexport --output ./terraform
```

```bash
uv run infra-export-kit migrate --help
```

### Validate prerequisites

```bash
uv run infra-export-kit validate
```

## Output Structure

```
terraform/
├── versions.tf      # Terraform and provider versions
├── provider.tf      # AzureRM provider config
├── variables.tf     # Extracted variables
├── locals.tf        # Local values and naming
├── modules.tf       # Module calls
├── modules/         # Category modules
│   ├── network/
│   ├── storage/
│   └── other/
├── outputs.tf       # Resource outputs
└── imports.tf       # Import blocks for state
```

When running with `--no-modules`, resources are grouped into category files
such as `network.tf` and `storage.tf`.

## Notes

- Key Vault secrets are imported as managed resources; their values will be stored in state if included in module inputs.
- If you want imports without managing secret values, consider adding `lifecycle { ignore_changes = [value] }` or using data sources.

## Development

```bash
uv sync --dev       # Install dependencies
make check          # Run lint, type-check, tests
make test           # Run tests only
make format         # Format code
```

## License

MIT
