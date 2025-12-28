from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from infra_export_kit.exporter import InfraExportKitExporter
from infra_export_kit.models import ExportConfig
from infra_export_kit.parser import TerraformParser
from infra_export_kit.transformer import TerraformTransformer
from infra_export_kit.version import __version__
from infra_export_kit.writer import TerraformWriter

app = typer.Typer(
    name="infra-export-kit",
    help="Export infrastructure to best-practices Terraform code",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"infra-export-kit version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", "-v", callback=version_callback, is_eager=True),
    ] = False,
) -> None:
    pass


@app.command()
def export(
    resource_groups: Annotated[
        list[str],
        typer.Argument(help="Azure resource group names to export"),
    ],
    output_dir: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory for Terraform files"),
    ] = Path("./terraform-output"),
    subscription_id: Annotated[
        str | None,
        typer.Option("--subscription", "-s", help="Azure subscription ID"),
    ] = None,
    no_modules: Annotated[
        bool,
        typer.Option("--no-modules", help="Disable module generation"),
    ] = False,
    no_variables: Annotated[
        bool,
        typer.Option("--no-variables", help="Disable variable extraction"),
    ] = False,
    flat: Annotated[
        bool,
        typer.Option("--flat", help="Disable grouping by resource category"),
    ] = False,
    naming: Annotated[
        str,
        typer.Option("--naming", help="Naming convention: snake_case, kebab-case, camelCase"),
    ] = "snake_case",
    terraform_version: Annotated[
        str,
        typer.Option("--tf-version", help="Required Terraform version constraint"),
    ] = ">= 1.5.0",
    azurerm_version: Annotated[
        str,
        typer.Option("--azurerm-version", help="Required AzureRM provider version"),
    ] = ">= 3.0.0",
) -> None:
    """Export Azure resource groups to Terraform with best practices applied."""
    config = ExportConfig(
        resource_groups=resource_groups,
        output_dir=output_dir,
        subscription_id=subscription_id,
        use_modules=not no_modules,
        extract_variables=not no_variables,
        group_by_category=not flat,
        naming_convention=naming,
        terraform_version=terraform_version,
        azurerm_version=azurerm_version,
    )

    console.print(
        Panel(
            f"[bold blue]Infra Export Kit[/]\n"
            f"Resource Groups: {', '.join(resource_groups)}\n"
            f"Output: {output_dir}",
            title="Export Configuration",
        )
    )

    exporter = InfraExportKitExporter(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Exporting resources...", total=None)
        result = exporter.run()

    if result.success:
        console.print(f"\n[green]✓[/] Exported {result.resources_exported} resources")
        console.print(f"[green]✓[/] Output written to: {result.output_path}")

        if result.warnings:
            console.print("\n[yellow]Warnings:[/]")
            for warning in result.warnings:
                console.print(f"  • {warning}")
    else:
        console.print("\n[red]✗ Export failed[/]")
        for error in result.errors:
            console.print(f"  [red]•[/] {error}")
        sys.exit(1)


@app.command()
def validate() -> None:
    """Validate that required tools (aztfexport, terraform) are installed."""
    from infra_export_kit.aztfexport import AztfExportRunner

    runner = AztfExportRunner()
    issues: list[str] = []

    console.print("[bold]Checking prerequisites...[/]\n")

    if runner.check_aztfexport_installed():
        version = runner.get_aztfexport_version()
        console.print(f"[green]✓[/] aztfexport: {version or 'installed'}")
    else:
        issues.append("aztfexport not found")
        console.print("[red]✗[/] aztfexport: not found")
        console.print("  Install: https://github.com/Azure/aztfexport#installation")

    if runner.check_terraform_installed():
        version = runner.get_terraform_version()
        console.print(f"[green]✓[/] terraform: {version or 'installed'}")
    else:
        issues.append("terraform not found")
        console.print("[red]✗[/] terraform: not found")
        console.print("  Install: https://developer.hashicorp.com/terraform/install")

    if runner.check_azure_cli_installed():
        console.print("[green]✓[/] az cli: installed")
    else:
        console.print("[yellow]![/] az cli: not found (optional, for authentication)")

    if issues:
        console.print(f"\n[red]Found {len(issues)} issue(s)[/]")
        sys.exit(1)
    else:
        console.print("\n[green]All prerequisites satisfied![/]")


@app.command()
def migrate(
    input_dir: Annotated[
        Path,
        typer.Argument(help="Path to flat aztfexport output directory"),
    ],
    output_dir: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory for module-structured Terraform"),
    ] = Path("./terraform-modules"),
    terraform_version: Annotated[
        str,
        typer.Option("--tf-version", help="Required Terraform version constraint"),
    ] = ">= 1.5.0",
    azurerm_version: Annotated[
        str,
        typer.Option("--azurerm-version", help="Required AzureRM provider version"),
    ] = ">= 3.0.0",
) -> None:
    """Convert flat aztfexport output to module structure with rewritten imports."""
    if not input_dir.exists():
        console.print(f"[red]Error: Input directory does not exist: {input_dir}[/]")
        sys.exit(1)

    console.print(
        Panel(
            f"[bold blue]Migrate to Module Structure[/]\nInput: {input_dir}\nOutput: {output_dir}",
            title="Migration",
        )
    )

    parser = TerraformParser()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Parsing flat Terraform files...", total=None)

        try:
            state = parser.parse_directory(input_dir)
        except Exception as e:
            console.print(f"[red]Error parsing input: {e}[/]")
            sys.exit(1)

    config = ExportConfig(
        resource_groups=[],
        output_dir=output_dir,
        use_modules=True,
        extract_variables=True,
        group_by_category=True,
        include_import_block=True,
        terraform_version=terraform_version,
        azurerm_version=azurerm_version,
    )

    transformer = TerraformTransformer(config)
    result = transformer.transform(state)

    writer = TerraformWriter(config)
    writer.write(result, output_dir)

    console.print(f"\n[green]✓[/] Migrated {len(result.state.resources)} resources")
    console.print(f"[green]✓[/] Generated {len(result.modules)} modules")
    console.print(f"[green]✓[/] Rewrote {len(result.rewritten_imports)} import blocks")
    console.print(f"[green]✓[/] Output written to: {output_dir}")

    if result.warnings:
        console.print("\n[yellow]Warnings:[/]")
        for warning in result.warnings:
            console.print(f"  • {warning}")

    console.print("\n[bold]Next steps:[/]")
    console.print(f"  1. cd {output_dir}")
    console.print("  2. terraform init")
    console.print("  3. terraform plan")
    console.print("  4. terraform apply")


if __name__ == "__main__":
    app()
