from __future__ import annotations

from infra_export_kit.aztfexport import AztfExportError, AztfExportRunner
from infra_export_kit.models import ExportConfig, ExportResult
from infra_export_kit.parser import TerraformParseError, TerraformParser
from infra_export_kit.transformer import TerraformTransformer
from infra_export_kit.writer import TerraformWriter


class InfraExportKitExporter:
    def __init__(self, config: ExportConfig) -> None:
        self.config = config
        self.runner = AztfExportRunner()
        self.parser = TerraformParser()
        self.transformer = TerraformTransformer(config)
        self.writer = TerraformWriter(config)

    def run(self) -> ExportResult:
        errors: list[str] = []
        warnings: list[str] = []

        if not self.runner.check_aztfexport_installed():
            return ExportResult(
                success=False,
                output_path=self.config.output_dir,
                resources_exported=0,
                errors=["aztfexport is not installed. Run 'infra-export-kit validate' for help."],
            )

        if not self.runner.check_terraform_installed():
            return ExportResult(
                success=False,
                output_path=self.config.output_dir,
                resources_exported=0,
                errors=["terraform is not installed. Run 'infra-export-kit validate' for help."],
            )

        try:
            raw_exports = self.runner.export_resource_groups(self.config)
        except AztfExportError as e:
            return ExportResult(
                success=False,
                output_path=self.config.output_dir,
                resources_exported=0,
                errors=[str(e)],
            )

        states = []
        for rg_name, rg_path in raw_exports.items():
            try:
                state = self.parser.parse_directory(rg_path)
                states.append(state)
            except TerraformParseError as e:
                errors.append(f"Failed to parse {rg_name}: {e}")

        if not states:
            return ExportResult(
                success=False,
                output_path=self.config.output_dir,
                resources_exported=0,
                errors=errors or ["No resources found to export"],
            )

        merged_state = self.parser.merge_states(states)

        transform_result = self.transformer.transform(merged_state)
        warnings.extend(transform_result.warnings)

        output_path = self.config.output_dir / "terraform"
        self.writer.write(transform_result, output_path)

        return ExportResult(
            success=True,
            output_path=output_path,
            resources_exported=len(transform_result.state.resources),
            errors=errors,
            warnings=warnings,
        )

    def validate_prerequisites(self) -> list[str]:
        issues: list[str] = []

        if not self.runner.check_aztfexport_installed():
            issues.append("aztfexport is not installed")

        if not self.runner.check_terraform_installed():
            issues.append("terraform is not installed")

        return issues
