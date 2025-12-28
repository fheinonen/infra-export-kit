from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import hcl2

from infra_export_kit.models import (
    ImportBlock,
    TerraformOutput,
    TerraformProvider,
    TerraformResource,
    TerraformState,
    TerraformVariable,
)


class TerraformParseError(Exception):
    pass


class TerraformParser:
    AZURE_RESOURCE_ID_PATTERN = re.compile(
        r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/[^/]+/[^/]+"
    )

    def parse_directory(self, directory: Path) -> TerraformState:
        state = TerraformState()

        tf_files = list(directory.glob("*.tf"))
        if not tf_files:
            raise TerraformParseError(f"No .tf files found in {directory}")

        for tf_file in tf_files:
            self._parse_file(tf_file, state)

        return state

    def _parse_file(self, file_path: Path, state: TerraformState) -> None:
        try:
            with file_path.open(encoding="utf-8") as f:
                content = hcl2.load(f)  # type: ignore[attr-defined]
        except Exception as e:
            raise TerraformParseError(f"Failed to parse {file_path}: {e}") from e

        self._extract_resources(content, state)
        self._extract_variables(content, state)
        self._extract_outputs(content, state)
        self._extract_providers(content, state)
        self._extract_imports(content, state)

    def _extract_resources(self, content: dict[str, Any], state: TerraformState) -> None:
        resources = content.get("resource", [])
        for resource_block in resources:
            for resource_type, instances in resource_block.items():
                if isinstance(instances, dict):
                    for name, attrs in instances.items():
                        azure_id = self._extract_azure_resource_id(attrs)
                        resource = TerraformResource(
                            resource_type=resource_type,
                            name=name,
                            attributes=attrs,
                            azure_resource_id=azure_id,
                        )
                        state.resources.append(resource)
                elif isinstance(instances, list):
                    for instance in instances:
                        for name, attrs in instance.items():
                            azure_id = self._extract_azure_resource_id(attrs)
                            resource = TerraformResource(
                                resource_type=resource_type,
                                name=name,
                                attributes=attrs,
                                azure_resource_id=azure_id,
                            )
                            state.resources.append(resource)

    def _extract_variables(self, content: dict[str, Any], state: TerraformState) -> None:
        variables = content.get("variable", [])
        for var_block in variables:
            for var_name, var_config in var_block.items():
                var = TerraformVariable(
                    name=var_name,
                    var_type=var_config.get("type", "string"),
                    default=var_config.get("default"),
                    description=var_config.get("description", ""),
                    sensitive=var_config.get("sensitive", False),
                )
                state.variables.append(var)

    def _extract_outputs(self, content: dict[str, Any], state: TerraformState) -> None:
        outputs = content.get("output", [])
        for output_block in outputs:
            for output_name, output_config in output_block.items():
                output = TerraformOutput(
                    name=output_name,
                    value=str(output_config.get("value", "")),
                    description=output_config.get("description", ""),
                    sensitive=output_config.get("sensitive", False),
                )
                state.outputs.append(output)

    def _extract_providers(self, content: dict[str, Any], state: TerraformState) -> None:
        providers = content.get("provider", [])
        for provider_block in providers:
            for provider_name, provider_config in provider_block.items():
                provider = TerraformProvider(
                    name=provider_name,
                    configuration=provider_config,
                )
                state.providers.append(provider)

        terraform_blocks = content.get("terraform", [])
        for tf_block in terraform_blocks:
            required_providers = tf_block.get("required_providers", [])
            for req_block in required_providers:
                for provider_name, provider_config in req_block.items():
                    existing = next(
                        (p for p in state.providers if p.name == provider_name),
                        None,
                    )
                    if existing:
                        existing.version = provider_config.get("version")
                    else:
                        provider = TerraformProvider(
                            name=provider_name,
                            version=provider_config.get("version"),
                        )
                        state.providers.append(provider)

    def _extract_imports(self, content: dict[str, Any], state: TerraformState) -> None:
        imports = content.get("import", [])
        for import_block in imports:
            import_id = import_block.get("id", "")
            import_to = import_block.get("to", "")
            if import_id and import_to:
                state.import_blocks.append(ImportBlock(id=import_id, to=import_to))

    def _extract_azure_resource_id(self, attrs: dict[str, Any]) -> str | None:
        if "id" in attrs:
            id_val = attrs["id"]
            if isinstance(id_val, str) and self.AZURE_RESOURCE_ID_PATTERN.match(id_val):
                return id_val

        for value in attrs.values():
            if isinstance(value, str) and self.AZURE_RESOURCE_ID_PATTERN.match(value):
                return value

        return None

    def merge_states(self, states: list[TerraformState]) -> TerraformState:
        merged = TerraformState()

        seen_resources: set[str] = set()
        seen_variables: set[str] = set()
        seen_outputs: set[str] = set()
        seen_providers: set[str] = set()
        seen_imports: set[str] = set()

        for state in states:
            for resource in state.resources:
                key = resource.address
                if key not in seen_resources:
                    seen_resources.add(key)
                    merged.resources.append(resource)

            for var in state.variables:
                if var.name not in seen_variables:
                    seen_variables.add(var.name)
                    merged.variables.append(var)

            for output in state.outputs:
                if output.name not in seen_outputs:
                    seen_outputs.add(output.name)
                    merged.outputs.append(output)

            for provider in state.providers:
                if provider.name not in seen_providers:
                    seen_providers.add(provider.name)
                    merged.providers.append(provider)

            for import_block in state.import_blocks:
                key = f"{import_block.id}:{import_block.to}"
                if key not in seen_imports:
                    seen_imports.add(key)
                    merged.import_blocks.append(import_block)

        return merged
