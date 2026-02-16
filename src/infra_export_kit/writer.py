from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from infra_export_kit.models import (
    ExportConfig,
    ImportBlock,
    TerraformOutput,
    TerraformProvider,
    TerraformResource,
    TerraformVariable,
)
from infra_export_kit.modules import GeneratedModule
from infra_export_kit.transformer import TransformResult


class TerraformWriter:
    def __init__(self, config: ExportConfig) -> None:
        self.config = config

    def write(self, result: TransformResult, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)

        self._write_versions(output_dir, result.state.providers)
        self._write_provider(output_dir)
        self._write_variables(output_dir, result.extracted_variables)
        self._write_tfvars_example(output_dir, result.extracted_variables)
        self._write_locals(output_dir)
        self._write_backend_template(output_dir)

        if result.modules:
            self._write_modules(output_dir, result.modules)
            self._write_module_calls(output_dir, result.modules)

        resources_to_write = (
            result.remaining_resources if result.modules else result.state.resources
        )

        if self.config.group_by_category and result.resources_by_category:
            for category, resources in result.resources_by_category.items():
                self._write_resources_file(output_dir, category.value, resources)
        elif resources_to_write:
            self._write_resources_file(output_dir, "main", resources_to_write)

        self._write_outputs(output_dir, result.generated_outputs)

        if self.config.include_import_block:
            if result.rewritten_imports:
                self._write_rewritten_imports(output_dir, result.rewritten_imports)
            else:
                self._write_import_blocks(output_dir, result.state.resources, result.modules)

    def _write_versions(self, output_dir: Path, _providers: list[TerraformProvider]) -> None:
        content = f'''terraform {{
  required_version = "{self.config.terraform_version}"

  required_providers {{
    azurerm = {{
      source  = "hashicorp/azurerm"
      version = "{self.config.azurerm_version}"
    }}
  }}
}}
'''
        (output_dir / "versions.tf").write_text(content)

    def _write_provider(self, output_dir: Path) -> None:
        content = """provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}
"""
        (output_dir / "provider.tf").write_text(content)

    def _write_variables(
        self,
        output_dir: Path,
        variables: list[TerraformVariable],
    ) -> None:
        if not variables:
            return

        lines: list[str] = []
        for var in variables:
            lines.append(f'variable "{var.name}" {{')
            if var.description:
                lines.append(f'  description = "{var.description}"')
            lines.append(f"  type        = {var.var_type}")
            if var.default is not None:
                default_str = self._format_value(var.default, allow_function_calls=False)
                lines.append(f"  default     = {default_str}")
            if var.sensitive:
                lines.append("  sensitive   = true")

            validation = self._get_variable_validation(var.name)
            if validation:
                lines.append("")
                lines.extend(validation)

            lines.append("}")
            lines.append("")

        (output_dir / "variables.tf").write_text("\n".join(lines))

    def _get_variable_validation(self, var_name: str) -> list[str] | None:
        validations: dict[str, list[str]] = {
            "environment": [
                "  validation {",
                '    condition     = contains(["dev", "staging", "prod"], var.environment)',
                '    error_message = "Environment must be dev, staging, or prod."',
                "  }",
            ],
            "location": [
                "  validation {",
                '    condition     = can(regex("^[a-z]+[a-z0-9]*$", var.location))',
                '    error_message = "Location must be a valid Azure region name."',
                "  }",
            ],
        }
        return validations.get(var_name)

    def _write_tfvars_example(
        self,
        output_dir: Path,
        variables: list[TerraformVariable],
    ) -> None:
        if not variables:
            return

        lines: list[str] = []
        for var in variables:
            if var.default is not None:
                default_str = self._format_value(var.default, allow_function_calls=False)
                lines.append(f"{var.name} = {default_str}")
            else:
                lines.append(f"# {var.name} = ")
            lines.append("")

        (output_dir / "terraform.tfvars.example").write_text("\n".join(lines))

    def _write_backend_template(self, output_dir: Path) -> None:
        content = """# Uncomment and configure for remote state storage
# terraform {
#   backend "azurerm" {
#     resource_group_name  = "tfstate-rg"
#     storage_account_name = "tfstate<unique>"
#     container_name       = "tfstate"
#     key                  = "terraform.tfstate"
#   }
# }
"""
        (output_dir / "backend.tf").write_text(content)

    def _write_locals(self, output_dir: Path) -> None:
        content = """locals {
  name_prefix = "app"

  common_tags = merge(var.common_tags, {
    Environment = var.environment
    ManagedBy   = "Terraform"
  })
}
"""
        (output_dir / "locals.tf").write_text(content)

    def _write_resources_file(
        self,
        output_dir: Path,
        filename: str,
        resources: list[TerraformResource],
    ) -> None:
        if not resources:
            return

        lines: list[str] = []
        for resource in resources:
            lines.extend(self._format_resource(resource))
            lines.append("")

        (output_dir / f"{filename}.tf").write_text("\n".join(lines))

    def _write_outputs(
        self,
        output_dir: Path,
        outputs: list[TerraformOutput],
    ) -> None:
        if not outputs:
            return

        lines: list[str] = []
        for output in outputs:
            lines.append(f'output "{output.name}" {{')
            if output.description:
                lines.append(f'  description = "{output.description}"')
            lines.append(f"  value       = {output.value}")
            if output.sensitive:
                lines.append("  sensitive   = true")
            lines.append("}")
            lines.append("")

        (output_dir / "outputs.tf").write_text("\n".join(lines))

    def _write_import_blocks(
        self,
        output_dir: Path,
        resources: list[TerraformResource],
        modules: list[GeneratedModule] | None = None,
    ) -> None:
        resource_to_module: dict[str, GeneratedModule] = {}
        for module in modules or []:
            for mod_resource in module.resources:
                resource_to_module[mod_resource.address] = module

        lines: list[str] = []
        for resource in resources:
            if resource.azure_resource_id:
                res_module = resource_to_module.get(resource.address)
                if res_module:
                    if res_module.is_category_module:
                        import_target = (
                            f"module.{res_module.name}.{resource.resource_type}."
                            f'this["{resource.name}"]'
                        )
                    else:
                        import_target = f"module.{res_module.name}.{resource.address}"
                else:
                    import_target = resource.address

                lines.append("import {")
                lines.append(f'  id = "{resource.azure_resource_id}"')
                lines.append(f"  to = {import_target}")
                lines.append("}")
                lines.append("")

        if lines:
            (output_dir / "imports.tf").write_text("\n".join(lines))

    def _write_rewritten_imports(
        self,
        output_dir: Path,
        import_blocks: list[ImportBlock],
    ) -> None:
        lines: list[str] = []
        for block in import_blocks:
            lines.append("import {")
            lines.append(f'  id = "{block.id}"')
            lines.append(f"  to = {block.to}")
            lines.append("}")
            lines.append("")

        if lines:
            (output_dir / "imports.tf").write_text("\n".join(lines))

    def _format_resource(self, resource: TerraformResource) -> list[str]:
        lines: list[str] = []
        lines.append(f'resource "{resource.resource_type}" "{resource.name}" {{')

        sorted_attrs = self._sort_attributes(resource.attributes)
        for key, value in sorted_attrs.items():
            formatted = self._format_attribute(key, value, indent=2)
            lines.extend(formatted)

        lifecycle_block = self._get_lifecycle_block(resource.resource_type)
        if lifecycle_block:
            lines.append("")
            lines.extend(lifecycle_block)

        lines.append("}")
        return lines

    def _get_lifecycle_block(self, resource_type: str) -> list[str] | None:
        if resource_type == "azurerm_key_vault_secret":
            return [
                "  lifecycle {",
                "    ignore_changes = [value, value_wo, value_wo_version]",
                "  }",
            ]

        prevent_destroy_types = {
            "azurerm_key_vault",
            "azurerm_storage_account",
            "azurerm_mssql_server",
            "azurerm_postgresql_server",
            "azurerm_postgresql_flexible_server",
            "azurerm_cosmosdb_account",
            "azurerm_redis_cache",
            "azurerm_kubernetes_cluster",
            "azurerm_log_analytics_workspace",
        }

        if resource_type in prevent_destroy_types:
            return [
                "  lifecycle {",
                "    prevent_destroy = true",
                "  }",
            ]
        return None

    def _sort_attributes(self, attrs: dict[str, Any]) -> dict[str, Any]:
        priority_order = [
            "name",
            "location",
            "resource_group_name",
            "sku",
            "sku_name",
        ]

        sorted_attrs: dict[str, Any] = {}

        for key in priority_order:
            if key in attrs:
                sorted_attrs[key] = attrs[key]

        for key, value in attrs.items():
            if key not in sorted_attrs:
                sorted_attrs[key] = value

        return sorted_attrs

    def _format_attribute(
        self,
        key: str,
        value: Any,
        indent: int = 0,
    ) -> list[str]:
        prefix = "  " * indent
        lines: list[str] = []

        if key == "depends_on" and isinstance(value, list):
            refs = [self._format_reference(item) for item in value]
            lines.append(f"{prefix}depends_on = [{', '.join(refs)}]")
        elif key == "tags" and isinstance(value, dict):
            formatted = self._format_value(value)
            lines.append(f"{prefix}{key} = {formatted}")
        elif isinstance(value, dict):
            if self._should_render_as_map_attribute(key, value):
                formatted = self._format_value(value)
                lines.append(f"{prefix}{key} = {formatted}")
            else:
                lines.append(f"{prefix}{key} {{")
                for k, v in value.items():
                    lines.extend(self._format_attribute(k, v, indent + 1))
                lines.append(f"{prefix}}}")
        elif isinstance(value, list):
            if all(isinstance(item, dict) for item in value):
                dynamic_lines = self._format_dynamic_list_block(key, value, indent)
                if dynamic_lines:
                    lines.extend(dynamic_lines)
                    return lines
                for item in value:
                    lines.append(f"{prefix}{key} {{")
                    for k, v in item.items():
                        lines.extend(self._format_attribute(k, v, indent + 1))
                    lines.append(f"{prefix}}}")
            else:
                collapsed = self._collapse_indexed_each_value_list(value)
                formatted = self._format_value(collapsed if collapsed is not None else value)
                lines.append(f"{prefix}{key} = {formatted}")
        else:
            formatted = self._format_value(value)
            lines.append(f"{prefix}{key} = {formatted}")

        return lines

    def _format_dynamic_list_block(
        self, key: str, value: list[Any], indent: int
    ) -> list[str] | None:
        if not value or not all(isinstance(item, dict) for item in value):
            return None

        merged_template: dict[str, Any] = {}
        for item in value:
            merged_template = self._merge_attribute_value(merged_template, item)

        rewritten_template = self._rewrite_dynamic_block_references(merged_template, key)
        if not self._has_dynamic_key_reference(rewritten_template, key):
            return None
        prefix = "  " * indent
        lines: list[str] = []
        lines.append(f'{prefix}dynamic "{key}" {{')
        lines.append(f"{prefix}  for_each = coalesce(try(each.value.{key}, null), [])")
        lines.append(f"{prefix}  content {{")
        for nested_key, nested_value in rewritten_template.items():
            lines.extend(self._format_attribute(nested_key, nested_value, indent + 2))
        lines.append(f"{prefix}  }}")
        lines.append(f"{prefix}}}")
        return lines

    def _rewrite_dynamic_block_references(self, value: Any, key: str) -> Any:
        if isinstance(value, dict):
            return {
                nested_key: self._rewrite_dynamic_block_references(nested_value, key)
                for nested_key, nested_value in value.items()
            }
        if isinstance(value, list):
            return [self._rewrite_dynamic_block_references(item, key) for item in value]
        if isinstance(value, str):
            updated = value
            direct_pattern = rf"each\.value\.{re.escape(key)}\[\d+\]"
            updated = re.sub(direct_pattern, f"{key}.value", updated)
            nested_pattern = (
                rf"[A-Za-z_][A-Za-z0-9_]*\.value(?:\.[A-Za-z0-9_]+|\[[0-9]+\])*"
                rf"\.{re.escape(key)}\[\d+\]"
            )
            updated = re.sub(nested_pattern, f"{key}.value", updated)
            return updated
        return value

    def _has_dynamic_key_reference(self, value: Any, key: str) -> bool:
        if isinstance(value, dict):
            return any(self._has_dynamic_key_reference(v, key) for v in value.values())
        if isinstance(value, list):
            return any(self._has_dynamic_key_reference(v, key) for v in value)
        if isinstance(value, str):
            return f"{key}.value" in value
        return False

    def _format_reference(self, value: str) -> str:
        if self._is_terraform_reference(value):
            return value
        return f'"{value}"'

    def _format_value(self, value: Any, allow_function_calls: bool = True) -> str:
        if value is None:
            return "null"
        elif isinstance(value, bool):
            return "true" if value else "false"
        elif isinstance(value, str):
            if (
                not allow_function_calls
                and value.startswith(("jsonencode(", "yamlencode(", "tomap(", "tolist(", "toset("))
            ):
                if value.startswith("jsonencode(") and value.endswith(")"):
                    inner = value[len("jsonencode(") : -1]
                    escaped_inner = inner.replace("\\", "\\\\").replace('"', '\\"')
                    return f'"{escaped_inner}"'
                escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                return f'"{escaped}"'
            if self._is_terraform_reference(value):
                return value
            if "\n" in value:
                return f"<<-EOT\n{value}\nEOT"
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, list):
            items = [
                self._format_value(item, allow_function_calls=allow_function_calls) for item in value
            ]
            return f"[{', '.join(items)}]"
        elif isinstance(value, dict):
            items = [
                (
                    f"{self._format_hcl_key(k)} = "
                    f"{self._format_value(v, allow_function_calls=allow_function_calls)}"
                )
                for k, v in value.items()
            ]
            return "{\n    " + "\n    ".join(items) + "\n  }"
        else:
            return json.dumps(value)

    def _should_render_as_map_attribute(self, key: str, value: dict[str, Any]) -> bool:
        if not value:
            return False

        known_map_attribute_keys = {
            "app_settings",
            "parameters",
            "workflow_parameters",
            "header",
            "parameter_values",
        }
        if key in known_map_attribute_keys:
            return True
        if key.endswith("_settings"):
            return True

        return any(not self._is_valid_identifier(str(k)) for k in value)

    def _is_valid_identifier(self, value: str) -> bool:
        return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value))

    def _format_hcl_key(self, key: str) -> str:
        if self._is_valid_identifier(key):
            return key
        escaped = key.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def _is_terraform_reference(self, value: str) -> bool:
        if value.startswith(("var.", "local.", "module.", "each.", "try(", "coalesce(")):
            return True
        if value.startswith(("jsonencode(", "yamlencode(", "tomap(", "tolist(", "toset(")):
            return True
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\.value(\.[A-Za-z0-9_]+|\[[^\]]+\])*$", value):
            return True
        tf_resource_pattern = r"^azurerm_[a-z_]+\.[a-z0-9_-]+(\[[^\]]+\])?(\.[a-z_]+)*$"
        return bool(re.match(tf_resource_pattern, value))

    def _write_modules(self, output_dir: Path, modules: list[GeneratedModule]) -> None:
        modules_dir = output_dir / "modules"
        modules_dir.mkdir(parents=True, exist_ok=True)

        for module in modules:
            module_dir = modules_dir / module.name
            module_dir.mkdir(parents=True, exist_ok=True)

            self._write_module_main(module_dir, module)
            self._write_module_variables(module_dir, module)
            self._write_module_outputs(module_dir, module)

    def _write_module_main(self, module_dir: Path, module: GeneratedModule) -> None:
        lines: list[str] = []
        self._write_category_module_main(lines, module)
        (module_dir / "main.tf").write_text("\n".join(lines))

    def _write_category_module_main(self, lines: list[str], module: GeneratedModule) -> None:
        resources_by_type: dict[str, list[TerraformResource]] = defaultdict(list)
        for resource in module.resources:
            resources_by_type[resource.resource_type].append(resource)
        default_maps = {
            var.name: var.default for var in module.variables if var.default is not None
        }

        for resource_type, resources in resources_by_type.items():
            map_name = module.resource_type_vars.get(resource_type)
            if not map_name:
                continue
            default_var_name = f"{map_name}_defaults"
            default_map = default_maps.get(default_var_name)

            lines.append(f'resource "{resource_type}" "this" {{')
            lines.append(f"  for_each = var.{map_name}")
            lines.append("")

            merged_attrs: dict[str, Any] = {}
            for resource in resources:
                merged_attrs = self._merge_attribute_templates(merged_attrs, resource.attributes)
            merged_attrs = self._inject_resource_required_fallbacks(
                resource_type,
                merged_attrs,
                default_var_name=default_var_name,
            )

            sorted_attrs = self._sort_attributes(merged_attrs)
            for key, value in sorted_attrs.items():
                if key == "location":
                    lines.append("  location = var.location")
                elif key == "resource_group_name":
                    lines.append("  resource_group_name = var.resource_group_name")
                elif key == "tags":
                    if resource_type == "azurerm_key_vault_secret":
                        replaced = self._replace_for_each_references(
                            value,
                            map_name,
                            default_var_name=default_var_name,
                            default_map=default_map,
                        )
                        formatted = self._format_attribute(key, replaced, indent=1)
                        lines.extend(formatted)
                    else:
                        lines.append("  tags = var.tags")
                elif key == "depends_on":
                    continue
                else:
                    replaced = self._replace_for_each_references(
                        value,
                        map_name,
                        default_var_name=default_var_name,
                        default_map=default_map,
                    )
                    formatted = self._format_attribute(key, replaced, indent=1)
                    lines.extend(formatted)

            lifecycle_block = self._get_lifecycle_block(resource_type)
            if lifecycle_block:
                lines.append("")
                lines.extend(lifecycle_block)

            lines.append("}")
            lines.append("")

    def _inject_resource_required_fallbacks(
        self,
        resource_type: str,
        merged_attrs: dict[str, Any],
        default_var_name: str | None = None,
    ) -> dict[str, Any]:
        patched = dict(merged_attrs)
        if resource_type == "azurerm_api_management_api":
            if "display_name" not in patched:
                patched["display_name"] = (
                    "try(each.value.source_api_id, null) == null ? "
                    "coalesce(try(each.value.display_name, null), each.value.name) : "
                    "try(each.value.display_name, null)"
                )
            if "protocols" not in patched:
                patched["protocols"] = (
                    "try(each.value.source_api_id, null) == null ? "
                    "coalesce(try(each.value.protocols, null), [\"https\"]) : "
                    "try(each.value.protocols, null)"
                )
        if resource_type == "azurerm_monitor_smart_detector_alert_rule":
            default_ids = "[]"
            if default_var_name:
                default_ids = f"try(var.{default_var_name}.action_group[0].ids, null)"
            patched["action_group"] = {
                "ids": (
                    "coalesce("
                    "try(each.value.action_group[0].ids, null), "
                    f"{default_ids}, "
                    "[])"
                )
            }
        if resource_type == "azurerm_logic_app_action_custom":
            patched["body"] = 'coalesce(try(each.value.body, null), jsonencode({}))'
        return patched

    def _write_module_variables(self, module_dir: Path, module: GeneratedModule) -> None:
        lines: list[str] = []

        for var in module.variables:
            lines.append(f'variable "{var.name}" {{')
            if var.description:
                lines.append(f'  description = "{var.description}"')
            lines.append(f"  type        = {var.var_type}")
            if var.default is not None:
                default_str = self._format_value(var.default, allow_function_calls=False)
                lines.append(f"  default     = {default_str}")
            lines.append("}")
            lines.append("")

        (module_dir / "variables.tf").write_text("\n".join(lines))

    def _write_module_outputs(self, module_dir: Path, module: GeneratedModule) -> None:
        if not module.outputs:
            return

        lines: list[str] = []
        for output in module.outputs:
            lines.append(f'output "{output.name}" {{')
            if output.description:
                lines.append(f'  description = "{output.description}"')
            lines.append(f"  value       = {output.value}")
            if output.sensitive:
                lines.append("  sensitive   = true")
            lines.append("}")
            lines.append("")

        (module_dir / "outputs.tf").write_text("\n".join(lines))

    def _write_module_calls(self, output_dir: Path, modules: list[GeneratedModule]) -> None:
        lines: list[str] = []

        for module in modules:
            var_names = {v.name for v in module.variables}
            call_params = module.call_params
            lines.append(f'module "{module.name}" {{')
            lines.append(f'  source = "{module.source_path}"')
            lines.append("")
            if "location" in var_names:
                if "location" in call_params:
                    loc_val = self._format_value(call_params["location"])
                    lines.append(f"  location            = {loc_val}")
                else:
                    lines.append("  location            = var.location")
            if "resource_group_name" in var_names:
                if "resource_group_name" in call_params:
                    rg_val = self._format_value(call_params["resource_group_name"])
                    lines.append(f"  resource_group_name = {rg_val}")
                else:
                    lines.append("  resource_group_name = var.resource_group_name")
            if "tags" in var_names:
                lines.append("  tags                = local.common_tags")
            for key, value in call_params.items():
                if key in {"location", "resource_group_name", "tags"}:
                    continue
                if key not in var_names:
                    continue
                param_lines = self._format_module_param(key, value)
                lines.extend(param_lines)
            lines.append("}")
            lines.append("")

        (output_dir / "modules.tf").write_text("\n".join(lines))

    def _format_module_param(self, key: str, value: Any, indent: int = 1) -> list[str]:
        prefix = "  " * indent
        lines: list[str] = []

        if isinstance(value, dict) and value:
            first_val = next(iter(value.values()), None)
            if isinstance(first_val, dict):
                lines.append(f"{prefix}{key} = {{")
                for k, v in value.items():
                    formatted_val = self._format_value(v)
                    lines.append(f'{prefix}  "{k}" = {formatted_val}')
                lines.append(f"{prefix}}}")
            else:
                formatted = self._format_value(value)
                lines.append(f"{prefix}{key} = {formatted}")
        else:
            formatted = self._format_value(value)
            lines.append(f"{prefix}{key} = {formatted}")

        return lines

    def _merge_attribute_templates(
        self, base: dict[str, Any], incoming: dict[str, Any]
    ) -> dict[str, Any]:
        merged = dict(base)
        for key, value in incoming.items():
            if key not in merged:
                merged[key] = value
                continue
            merged[key] = self._merge_attribute_value(merged[key], value)
        return merged

    def _merge_attribute_value(self, base: Any, incoming: Any) -> Any:
        if base is None:
            return incoming
        if incoming is None:
            return base
        if isinstance(base, dict) and isinstance(incoming, dict):
            merged = dict(base)
            for key, value in incoming.items():
                if key not in merged:
                    merged[key] = value
                else:
                    merged[key] = self._merge_attribute_value(merged[key], value)
            return merged
        if isinstance(base, list) and isinstance(incoming, list):
            length = max(len(base), len(incoming))
            merged_list: list[Any] = []
            for index in range(length):
                left = base[index] if index < len(base) else None
                right = incoming[index] if index < len(incoming) else None
                merged_list.append(self._merge_attribute_value(left, right))
            return merged_list
        return base

    def _replace_for_each_references(
        self,
        value: Any,
        map_name: str,
        default_var_name: str | None = None,
        default_map: Any | None = None,
    ) -> Any:
        if isinstance(value, dict):
            return {
                k: self._replace_for_each_references(
                    v,
                    map_name,
                    default_var_name=default_var_name,
                    default_map=default_map,
                )
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [
                self._replace_for_each_references(
                    v,
                    map_name,
                    default_var_name=default_var_name,
                    default_map=default_map,
                )
                for v in value
            ]
        if isinstance(value, str):
            pattern = rf'^var\.{re.escape(map_name)}\["[^"]+"\](.*)$'
            match = re.match(pattern, value)
            if match:
                suffix = match.group(1)
                ref = f"each.value{suffix}"
                if default_map is None or default_var_name is None:
                    if self._requires_safe_attribute_access(suffix):
                        return f"try({ref}, null)"
                    return ref
                path = self._parse_reference_suffix(suffix)
                if self._path_has_default(default_map, path):
                    default_ref = f"var.{default_var_name}{suffix}"
                    safe_ref = f"try({ref}, null)"
                    return f"{safe_ref} != null ? {safe_ref} : {default_ref}"
                if self._requires_safe_attribute_access(suffix):
                    return f"try({ref}, null)"
                return ref
            embedded_pattern = rf'var\.{re.escape(map_name)}\["[^"]+"\]((?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])*)'
            replaced = re.sub(embedded_pattern, lambda m: f"each.value{m.group(1)}", value)
            return self._wrap_nullable_each_index_reference(replaced)
        return value

    def _wrap_nullable_each_index_reference(self, value: str) -> str:
        if " ? " in value and " : " in value:
            return value
        match = re.match(
            r"^(azurerm_[a-z_]+\.this\[)(each\.value(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])+)(\]\..+)$",
            value,
        )
        if not match:
            return value
        _, index_ref, _ = match.groups()
        return f"try({index_ref}, null) != null ? {value} : null"

    def _requires_safe_attribute_access(self, suffix: str) -> bool:
        path = self._parse_reference_suffix(suffix)
        if len(path) <= 1:
            return False
        return True

    def _collapse_indexed_each_value_list(self, value: list[Any]) -> str | None:
        if not value or not all(isinstance(item, str) for item in value):
            return None

        pattern = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\.value(.+)\[(\d+)\]$")
        heads: list[str] = []
        bases: list[str] = []
        indexes: list[int] = []
        for item in value:
            match = pattern.match(item)
            if not match:
                return None
            head, base, index = match.groups()
            heads.append(head)
            bases.append(base)
            indexes.append(int(index))

        first_head = heads[0]
        if any(head != first_head for head in heads):
            return None

        first_base = bases[0]
        if any(base != first_base for base in bases):
            return None

        expected = list(range(len(indexes)))
        if sorted(indexes) != expected:
            return None

        return f"{first_head}.value{first_base}"

    def _parse_reference_suffix(self, suffix: str) -> list[str | int]:
        if not suffix:
            return []

        path: list[str | int] = []
        index = 0
        while index < len(suffix):
            char = suffix[index]
            if char == ".":
                index += 1
                start = index
                while index < len(suffix) and suffix[index] not in ".[":
                    index += 1
                if start < index:
                    path.append(suffix[start:index])
            elif char == "[":
                index += 1
                if index < len(suffix) and suffix[index] == '"':
                    index += 1
                    start = index
                    while index < len(suffix) and suffix[index] != '"':
                        index += 1
                    key = suffix[start:index]
                    if index < len(suffix) and suffix[index] == '"':
                        index += 1
                    if index < len(suffix) and suffix[index] == "]":
                        index += 1
                    path.append(key)
                else:
                    start = index
                    while index < len(suffix) and suffix[index] != "]":
                        index += 1
                    token = suffix[start:index]
                    if index < len(suffix) and suffix[index] == "]":
                        index += 1
                    if token.isdigit():
                        path.append(int(token))
                    else:
                        path.append(token)
            else:
                index += 1
        return path

    def _path_has_default(self, default_map: Any, path: list[str | int]) -> bool:
        current = default_map
        for part in path:
            if isinstance(part, int):
                if not isinstance(current, list) or part >= len(current):
                    return False
                current = current[part]
            else:
                if not isinstance(current, dict) or part not in current:
                    return False
                current = current[part]
        return current is not None
