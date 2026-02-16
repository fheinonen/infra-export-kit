from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from infra_export_kit.models import (
    ExportConfig,
    ImportBlock,
    ResourceCategory,
    TerraformOutput,
    TerraformResource,
    TerraformState,
    TerraformVariable,
)
from infra_export_kit.modules import GeneratedModule, ModuleGenerator

SENSITIVE_ATTRIBUTE_PATTERNS = [
    r"password",
    r"secret",
    r"key",
    r"token",
    r"connection_string",
    r"sas_token",
    r"access_key",
    r"private_key",
    r"api_key",
    r"credentials",
]

SECRET_VALUE_PATTERNS = [
    r"-----BEGIN.*PRIVATE KEY-----",
    r"-----BEGIN.*CERTIFICATE-----",
    r"^[A-Za-z0-9+/]{20,}={0,2}$",
]

DESCRIPTIVE_NAME_KEYS = [
    "name",
    "operation_id",
    "display_name",
    "api_name",
    "path",
    "url_template",
    "title",
]

NON_DESCRIPTIVE_NAME_KEYS = {
    "resource_group_name",
    "location",
    "api_management_name",
    "subscription_id",
    "tenant_id",
}

EXTRACTABLE_ATTRIBUTES = [
    "location",
    "resource_group_name",
    "sku",
    "sku_name",
    "tags",
    "environment",
]

DEPRECATED_ATTRIBUTE_RENAMES: dict[str, str] = {
    "enable_rbac_authorization": "rbac_authorization_enabled",
}

# Resources typically created/owned by Azure services and not safe to manage directly
# in generated IaC by default.
AZURE_MANAGED_RESOURCE_TYPES: set[str] = {
    "azurerm_log_analytics_workspace_table_custom_log",
}


@dataclass
class TransformResult:
    state: TerraformState
    resources_by_category: dict[ResourceCategory, list[TerraformResource]] = field(
        default_factory=dict
    )
    extracted_variables: list[TerraformVariable] = field(default_factory=list)
    generated_outputs: list[TerraformOutput] = field(default_factory=list)
    modules: list[GeneratedModule] = field(default_factory=list)
    remaining_resources: list[TerraformResource] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    address_mapping: dict[str, str] = field(default_factory=dict)
    rewritten_imports: list[ImportBlock] = field(default_factory=list)


class TerraformTransformer:
    def __init__(self, config: ExportConfig) -> None:
        self.config = config
        self._variable_counter: dict[str, int] = defaultdict(int)
        self._name_counter: dict[str, int] = {}
        self._name_mapping: dict[str, str] = {}
        self._azure_id_mapping: dict[str, str] = {}
        self._azure_id_candidates: dict[str, list[str]] = {}

    def transform(self, state: TerraformState) -> TransformResult:
        result = TransformResult(state=TerraformState())
        filtered_resources, filtered_imports = self._filter_excluded_resources(
            state.resources, state.import_blocks
        )

        result.state.providers = state.providers.copy()

        if self.config.extract_variables:
            result.extracted_variables = self._extract_common_variables(filtered_resources)
            result.state.variables = result.extracted_variables

        self._name_mapping = self._build_name_mapping(filtered_resources)
        self._azure_id_mapping = self._build_azure_id_mapping(filtered_resources, filtered_imports)

        for resource in filtered_resources:
            transformed = self._transform_resource(resource, result)
            if transformed is None:
                continue
            result.state.resources.append(transformed)

        if self.config.use_modules:
            module_generator = ModuleGenerator()
            result.modules = module_generator.generate_category_modules(result.state.resources)
            category_call_params = self._build_category_call_params(filtered_resources)
            for module in result.modules:
                if module.is_category_module:
                    params = category_call_params.get(module.name)
                    if params:
                        module.call_params = params
            self._hoist_category_string_values(result.modules)

            result.address_mapping = self._build_module_address_mapping(
                filtered_resources, result.modules
            )
            result.rewritten_imports = self._rewrite_import_blocks(
                filtered_imports, result.address_mapping
            )

            result.remaining_resources = []
        else:
            result.remaining_resources = result.state.resources

        if self.config.group_by_category and result.remaining_resources:
            result.resources_by_category = self._group_by_category(result.remaining_resources)

        if result.modules:
            result.generated_outputs = self._generate_module_root_outputs(result.modules)
        else:
            result.generated_outputs = self._generate_outputs(result.remaining_resources)
        result.state.outputs = result.generated_outputs

        return result

    def _filter_excluded_resources(
        self,
        resources: list[TerraformResource],
        import_blocks: list[ImportBlock],
    ) -> tuple[list[TerraformResource], list[ImportBlock]]:
        filtered_resources = [
            resource
            for resource in resources
            if resource.resource_type not in AZURE_MANAGED_RESOURCE_TYPES
        ]

        filtered_imports: list[ImportBlock] = []
        for block in import_blocks:
            resource_type = self._resource_type_from_import_to(block.to)
            if resource_type and resource_type in AZURE_MANAGED_RESOURCE_TYPES:
                continue
            filtered_imports.append(block)

        return filtered_resources, filtered_imports

    def _resource_type_from_import_to(self, to_value: str) -> str | None:
        raw = to_value
        if raw.startswith("${") and raw.endswith("}"):
            raw = raw[2:-1]
        match = re.match(r"^(azurerm_[a-z_]+)\.[A-Za-z0-9_-]+$", raw)
        if not match:
            return None
        return match.group(1)

    def _build_name_mapping(self, resources: list[TerraformResource]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        temp_counter: dict[str, int] = {}

        for resource in resources:
            old_address = resource.address
            new_name = self._compute_new_name(
                resource.name, resource.resource_type, resource.attributes, temp_counter
            )
            new_address = f"{resource.resource_type}.{new_name}"
            mapping[old_address] = new_address

        return mapping

    def _build_azure_id_mapping(
        self,
        resources: list[TerraformResource],
        import_blocks: list[ImportBlock],
    ) -> dict[str, str]:
        mapping: dict[str, str] = {}
        scores: dict[str, int] = {}
        candidates: dict[str, list[str]] = defaultdict(list)

        # Import blocks explicitly define ID ownership.
        for block in import_blocks:
            original_to = block.to
            if original_to.startswith("${") and original_to.endswith("}"):
                original_to = original_to[2:-1]
            target_address = self._name_mapping.get(original_to, original_to)
            normalized_id = self._normalize_azure_id(block.id)
            target_ref = f"{target_address}.id"
            if target_ref not in candidates[normalized_id]:
                candidates[normalized_id].append(target_ref)
            mapping[normalized_id] = target_ref
            scores[normalized_id] = 100

        for resource in resources:
            if not resource.azure_resource_id:
                continue
            normalized_id = self._normalize_azure_id(resource.azure_resource_id)
            address = self._name_mapping.get(resource.address, resource.address)
            candidate_ref = f"{address}.id"
            if candidate_ref not in candidates[normalized_id]:
                candidates[normalized_id].append(candidate_ref)
            score = self._resource_id_match_score(resource, normalized_id)
            previous = scores.get(normalized_id, -1)
            if score >= previous:
                scores[normalized_id] = score
                mapping[normalized_id] = candidate_ref
        self._azure_id_candidates = dict(candidates)
        return mapping

    def _compute_new_name(
        self, name: str, resource_type: str, attrs: dict[str, Any], counter: dict[str, int]
    ) -> str:
        match = re.match(r"^res-(\d+)$", name)
        if match:
            base_name = self._descriptive_name_from_attrs(attrs)
            if base_name:
                key = f"{resource_type}:{base_name}"
                counter[key] = counter.get(key, 0) + 1
                if counter[key] == 1:
                    return base_name
                return f"{base_name}_{counter[key]}"
            return self._generated_fallback_name(resource_type, match.group(1))
        return self._apply_naming_convention(name)

    def _transform_resource(
        self,
        resource: TerraformResource,
        result: TransformResult,
    ) -> TerraformResource | None:
        old_address = resource.address
        new_address = self._name_mapping.get(old_address, old_address)
        new_name = new_address.split(".", 1)[1] if "." in new_address else resource.name

        new_attrs = self._transform_attributes(resource.attributes, result)
        if resource.resource_type == "azurerm_key_vault_secret":
            original_tags = resource.attributes.get("tags")
            if isinstance(original_tags, dict):
                new_attrs["tags"] = original_tags
            else:
                new_attrs.pop("tags", None)
        new_attrs = self._sanitize_resource_attributes(resource.resource_type, new_attrs)
        if self._should_skip_resource(resource.resource_type, new_attrs):
            return None

        return TerraformResource(
            resource_type=resource.resource_type,
            name=new_name,
            attributes=new_attrs,
            azure_resource_id=resource.azure_resource_id,
        )

    def _sanitize_resource_attributes(
        self, resource_type: str, attrs: dict[str, Any]
    ) -> dict[str, Any]:
        if resource_type == "azurerm_key_vault_secret":
            keep = {
                "name",
                "key_vault_id",
                "value",
                "tags",
                "content_type",
                "not_before_date",
                "expiration_date",
            }
            sanitized = {key: value for key, value in attrs.items() if key in keep}
            # Provider requires one of value/value_wo even for imported secrets.
            # Keep real secret values out of generated code by forcing a placeholder.
            sanitized["value"] = "__import_only__"
            return sanitized
        if resource_type == "azurerm_api_management_backend":
            sanitized = dict(attrs)
            tls_value = sanitized.get("tls")
            if self._is_empty_value(tls_value):
                sanitized.pop("tls", None)
            return sanitized
        if resource_type == "azurerm_api_management_named_value":
            sanitized = dict(attrs)
            if "value" not in sanitized and "value_from_key_vault" not in sanitized:
                # Provider schema requires one of value/value_from_key_vault.
                sanitized["value"] = "__import_only__"
            return sanitized
        if resource_type == "azurerm_api_management_logger":
            sanitized = dict(attrs)
            eventhub = sanitized.get("eventhub")
            if isinstance(eventhub, list):
                valid_eventhub_blocks: list[dict[str, Any]] = []
                for block in eventhub:
                    if not isinstance(block, dict):
                        continue
                    has_connection_string = isinstance(block.get("connection_string"), str) and bool(
                        block.get("connection_string")
                    )
                    has_endpoint_uri = isinstance(block.get("endpoint_uri"), str) and bool(
                        block.get("endpoint_uri")
                    )
                    if has_connection_string or has_endpoint_uri:
                        valid_eventhub_blocks.append(block)
                if valid_eventhub_blocks:
                    sanitized["eventhub"] = valid_eventhub_blocks
                else:
                    sanitized.pop("eventhub", None)
            return sanitized
        if resource_type == "azurerm_log_analytics_workspace_table_custom_log":
            sanitized = dict(attrs)
            columns = sanitized.get("column")
            if self._is_empty_value(columns):
                # Provider requires at least one column block.
                sanitized["column"] = [{"name": "RawData", "type": "string"}]
            return sanitized
        if resource_type == "azurerm_windows_function_app":
            sanitized = dict(attrs)
            site_config = sanitized.get("site_config")
            if isinstance(site_config, list):
                cleaned_site_config: list[Any] = []
                for block in site_config:
                    if not isinstance(block, dict):
                        cleaned_site_config.append(block)
                        continue
                    updated = dict(block)
                    for key in (
                        "ip_restriction_default_action",
                        "scm_ip_restriction_default_action",
                    ):
                        if updated.get(key) == "":
                            updated.pop(key, None)
                    cleaned_site_config.append(updated)
                sanitized["site_config"] = cleaned_site_config
            return sanitized
        return attrs

    def _should_skip_resource(self, resource_type: str, attrs: dict[str, Any]) -> bool:
        if resource_type == "azurerm_api_management_logger":
            has_resource_id = isinstance(attrs.get("resource_id"), str) and bool(attrs.get("resource_id"))
            eventhub = attrs.get("eventhub")
            has_eventhub = isinstance(eventhub, list) and len(eventhub) > 0
            if not has_resource_id and not has_eventhub:
                return True
        return False

    def _normalize_resource_name(self, name: str, resource_type: str, attrs: dict[str, Any]) -> str:
        match = re.match(r"^res-(\d+)$", name)
        if match:
            base_name = self._descriptive_name_from_attrs(attrs)
            if base_name:
                return self._ensure_unique_name(base_name, resource_type)
            return self._generated_fallback_name(resource_type, match.group(1))

        return self._apply_naming_convention(name)

    def _generated_fallback_name(self, resource_type: str, index: str) -> str:
        base_type = resource_type.removeprefix("azurerm_")
        return self._apply_naming_convention(f"{base_type}_{index}")

    def _sanitize_name(self, name: str) -> str:
        if name == "@":
            return "root"

        prefixes_to_strip = ["rg-", "kv-", "st-", "vm-", "vnet-", "nsg-", "pip-"]
        lower_name = name.lower()
        for prefix in prefixes_to_strip:
            if lower_name.startswith(prefix):
                name = name[len(prefix) :]
                break

        sanitized = self._apply_naming_convention(name)
        if not sanitized or sanitized.isdigit():
            return f"res_{name}"

        if sanitized[0].isdigit():
            sanitized = f"n{sanitized}"

        return sanitized

    def _descriptive_name_from_attrs(self, attrs: dict[str, Any]) -> str | None:
        for key in DESCRIPTIVE_NAME_KEYS:
            value = attrs.get(key)
            sanitized = self._sanitize_descriptive_string(value)
            if sanitized:
                return sanitized

        for key, value in attrs.items():
            if key in NON_DESCRIPTIVE_NAME_KEYS:
                continue
            if key.endswith("_name"):
                sanitized = self._sanitize_descriptive_string(value)
                if sanitized:
                    return sanitized
        return None

    def _sanitize_descriptive_string(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        if not value.strip():
            return None
        if "${" in value and "}" in value:
            return None
        if self._is_terraform_reference(value):
            return None
        return self._sanitize_name(value)

    def _apply_naming_convention(self, name: str) -> str:
        if self.config.naming_convention == "snake_case":
            normalized = re.sub(r"[^a-zA-Z0-9]", "_", name)
            normalized = re.sub(r"_+", "_", normalized)
            return normalized.lower().strip("_")
        elif self.config.naming_convention == "kebab-case":
            normalized = re.sub(r"[^a-zA-Z0-9]", "-", name)
            normalized = re.sub(r"-+", "-", normalized)
            return normalized.lower().strip("-")
        elif self.config.naming_convention == "camelCase":
            parts = re.split(r"[^a-zA-Z0-9]", name)
            if not parts:
                return name
            return parts[0].lower() + "".join(p.capitalize() for p in parts[1:])
        return name

    def _ensure_unique_name(self, base_name: str, resource_type: str) -> str:
        key = f"{resource_type}:{base_name}"
        self._name_counter[key] = self._name_counter.get(key, 0) + 1

        if self._name_counter[key] == 1:
            return base_name
        return f"{base_name}_{self._name_counter[key]}"

    def _transform_attributes(
        self,
        attrs: dict[str, Any],
        result: TransformResult,
    ) -> dict[str, Any]:
        new_attrs: dict[str, Any] = {}

        for key, value in attrs.items():
            key = DEPRECATED_ATTRIBUTE_RENAMES.get(key, key)

            if self._is_sensitive_attribute(key):
                result.warnings.append(
                    f"Sensitive attribute '{key}' found - consider using Key Vault reference"
                )

            if isinstance(value, str) and self._looks_like_secret_value(value):
                result.warnings.append(
                    f"SECURITY: Attribute '{key}' contains what appears to be a secret value"
                )

            if key == "depends_on":
                new_attrs[key] = self._transform_depends_on(value)
            elif isinstance(value, dict):
                if key == "tags":
                    new_attrs[key] = "local.common_tags"
                else:
                    new_attrs[key] = self._transform_attributes(value, result)
            elif isinstance(value, list):
                new_attrs[key] = [
                    self._transform_attributes(item, result) if isinstance(item, dict) else item
                    for item in value
                ]
            elif isinstance(value, str):
                transformed = self._transform_string_value(value, key)
                if self.config.extract_variables and key in ("location", "resource_group_name"):
                    new_attrs[key] = f"var.{key}"
                else:
                    new_attrs[key] = transformed
            else:
                new_attrs[key] = value

        return new_attrs

    def _transform_depends_on(self, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []

        transformed: list[str] = []
        for item in value:
            if isinstance(item, str):
                clean = self._clean_interpolation(item)
                new_ref = self._update_reference(clean)
                transformed.append(new_ref)

        return transformed

    def _transform_string_value(self, value: str, key: str) -> str:
        if value.startswith("${") and value.endswith("}"):
            inner = value[2:-1]
            updated = self._update_reference(inner)
            return updated

        if "${" in value and "}" in value:
            def _replace_interpolation(match: re.Match[str]) -> str:
                inner = match.group(1)
                updated = self._update_reference(inner)
                return f"${{{updated}}}"

            return re.sub(r"\$\{([^}]+)\}", _replace_interpolation, value)

        if key == "destination_resource_id":
            return value

        if self._is_azure_resource_id(value) and key.endswith("_id"):
            normalized_id = self._normalize_azure_id(value)
            selected = self._select_id_reference_for_key(normalized_id, key)
            if selected:
                return selected
            mapped_reference = self._azure_id_mapping.get(normalized_id)
            if mapped_reference:
                return mapped_reference
            return value

        return value

    def _clean_interpolation(self, value: str) -> str:
        if value.startswith('"${') and value.endswith('}"'):
            return value[3:-2]
        if value.startswith("${") and value.endswith("}"):
            return value[2:-1]
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        return value

    def _update_reference(self, ref: str) -> str:
        for old_addr, new_addr in self._name_mapping.items():
            if ref.startswith(old_addr):
                return ref.replace(old_addr, new_addr, 1)
        return ref

    def _is_azure_resource_id(self, value: str) -> bool:
        return value.startswith("/subscriptions/") and "/providers/" in value

    def _normalize_azure_id(self, value: str) -> str:
        return value.strip().rstrip("/").lower()

    def _resource_id_match_score(self, resource: TerraformResource, normalized_id: str) -> int:
        score = 0
        id_name = normalized_id.rsplit("/", 1)[-1]
        resource_name = resource.attributes.get("name")

        # Strong signal that the ARM ID belongs to this resource.
        if isinstance(resource_name, str) and resource_name.lower() == id_name:
            score += 10

        # Weak signal: top-level resources are usually true ARM ID owners.
        if not any(key.endswith("_id") for key in resource.attributes):
            score += 1

        return score

    def _select_id_reference_for_key(self, normalized_id: str, key: str) -> str | None:
        candidates = self._azure_id_candidates.get(normalized_id, [])
        if not candidates:
            return None

        expected_resource_type = self._expected_resource_type_from_id_key(key)
        if expected_resource_type:
            expected_prefix = f"{expected_resource_type}."
            for candidate in candidates:
                if candidate.startswith(expected_prefix):
                    return candidate

        return None

    def _expected_resource_type_from_id_key(self, key: str) -> str | None:
        if not key.endswith("_id"):
            return None
        base = key[: -len("_id")]
        if not base:
            return None
        return f"azurerm_{base}"

    def _is_sensitive_attribute(self, attr_name: str) -> bool:
        attr_lower = attr_name.lower()
        return any(re.search(pattern, attr_lower) for pattern in SENSITIVE_ATTRIBUTE_PATTERNS)

    def _looks_like_secret_value(self, value: str) -> bool:
        return any(re.search(pattern, value) for pattern in SECRET_VALUE_PATTERNS)

    def _group_by_category(
        self,
        resources: list[TerraformResource],
    ) -> dict[ResourceCategory, list[TerraformResource]]:
        grouped: dict[ResourceCategory, list[TerraformResource]] = defaultdict(list)
        for resource in resources:
            grouped[resource.category].append(resource)
        return dict(grouped)

    def _extract_common_variables(
        self,
        resources: list[TerraformResource],
    ) -> list[TerraformVariable]:
        variables: list[TerraformVariable] = []
        has_location = False
        has_resource_group = False
        location_values: set[str] = set()
        resource_group_values: set[str] = set()
        resource_group_resource_names: set[str] = set()
        non_literal_location = False
        non_literal_resource_group = False
        tags: dict[str, str] = {}

        for resource in resources:
            if "location" in resource.attributes:
                has_location = True
                location = resource.attributes["location"]
                if isinstance(location, str) and self._is_literal_default_value(location):
                    location_values.add(location)
                else:
                    non_literal_location = True
            if "resource_group_name" in resource.attributes:
                has_resource_group = True
                resource_group_name = resource.attributes["resource_group_name"]
                if isinstance(resource_group_name, str) and self._is_literal_default_value(
                    resource_group_name
                ):
                    resource_group_values.add(resource_group_name)
                else:
                    non_literal_resource_group = True
            if resource.resource_type == "azurerm_resource_group":
                rg_name = resource.attributes.get("name")
                if isinstance(rg_name, str) and self._is_literal_default_value(rg_name):
                    resource_group_resource_names.add(rg_name)
            if "tags" in resource.attributes and isinstance(resource.attributes["tags"], dict):
                tags.update(resource.attributes["tags"])

        if has_location:
            location_default: str | None = None
            if not non_literal_location and len(location_values) == 1:
                location_default = next(iter(location_values))
            variables.append(
                TerraformVariable(
                    name="location",
                    var_type="string",
                    default=location_default,
                    description="Azure region for resources",
                )
            )

        if has_resource_group:
            resource_group_default: str | None = None
            if not non_literal_resource_group and len(resource_group_values) == 1:
                resource_group_default = next(iter(resource_group_values))
            elif len(resource_group_resource_names) == 1:
                # Common in migrated flat exports: resource_group_name is a reference
                # to a single azurerm_resource_group resource declared in the same root.
                resource_group_default = next(iter(resource_group_resource_names))
            variables.append(
                TerraformVariable(
                    name="resource_group_name",
                    var_type="string",
                    default=resource_group_default,
                    description="Name of the resource group",
                )
            )

        variables.append(
            TerraformVariable(
                name="common_tags",
                var_type="map(string)",
                default=tags if tags else {},
                description="Common tags applied to all resources",
            )
        )

        variables.append(
            TerraformVariable(
                name="environment",
                var_type="string",
                default="prod",
                description="Environment name (dev, staging, prod)",
            )
        )

        return variables

    def _is_literal_default_value(self, value: str) -> bool:
        if value.startswith("${") and value.endswith("}"):
            return False
        if "${" in value and "}" in value:
            return False
        if self._is_terraform_reference(value):
            return False
        return True

    def _build_category_call_params(
        self, resources: list[TerraformResource]
    ) -> dict[str, dict[str, Any]]:
        by_category: dict[ResourceCategory, list[TerraformResource]] = defaultdict(list)
        resource_group_names = {
            str(resource.attributes["name"])
            for resource in resources
            if resource.resource_type == "azurerm_resource_group"
            and isinstance(resource.attributes.get("name"), str)
            and self._is_literal_default_value(str(resource.attributes["name"]))
        }
        for resource in resources:
            by_category[resource.category].append(resource)

        params_by_category: dict[str, dict[str, Any]] = {}
        for category, category_resources in by_category.items():
            location_values = {
                resource.attributes.get("location")
                for resource in category_resources
                if "location" in resource.attributes
            }
            rg_values = {
                resource.attributes.get("resource_group_name")
                for resource in category_resources
                if "resource_group_name" in resource.attributes
            }

            params: dict[str, Any] = {}
            if len(location_values) == 1:
                value = next(iter(location_values))
                if isinstance(value, str) and self._is_literal_default_value(value):
                    params["location"] = value
            if len(rg_values) == 1:
                value = next(iter(rg_values))
                if isinstance(value, str) and self._is_literal_default_value(value):
                    params["resource_group_name"] = value
                elif len(resource_group_names) == 1:
                    params["resource_group_name"] = next(iter(resource_group_names))

            if params:
                params_by_category[category.value] = params

        return params_by_category

    def _hoist_category_string_values(self, modules: list[GeneratedModule]) -> None:
        for module in modules:
            if not module.is_category_module:
                continue

            apim_policy_to_operation_name = self._build_apim_policy_to_operation_name(
                module.resources
            )
            module_resource_types = {resource.resource_type for resource in module.resources}
            used_names = {var.name for var in module.variables}
            new_vars: list[TerraformVariable] = []
            call_params = dict(module.call_params)
            type_var_names: dict[str, str] = {}
            resources_by_type: dict[str, list[TerraformResource]] = defaultdict(list)
            defaults_by_map: dict[str, dict[str, Any]] = {}

            for resource in module.resources:
                resources_by_type[resource.resource_type].append(resource)
                map_name = type_var_names.get(resource.resource_type)
                if not map_name:
                    base_name = self._resource_type_var_name(resource.resource_type)
                    map_name = self._ensure_unique_var_name(base_name, used_names)
                    used_names.add(map_name)
                    type_var_names[resource.resource_type] = map_name
                    new_vars.append(
                        TerraformVariable(
                            name=map_name,
                            var_type="map(any)",
                            description=f"String values for {resource.resource_type} resources",
                        )
                    )

                resource_map = call_params.setdefault(map_name, {})
                resource_entry = resource_map.setdefault(resource.name, {})
                resource.attributes = self._replace_string_literals_by_type(
                    resource_name=resource.name,
                    value=resource.attributes,
                    resource_type=resource.resource_type,
                    map_name=map_name,
                    resource_map=resource_entry,
                    module_resource_types=module_resource_types,
                    apim_policy_to_operation_name=apim_policy_to_operation_name,
                )

            for resource_type, map_name in type_var_names.items():
                resource_map = call_params.get(map_name, {})
                if len(resources_by_type.get(resource_type, [])) < 2:
                    continue
                defaults = self._extract_common_map_defaults(resource_map)
                if defaults:
                    defaults_by_map[map_name] = defaults
                    default_var_name = f"{map_name}_defaults"
                    if default_var_name not in used_names:
                        used_names.add(default_var_name)
                        new_vars.append(
                            TerraformVariable(
                                name=default_var_name,
                                var_type="map(any)",
                                default=defaults,
                                description=f"Default values for {resource_type} resources",
                            )
                        )

            if new_vars:
                module.variables.extend(new_vars)
            module.call_params = call_params
            module.resource_type_vars = type_var_names
            self._apply_category_map_var_types(module, defaults_by_map)
            self._rewrite_category_references(module)

    def _replace_string_literals_by_type(
        self,
        resource_name: str,
        value: Any,
        resource_type: str,
        map_name: str,
        resource_map: dict[str, Any],
        module_resource_types: set[str],
        apim_policy_to_operation_name: dict[str, str] | None = None,
        path: list[str | int] | None = None,
    ) -> Any:
        if path is None:
            path = []

        if isinstance(value, dict):
            updated: dict[str, Any] = {}
            for key, nested in value.items():
                if key in {"location", "resource_group_name", "depends_on"}:
                    updated[key] = nested
                    continue
                if key == "tags" and resource_type != "azurerm_key_vault_secret":
                    updated[key] = nested
                    continue
                updated[key] = self._replace_string_literals_by_type(
                    resource_name=resource_name,
                    value=nested,
                    resource_type=resource_type,
                    map_name=map_name,
                    resource_map=resource_map,
                    module_resource_types=module_resource_types,
                    apim_policy_to_operation_name=apim_policy_to_operation_name,
                    path=[*path, str(key)],
                )
            return updated
        if isinstance(value, list):
            return [
                self._replace_string_literals_by_type(
                    resource_name=resource_name,
                    value=item,
                    resource_type=resource_type,
                    map_name=map_name,
                    resource_map=resource_map,
                    module_resource_types=module_resource_types,
                    apim_policy_to_operation_name=apim_policy_to_operation_name,
                    path=[*path, index],
                )
                for index, item in enumerate(value)
            ]
        if isinstance(value, str):
            if "${" in value and "}" in value:
                return value
            if self._is_terraform_reference(value):
                updated_value = self._update_reference(value)
                ref = self._parse_resource_reference(updated_value)
                if (
                    ref
                    and resource_type == "azurerm_api_management_api_operation_tag"
                    and path
                    and path[-1] == "api_operation_id"
                    and ref["resource_type"] == "azurerm_api_management_api_operation_policy"
                ):
                    # API operation tags bind to operation IDs, not operation policy IDs.
                    ref["resource_type"] = "azurerm_api_management_api_operation"
                    if apim_policy_to_operation_name:
                        mapped_name = apim_policy_to_operation_name.get(ref["name"])
                        if mapped_name:
                            ref["name"] = mapped_name
                if ref and ref["resource_type"] in module_resource_types:
                    if not path:
                        path = ["value"]
                    update = self._build_nested_update(path, ref["name"])
                    self._merge_structures(resource_map, update)
                    ref_name = self._build_map_reference(map_name, resource_name, path)
                    return f'{ref["resource_type"]}.this[{ref_name}]{ref["suffix"]}'
                return updated_value
            if not path:
                path = ["value"]
            update = self._build_nested_update(path, value)
            self._merge_structures(resource_map, update)
            reference = self._build_map_reference(map_name, resource_name, path)
            return reference
        if isinstance(value, (int, float, bool)):
            if not path:
                path = ["value"]
            update = self._build_nested_update(path, value)
            self._merge_structures(resource_map, update)
            reference = self._build_map_reference(map_name, resource_name, path)
            return reference
        return value

    def _build_apim_policy_to_operation_name(
        self, resources: list[TerraformResource]
    ) -> dict[str, str]:
        operation_name_by_api_and_operation_id: dict[tuple[str, str], str] = {}
        mapping: dict[str, str] = {}

        for resource in resources:
            if resource.resource_type != "azurerm_api_management_api_operation":
                continue
            api_name = resource.attributes.get("api_name")
            operation_id = resource.attributes.get("operation_id")
            if isinstance(api_name, str) and isinstance(operation_id, str):
                operation_name_by_api_and_operation_id[(api_name, operation_id)] = resource.name

        for resource in resources:
            if resource.resource_type != "azurerm_api_management_api_operation_policy":
                continue
            api_name = resource.attributes.get("api_name")
            operation_id = resource.attributes.get("operation_id")
            if not isinstance(api_name, str) or not isinstance(operation_id, str):
                continue
            operation_name = operation_name_by_api_and_operation_id.get((api_name, operation_id))
            if operation_name:
                mapping[resource.name] = operation_name

        return mapping

    def _parse_resource_reference(self, value: str) -> dict[str, str] | None:
        match = re.match(r"^(azurerm_[a-z_]+)\.([a-z0-9_-]+)(\..+)$", value)
        if not match:
            return None
        resource_type, name, suffix = match.groups()
        return {
            "resource_type": resource_type,
            "name": name,
            "suffix": suffix,
        }

    def _ensure_unique_var_name(self, base_name: str, used_names: set[str]) -> str:
        if base_name not in used_names:
            return base_name
        counter = 2
        while f"{base_name}_{counter}" in used_names:
            counter += 1
        return f"{base_name}_{counter}"

    def _resource_type_var_name(self, resource_type: str) -> str:
        base = resource_type.replace("azurerm_", "")
        normalized = re.sub(r"[^a-zA-Z0-9]", "_", base)
        normalized = re.sub(r"_+", "_", normalized).strip("_").lower()
        if not normalized:
            normalized = "resources"
        if not normalized.endswith("s"):
            normalized = f"{normalized}s"
        if normalized[0].isdigit():
            normalized = f"n{normalized}"
        return normalized

    def _build_nested_update(self, path: list[str | int], value: str | int | float | bool) -> Any:
        if not path:
            return value
        head = path[0]
        nested = self._build_nested_update(path[1:], value)
        if isinstance(head, int):
            items: list[Any] = []
            while len(items) <= head:
                items.append(None)
            items[head] = nested
            return items
        return {head: nested}

    def _merge_structures(self, base: Any, update: Any) -> Any:
        if isinstance(update, dict):
            if not isinstance(base, dict):
                base = {}
            for key, value in update.items():
                if key in base:
                    base[key] = self._merge_structures(base[key], value)
                else:
                    base[key] = value
            return base
        if isinstance(update, list):
            if not isinstance(base, list):
                base = []
            for index, value in enumerate(update):
                if index >= len(base):
                    base.extend([None] * (index + 1 - len(base)))
                if value is None:
                    continue
                if base[index] is None:
                    base[index] = value
                else:
                    base[index] = self._merge_structures(base[index], value)
            return base
        return update

    def _build_map_reference(self, map_name: str, resource_name: str, path: list[str | int]) -> str:
        ref = f'var.{map_name}["{resource_name}"]'
        for part in path:
            if isinstance(part, int):
                ref = f"{ref}[{part}]"
            elif self._is_valid_identifier(part):
                ref = f"{ref}.{part}"
            else:
                ref = f'{ref}["{part}"]'
        return ref

    def _is_valid_identifier(self, value: str) -> bool:
        return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value))

    def _apply_category_map_var_types(
        self,
        module: GeneratedModule,
        defaults_by_map: dict[str, dict[str, Any]],
    ) -> None:
        vars_by_name = {var.name: var for var in module.variables}

        for map_name in module.resource_type_vars.values():
            resource_map = module.call_params.get(map_name, {})
            node: dict[str, Any] | None = None
            for value in resource_map.values():
                node = self._merge_type_nodes(node, self._infer_type_node(value))

            defaults = defaults_by_map.get(map_name)
            if defaults is not None:
                node = self._merge_type_nodes(node, self._infer_type_node(defaults))

            if node is None:
                node = {"kind": "object", "fields": {}}

            object_type = self._type_node_to_hcl(node)
            map_var = vars_by_name.get(map_name)
            if map_var:
                map_var.var_type = f"map({object_type})"

            default_var = vars_by_name.get(f"{map_name}_defaults")
            if default_var:
                default_var.var_type = object_type

    def _infer_type_node(self, value: Any) -> dict[str, Any]:
        if value is None:
            return {"kind": "any"}
        if isinstance(value, str):
            return {"kind": "string"}
        if isinstance(value, dict):
            fields: dict[str, Any] = {}
            for key, nested in value.items():
                if nested is None:
                    continue
                fields[str(key)] = self._infer_type_node(nested)
            return {"kind": "object", "fields": fields}
        if isinstance(value, list):
            items = [item for item in value if item is not None]
            if not items:
                return {"kind": "list", "elem": {"kind": "any"}}
            elem = self._infer_type_node(items[0])
            for item in items[1:]:
                elem = self._merge_type_nodes(elem, self._infer_type_node(item))
            return {"kind": "list", "elem": elem}
        return {"kind": "any"}

    def _merge_type_nodes(
        self, left: dict[str, Any] | None, right: dict[str, Any]
    ) -> dict[str, Any]:
        if left is None:
            return right
        if left["kind"] == "any":
            return right
        if right["kind"] == "any":
            return left
        if left["kind"] != right["kind"]:
            return {"kind": "any"}

        kind = left["kind"]
        if kind == "string":
            return left
        if kind == "list":
            return {"kind": "list", "elem": self._merge_type_nodes(left["elem"], right["elem"])}
        if kind == "object":
            fields = dict(left.get("fields", {}))
            for key, value in right.get("fields", {}).items():
                if key in fields:
                    fields[key] = self._merge_type_nodes(fields[key], value)
                else:
                    fields[key] = value
            return {"kind": "object", "fields": fields}
        return {"kind": "any"}

    def _type_node_to_hcl(self, node: dict[str, Any]) -> str:
        kind = node.get("kind")
        if kind == "string":
            return "string"
        if kind == "list":
            elem = node.get("elem", {"kind": "any"})
            return f"list({self._type_node_to_hcl(elem)})"
        if kind == "object":
            fields = node.get("fields", {})
            if not fields:
                return "object({})"
            if any(not self._is_valid_identifier(key) for key in fields):
                return "map(any)"
            items = []
            for key in sorted(fields):
                field_type = self._type_node_to_hcl(fields[key])
                items.append(f"{key} = optional({field_type})")
            return "object({" + ", ".join(items) + "})"
        return "any"

    def _is_terraform_reference(self, value: str) -> bool:
        if value.startswith(("var.", "local.", "module.", "each.", "try(", "coalesce(")):
            return True
        tf_resource_pattern = r"^azurerm_[a-z_]+\.[a-z0-9_-]+(\[[^\]]+\])?(\.[a-z_]+)*$"
        return bool(re.match(tf_resource_pattern, value))

    def _extract_common_map_defaults(self, resource_map: dict[str, Any]) -> dict[str, Any]:
        if len(resource_map) < 2:
            return {}

        values_by_path: dict[tuple[Any, ...], dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        for resource_values in resource_map.values():
            self._collect_leaf_values(resource_values, [], values_by_path)

        total_resources = len(resource_map)
        default_paths: list[tuple[Any, ...]] = []
        defaults: dict[str, Any] = {}

        for path, counts in values_by_path.items():
            total_count = sum(counts.values())
            if total_count != total_resources:
                continue
            if len(counts) != 1:
                continue
            value = next(iter(counts.keys()))
            default_paths.append(path)
            defaults = self._merge_structures(
                defaults, self._build_nested_update(list(path), value)
            )

        if not default_paths:
            return {}

        for resource_values in resource_map.values():
            for path in default_paths:
                self._remove_default_path(resource_values, list(path))

        return defaults

    def _collect_leaf_values(
        self,
        value: Any,
        path: list[str | int],
        values_by_path: dict[tuple[Any, ...], dict[str, int]],
    ) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                self._collect_leaf_values(nested, [*path, str(key)], values_by_path)
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                self._collect_leaf_values(item, [*path, index], values_by_path)
            return
        if isinstance(value, str):
            if path and isinstance(path[-1], str) and path[-1] == "zone_name":
                return
            if path and isinstance(path[-1], str) and path[-1].endswith("_id"):
                return
            values_by_path[tuple(path)][value] += 1

    def _remove_default_path(self, value: Any, path: list[str | int]) -> bool:
        if not path:
            return self._is_empty_value(value)

        head = path[0]
        tail = path[1:]

        if isinstance(value, dict) and isinstance(head, str):
            if head not in value:
                return self._is_empty_value(value)
            if not tail:
                value.pop(head, None)
            else:
                if self._remove_default_path(value[head], tail):
                    value.pop(head, None)
            return self._is_empty_value(value)

        if isinstance(value, list) and isinstance(head, int):
            if head >= len(value):
                return self._is_empty_value(value)
            if not tail:
                value[head] = None
            else:
                if self._remove_default_path(value[head], tail):
                    value[head] = None
            return self._is_empty_value(value)

        return self._is_empty_value(value)

    def _is_empty_value(self, value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, dict):
            return all(self._is_empty_value(v) for v in value.values())
        if isinstance(value, list):
            return all(self._is_empty_value(v) for v in value)
        return False

    def _rewrite_category_references(self, module: GeneratedModule) -> None:
        self._normalize_apim_operation_tag_references(module.resources)
        by_type: dict[str, set[str]] = defaultdict(set)
        for resource in module.resources:
            by_type[resource.resource_type].add(resource.name)

        for resource in module.resources:
            resource.attributes = self._replace_reference_strings(resource.attributes, by_type)
        for output in module.outputs:
            output.value = self._replace_reference_strings(output.value, by_type)

    def _normalize_apim_operation_tag_references(
        self, resources: list[TerraformResource]
    ) -> None:
        operation_name_by_api_and_operation_id: dict[tuple[str, str], str] = {}
        policy_by_name: dict[str, TerraformResource] = {}

        for resource in resources:
            if resource.resource_type == "azurerm_api_management_api_operation":
                api_name = resource.attributes.get("api_name")
                operation_id = resource.attributes.get("operation_id")
                if isinstance(api_name, str) and isinstance(operation_id, str):
                    operation_name_by_api_and_operation_id[(api_name, operation_id)] = (
                        resource.name
                    )
            elif resource.resource_type == "azurerm_api_management_api_operation_policy":
                policy_by_name[resource.name] = resource

        if not operation_name_by_api_and_operation_id or not policy_by_name:
            return

        for resource in resources:
            if resource.resource_type != "azurerm_api_management_api_operation_tag":
                continue
            api_operation_id = resource.attributes.get("api_operation_id")
            if not isinstance(api_operation_id, str):
                continue
            match = re.match(
                r"^azurerm_api_management_api_operation_policy\.([a-z0-9_-]+)\.id$",
                api_operation_id,
            )
            if not match:
                continue
            policy_name = match.group(1)
            policy = policy_by_name.get(policy_name)
            if policy is None:
                continue
            api_name = policy.attributes.get("api_name")
            operation_id = policy.attributes.get("operation_id")
            if not isinstance(api_name, str) or not isinstance(operation_id, str):
                continue
            operation_name = operation_name_by_api_and_operation_id.get((api_name, operation_id))
            if not operation_name:
                continue
            resource.attributes["api_operation_id"] = (
                f"azurerm_api_management_api_operation.{operation_name}.id"
            )

    def _replace_reference_strings(self, value: Any, by_type: dict[str, set[str]]) -> Any:
        if isinstance(value, dict):
            return {
                key: self._replace_reference_strings(nested, by_type)
                for key, nested in value.items()
            }
        if isinstance(value, list):
            return [self._replace_reference_strings(item, by_type) for item in value]
        if isinstance(value, str):
            match = re.match(
                r"^(azurerm_[a-z_]+)\.([a-z0-9_]+)(\..+)?$",
                value,
            )
            if match:
                resource_type, name, suffix = match.groups()
                if name in by_type.get(resource_type, set()):
                    trailing = suffix or ""
                    return f'{resource_type}.this["{name}"]{trailing}'
            return self._rewrite_embedded_resource_references(value, by_type)
        return value

    def _rewrite_embedded_resource_references(
        self, value: str, by_type: dict[str, set[str]]
    ) -> str:
        address_map: dict[str, str] = {}
        for resource_type, names in by_type.items():
            for name in names:
                address = f"{resource_type}.{name}"
                address_map[address] = f'{resource_type}.this["{name}"]'

        if not address_map:
            return value

        pattern = re.compile(r"azurerm_[a-z_]+\.[a-z0-9_]+")

        def _replace(match: re.Match[str]) -> str:
            address = match.group(0)
            return address_map.get(address, address)

        return pattern.sub(_replace, value)

    def _generate_outputs(
        self,
        resources: list[TerraformResource],
    ) -> list[TerraformOutput]:
        outputs: list[TerraformOutput] = []

        important_types = {
            "azurerm_resource_group": "resource_group",
            "azurerm_virtual_network": "vnet",
            "azurerm_subnet": "subnet",
            "azurerm_storage_account": "storage",
            "azurerm_key_vault": "key_vault",
            "azurerm_kubernetes_cluster": "aks",
            "azurerm_mssql_server": "sql_server",
            "azurerm_postgresql_flexible_server": "postgresql",
        }

        for resource in resources:
            if resource.resource_type in important_types:
                type_prefix = important_types[resource.resource_type]
                output_name = f"{type_prefix}_{resource.name}_id"
                outputs.append(
                    TerraformOutput(
                        name=output_name,
                        value=f"{resource.resource_type}.{resource.name}.id",
                        description=f"Resource ID of {resource.resource_type}.{resource.name}",
                    )
                )

                if resource.resource_type == "azurerm_resource_group":
                    outputs.append(
                        TerraformOutput(
                            name=f"{type_prefix}_{resource.name}_name",
                            value=f"{resource.resource_type}.{resource.name}.name",
                            description=f"Name of resource group {resource.name}",
                        )
                    )

        return outputs

    def _generate_module_root_outputs(
        self,
        modules: list[GeneratedModule],
    ) -> list[TerraformOutput]:
        outputs: list[TerraformOutput] = []

        for module in modules:
            for module_output in module.outputs:
                output_name = f"{module.name}_{module_output.name}"
                outputs.append(
                    TerraformOutput(
                        name=output_name,
                        value=f"module.{module.name}.{module_output.name}",
                        description=module_output.description,
                        sensitive=module_output.sensitive,
                    )
                )

        return outputs

    def _build_module_address_mapping(
        self,
        original_resources: list[TerraformResource],
        modules: list[GeneratedModule],
    ) -> dict[str, str]:
        resource_to_module: dict[str, GeneratedModule] = {}
        for module in modules:
            for resource in module.resources:
                resource_to_module[resource.address] = module

        mapping: dict[str, str] = {}
        for orig_resource in original_resources:
            old_address = orig_resource.address
            new_address = self._name_mapping.get(old_address, old_address)
            new_name = new_address.split(".", 1)[1] if "." in new_address else orig_resource.name

            res_module = resource_to_module.get(new_address)
            if res_module and res_module.is_category_module:
                module_address = (
                    f'module.{res_module.name}.{orig_resource.resource_type}.this["{new_name}"]'
                )
                mapping[old_address] = module_address
            elif res_module:
                mapping[old_address] = f"module.{res_module.name}.{new_address}"

        return mapping

    def _rewrite_import_blocks(
        self,
        import_blocks: list[ImportBlock],
        address_mapping: dict[str, str],
    ) -> list[ImportBlock]:
        rewritten: list[ImportBlock] = []
        for block in import_blocks:
            # hcl2 parser returns references wrapped in ${...}, strip that
            original_to = block.to
            if original_to.startswith("${") and original_to.endswith("}"):
                original_to = original_to[2:-1]
            direct = address_mapping.get(original_to)
            renamed = address_mapping.get(self._name_mapping.get(original_to, ""))
            new_to = direct or renamed
            if not new_to:
                continue
            rewritten.append(ImportBlock(id=block.id, to=new_to))
        return rewritten
