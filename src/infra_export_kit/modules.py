from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from infra_export_kit.models import ResourceCategory, TerraformResource, TerraformVariable


class ModuleType(Enum):
    NETWORK = "network"
    STORAGE = "storage"
    COMPUTE = "compute"
    DATABASE = "database"
    KEYVAULT = "keyvault"
    CONTAINER = "container"
    WEB = "web"
    IDENTITY = "identity"
    MONITORING = "monitoring"
    SECURITY = "security"
    OTHER = "other"


CATEGORY_TO_MODULE_TYPE: dict[ResourceCategory, ModuleType] = {
    ResourceCategory.NETWORK: ModuleType.NETWORK,
    ResourceCategory.STORAGE: ModuleType.STORAGE,
    ResourceCategory.COMPUTE: ModuleType.COMPUTE,
    ResourceCategory.DATABASE: ModuleType.DATABASE,
    ResourceCategory.IDENTITY: ModuleType.IDENTITY,
    ResourceCategory.MONITORING: ModuleType.MONITORING,
    ResourceCategory.SECURITY: ModuleType.SECURITY,
    ResourceCategory.CONTAINER: ModuleType.CONTAINER,
    ResourceCategory.WEB: ModuleType.WEB,
    ResourceCategory.OTHER: ModuleType.OTHER,
}


@dataclass
class ModulePattern:
    module_type: ModuleType
    primary_types: list[str]
    related_types: list[str]
    description: str


MODULE_PATTERNS: list[ModulePattern] = [
    ModulePattern(
        module_type=ModuleType.NETWORK,
        primary_types=["azurerm_virtual_network"],
        related_types=[
            "azurerm_subnet",
            "azurerm_network_security_group",
            "azurerm_network_security_rule",
            "azurerm_route_table",
            "azurerm_route",
            "azurerm_subnet_network_security_group_association",
            "azurerm_subnet_route_table_association",
            "azurerm_nat_gateway",
            "azurerm_nat_gateway_public_ip_association",
            "azurerm_public_ip",
        ],
        description="Virtual network with subnets, NSGs, and routing",
    ),
    ModulePattern(
        module_type=ModuleType.STORAGE,
        primary_types=["azurerm_storage_account"],
        related_types=[
            "azurerm_storage_container",
            "azurerm_storage_share",
            "azurerm_storage_queue",
            "azurerm_storage_table",
            "azurerm_storage_blob",
            "azurerm_storage_management_policy",
            "azurerm_storage_account_queue_properties",
            "azurerm_storage_account_blob_properties",
        ],
        description="Storage account with containers, shares, and policies",
    ),
    ModulePattern(
        module_type=ModuleType.COMPUTE,
        primary_types=[
            "azurerm_linux_virtual_machine",
            "azurerm_windows_virtual_machine",
            "azurerm_virtual_machine",
        ],
        related_types=[
            "azurerm_network_interface",
            "azurerm_managed_disk",
            "azurerm_virtual_machine_data_disk_attachment",
            "azurerm_virtual_machine_extension",
            "azurerm_public_ip",
            "azurerm_availability_set",
        ],
        description="Virtual machine with NICs, disks, and extensions",
    ),
    ModulePattern(
        module_type=ModuleType.DATABASE,
        primary_types=[
            "azurerm_mssql_server",
            "azurerm_postgresql_flexible_server",
            "azurerm_mysql_flexible_server",
        ],
        related_types=[
            "azurerm_mssql_database",
            "azurerm_mssql_firewall_rule",
            "azurerm_mssql_virtual_network_rule",
            "azurerm_postgresql_flexible_server_database",
            "azurerm_postgresql_flexible_server_firewall_rule",
            "azurerm_mysql_flexible_database",
            "azurerm_mysql_flexible_server_firewall_rule",
        ],
        description="Database server with databases and firewall rules",
    ),
    ModulePattern(
        module_type=ModuleType.KEYVAULT,
        primary_types=["azurerm_key_vault"],
        related_types=[
            "azurerm_key_vault_access_policy",
            "azurerm_key_vault_secret",
            "azurerm_key_vault_key",
            "azurerm_key_vault_certificate",
        ],
        description="Key Vault with access policies and secrets",
    ),
    ModulePattern(
        module_type=ModuleType.CONTAINER,
        primary_types=["azurerm_kubernetes_cluster"],
        related_types=[
            "azurerm_kubernetes_cluster_node_pool",
            "azurerm_container_registry",
        ],
        description="Kubernetes cluster with node pools",
    ),
    ModulePattern(
        module_type=ModuleType.WEB,
        primary_types=[
            "azurerm_linux_web_app",
            "azurerm_windows_web_app",
            "azurerm_linux_function_app",
            "azurerm_windows_function_app",
        ],
        related_types=[
            "azurerm_service_plan",
            "azurerm_app_service_custom_hostname_binding",
            "azurerm_app_service_certificate",
        ],
        description="Web app or function with service plan",
    ),
]


@dataclass
class ModuleOutput:
    name: str
    value: str
    description: str = ""
    sensitive: bool = False


@dataclass
class GeneratedModule:
    name: str
    module_type: ModuleType
    resources: list[TerraformResource] = field(default_factory=list)
    variables: list[TerraformVariable] = field(default_factory=list)
    outputs: list[ModuleOutput] = field(default_factory=list)
    source_path: str = ""
    is_category_module: bool = False
    call_params: dict[str, Any] = field(default_factory=dict)
    resource_type_vars: dict[str, str] = field(default_factory=dict)


@dataclass
class ModuleCall:
    name: str
    source: str
    variables: dict[str, Any] = field(default_factory=dict)


class ModuleGenerator:
    def __init__(self) -> None:
        self.patterns = MODULE_PATTERNS
        self._name_counter: dict[str, int] = {}

    def _sanitize_terraform_name(self, name: str) -> str:
        if name == "@":
            return "root"

        name = name.replace("@", "_at_")
        sanitized = re.sub(r"[^a-zA-Z0-9]", "_", name)
        sanitized = re.sub(r"_+", "_", sanitized)
        sanitized = sanitized.strip("_").lower()

        if sanitized and sanitized[0].isdigit():
            sanitized = f"n{sanitized}"

        if not sanitized:
            return "unnamed"

        return sanitized

    def _ensure_unique_module_name(self, base_name: str) -> str:
        self._name_counter[base_name] = self._name_counter.get(base_name, 0) + 1

        if self._name_counter[base_name] == 1:
            return base_name
        return f"{base_name}_{self._name_counter[base_name]}"

    def reset_name_counter(self) -> None:
        self._name_counter = {}

    def detect_modules(self, resources: list[TerraformResource]) -> list[GeneratedModule]:
        self.reset_name_counter()
        modules: list[GeneratedModule] = []
        used_resources: set[str] = set()

        for pattern in self.patterns:
            primary_resources = [
                r
                for r in resources
                if r.resource_type in pattern.primary_types and r.address not in used_resources
            ]

            for primary in primary_resources:
                module_resources = [primary]
                used_resources.add(primary.address)

                related = self._find_related_resources(
                    primary, resources, pattern.related_types, used_resources
                )
                for r in related:
                    module_resources.append(r)
                    used_resources.add(r.address)

                if len(module_resources) > 1:
                    module_name = self._generate_module_name(primary, pattern.module_type)
                    module = GeneratedModule(
                        name=module_name,
                        module_type=pattern.module_type,
                        resources=module_resources,
                        variables=self._generate_module_variables(module_resources),
                        outputs=self._generate_module_outputs(module_resources, pattern),
                        source_path=f"./modules/{module_name}",
                    )
                    modules.append(module)

        return modules

    def _find_related_resources(
        self,
        primary: TerraformResource,
        all_resources: list[TerraformResource],
        related_types: list[str],
        used: set[str],
    ) -> list[TerraformResource]:
        related: list[TerraformResource] = []
        primary_name = self._extract_resource_name(primary)

        for resource in all_resources:
            if resource.address in used:
                continue
            if resource.resource_type not in related_types:
                continue

            if self._resources_are_related(primary, resource, primary_name):
                related.append(resource)

        return related

    def _resources_are_related(
        self,
        primary: TerraformResource,
        candidate: TerraformResource,
        primary_name: str,
    ) -> bool:
        primary_id = primary.azure_resource_id or ""
        candidate_attrs = candidate.attributes

        for key, value in candidate_attrs.items():
            if isinstance(value, str):
                if primary_id and primary_id in value:
                    return True
                if primary_name and primary_name in value:
                    return True

            if (
                (key.endswith("_id") or key.endswith("_name"))
                and isinstance(value, str)
                and primary_name
                and primary_name in value
            ):
                return True

        if primary.resource_type == "azurerm_virtual_network":
            vnet_name = primary.attributes.get("name", "")
            if candidate.resource_type == "azurerm_subnet":
                candidate_vnet = candidate.attributes.get("virtual_network_name", "")
                if vnet_name and vnet_name == candidate_vnet:
                    return True

        if primary.resource_type == "azurerm_storage_account":
            storage_name = primary.attributes.get("name", "")
            if candidate.resource_type in [
                "azurerm_storage_container",
                "azurerm_storage_share",
            ]:
                candidate_storage = candidate.attributes.get("storage_account_name", "")
                if storage_name and storage_name == candidate_storage:
                    return True

        return False

    def _extract_resource_name(self, resource: TerraformResource) -> str:
        return str(resource.attributes.get("name", resource.name))

    def _generate_module_name(self, primary: TerraformResource, module_type: ModuleType) -> str:
        resource_name = self._extract_resource_name(primary)
        clean_name = self._sanitize_terraform_name(resource_name)
        base_name = f"{module_type.value}_{clean_name}"
        return self._ensure_unique_module_name(base_name)

    def _generate_module_variables(
        self, resources: list[TerraformResource]
    ) -> list[TerraformVariable]:
        variables: list[TerraformVariable] = []
        seen: set[str] = set()

        locations: set[str] = set()
        resource_groups: set[str] = set()

        for resource in resources:
            if "location" in resource.attributes:
                locations.add(str(resource.attributes["location"]))
            if "resource_group_name" in resource.attributes:
                resource_groups.add(str(resource.attributes["resource_group_name"]))

        if locations and "location" not in seen:
            seen.add("location")
            variables.append(
                TerraformVariable(
                    name="location",
                    var_type="string",
                    description="Azure region for resources",
                )
            )

        if resource_groups and "resource_group_name" not in seen:
            seen.add("resource_group_name")
            variables.append(
                TerraformVariable(
                    name="resource_group_name",
                    var_type="string",
                    description="Name of the resource group",
                )
            )

        variables.append(
            TerraformVariable(
                name="tags",
                var_type="map(string)",
                default={},
                description="Tags to apply to resources",
            )
        )

        return variables

    def _generate_module_outputs(
        self,
        resources: list[TerraformResource],
        pattern: ModulePattern,
    ) -> list[ModuleOutput]:
        outputs: list[ModuleOutput] = []

        for resource in resources:
            if resource.resource_type in pattern.primary_types:
                outputs.append(
                    ModuleOutput(
                        name="id",
                        value=f"{resource.resource_type}.this.id",
                        description=f"ID of the {resource.resource_type}",
                    )
                )
                outputs.append(
                    ModuleOutput(
                        name="name",
                        value=f"{resource.resource_type}.this.name",
                        description=f"Name of the {resource.resource_type}",
                    )
                )
                break

        if pattern.module_type == ModuleType.NETWORK:
            subnet_resources = [r for r in resources if r.resource_type == "azurerm_subnet"]
            if subnet_resources:
                subnet_refs = ", ".join(
                    f'"{r.name}" = azurerm_subnet.{r.name}.id' for r in subnet_resources
                )
                outputs.append(
                    ModuleOutput(
                        name="subnet_ids",
                        value=f"{{ {subnet_refs} }}",
                        description="Map of subnet names to IDs",
                    )
                )

        if pattern.module_type == ModuleType.STORAGE:
            outputs.append(
                ModuleOutput(
                    name="primary_blob_endpoint",
                    value="azurerm_storage_account.this.primary_blob_endpoint",
                    description="Primary blob endpoint URL",
                )
            )

        return outputs

    def get_remaining_resources(
        self,
        all_resources: list[TerraformResource],
        modules: list[GeneratedModule],
    ) -> list[TerraformResource]:
        used_addresses: set[str] = set()
        for module in modules:
            for resource in module.resources:
                used_addresses.add(resource.address)

        return [r for r in all_resources if r.address not in used_addresses]

    def generate_category_modules(
        self,
        resources: list[TerraformResource],
    ) -> list[GeneratedModule]:
        by_category: dict[ResourceCategory, list[TerraformResource]] = defaultdict(list)

        for resource in resources:
            by_category[resource.category].append(resource)

        modules: list[GeneratedModule] = []
        for category, category_resources in by_category.items():
            if not category_resources:
                continue

            module_type = CATEGORY_TO_MODULE_TYPE.get(category, ModuleType.OTHER)
            module = GeneratedModule(
                name=category.value,
                module_type=module_type,
                resources=category_resources,
                variables=self._generate_category_module_variables(category_resources),
                outputs=self._generate_category_module_outputs(category_resources),
                source_path=f"./modules/{category.value}",
                is_category_module=True,
            )
            modules.append(module)

        return modules

    def _generate_category_module_variables(
        self,
        resources: list[TerraformResource],
    ) -> list[TerraformVariable]:
        variables: list[TerraformVariable] = []
        seen: set[str] = set()

        has_location = any("location" in r.attributes for r in resources)
        has_rg = any("resource_group_name" in r.attributes for r in resources)

        if has_location and "location" not in seen:
            seen.add("location")
            variables.append(
                TerraformVariable(
                    name="location",
                    var_type="string",
                    description="Azure region for resources",
                )
            )

        if has_rg and "resource_group_name" not in seen:
            seen.add("resource_group_name")
            variables.append(
                TerraformVariable(
                    name="resource_group_name",
                    var_type="string",
                    description="Name of the resource group",
                )
            )

        variables.append(
            TerraformVariable(
                name="tags",
                var_type="map(string)",
                default={},
                description="Tags to apply to resources",
            )
        )

        return variables

    def _generate_category_module_outputs(
        self,
        resources: list[TerraformResource],
    ) -> list[ModuleOutput]:
        outputs: list[ModuleOutput] = []

        important_types = {
            "azurerm_resource_group",
            "azurerm_virtual_network",
            "azurerm_subnet",
            "azurerm_storage_account",
            "azurerm_key_vault",
            "azurerm_kubernetes_cluster",
            "azurerm_mssql_server",
            "azurerm_postgresql_flexible_server",
            "azurerm_log_analytics_workspace",
            "azurerm_application_insights",
            "azurerm_container_registry",
            "azurerm_linux_web_app",
            "azurerm_windows_web_app",
        }

        for resource in resources:
            if resource.resource_type in important_types:
                outputs.append(
                    ModuleOutput(
                        name=f"{resource.name}_id",
                        value=f"{resource.resource_type}.{resource.name}.id",
                        description=f"ID of {resource.resource_type}.{resource.name}",
                    )
                )

        return outputs
