from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ModuleStrategy(Enum):
    CATEGORY = "category"


class ResourceCategory(Enum):
    COMPUTE = "compute"
    NETWORK = "network"
    STORAGE = "storage"
    DATABASE = "database"
    IDENTITY = "identity"
    MONITORING = "monitoring"
    SECURITY = "security"
    CONTAINER = "container"
    WEB = "web"
    OTHER = "other"


RESOURCE_TYPE_CATEGORIES: dict[str, ResourceCategory] = {
    "azurerm_virtual_machine": ResourceCategory.COMPUTE,
    "azurerm_linux_virtual_machine": ResourceCategory.COMPUTE,
    "azurerm_windows_virtual_machine": ResourceCategory.COMPUTE,
    "azurerm_virtual_machine_scale_set": ResourceCategory.COMPUTE,
    "azurerm_availability_set": ResourceCategory.COMPUTE,
    "azurerm_virtual_network": ResourceCategory.NETWORK,
    "azurerm_subnet": ResourceCategory.NETWORK,
    "azurerm_network_interface": ResourceCategory.NETWORK,
    "azurerm_public_ip": ResourceCategory.NETWORK,
    "azurerm_network_security_group": ResourceCategory.NETWORK,
    "azurerm_application_gateway": ResourceCategory.NETWORK,
    "azurerm_load_balancer": ResourceCategory.NETWORK,
    "azurerm_private_endpoint": ResourceCategory.NETWORK,
    "azurerm_dns_zone": ResourceCategory.NETWORK,
    "azurerm_dns_a_record": ResourceCategory.NETWORK,
    "azurerm_dns_aaaa_record": ResourceCategory.NETWORK,
    "azurerm_dns_cname_record": ResourceCategory.NETWORK,
    "azurerm_dns_mx_record": ResourceCategory.NETWORK,
    "azurerm_dns_ns_record": ResourceCategory.NETWORK,
    "azurerm_dns_ptr_record": ResourceCategory.NETWORK,
    "azurerm_dns_srv_record": ResourceCategory.NETWORK,
    "azurerm_dns_txt_record": ResourceCategory.NETWORK,
    "azurerm_dns_caa_record": ResourceCategory.NETWORK,
    "azurerm_private_dns_zone": ResourceCategory.NETWORK,
    "azurerm_private_dns_a_record": ResourceCategory.NETWORK,
    "azurerm_private_dns_aaaa_record": ResourceCategory.NETWORK,
    "azurerm_private_dns_cname_record": ResourceCategory.NETWORK,
    "azurerm_private_dns_mx_record": ResourceCategory.NETWORK,
    "azurerm_private_dns_ptr_record": ResourceCategory.NETWORK,
    "azurerm_private_dns_srv_record": ResourceCategory.NETWORK,
    "azurerm_private_dns_txt_record": ResourceCategory.NETWORK,
    "azurerm_private_dns_zone_virtual_network_link": ResourceCategory.NETWORK,
    "azurerm_storage_account": ResourceCategory.STORAGE,
    "azurerm_storage_account_queue_properties": ResourceCategory.STORAGE,
    "azurerm_storage_container": ResourceCategory.STORAGE,
    "azurerm_storage_blob": ResourceCategory.STORAGE,
    "azurerm_storage_share": ResourceCategory.STORAGE,
    "azurerm_mssql_server": ResourceCategory.DATABASE,
    "azurerm_mssql_database": ResourceCategory.DATABASE,
    "azurerm_postgresql_server": ResourceCategory.DATABASE,
    "azurerm_postgresql_flexible_server": ResourceCategory.DATABASE,
    "azurerm_mysql_server": ResourceCategory.DATABASE,
    "azurerm_cosmosdb_account": ResourceCategory.DATABASE,
    "azurerm_redis_cache": ResourceCategory.DATABASE,
    "azurerm_user_assigned_identity": ResourceCategory.IDENTITY,
    "azurerm_role_assignment": ResourceCategory.IDENTITY,
    "azurerm_key_vault": ResourceCategory.SECURITY,
    "azurerm_key_vault_secret": ResourceCategory.SECURITY,
    "azurerm_key_vault_key": ResourceCategory.SECURITY,
    "azurerm_key_vault_certificate": ResourceCategory.SECURITY,
    "azurerm_log_analytics_workspace": ResourceCategory.MONITORING,
    "azurerm_application_insights": ResourceCategory.OTHER,
    "azurerm_monitor_diagnostic_setting": ResourceCategory.MONITORING,
    "azurerm_monitor_action_group": ResourceCategory.MONITORING,
    "azurerm_log_analytics_data_export_rule": ResourceCategory.MONITORING,
    "azurerm_log_analytics_saved_search": ResourceCategory.MONITORING,
    "azurerm_log_analytics_workspace_table_custom_log": ResourceCategory.MONITORING,
    "azurerm_kubernetes_cluster": ResourceCategory.CONTAINER,
    "azurerm_container_registry": ResourceCategory.CONTAINER,
    "azurerm_container_group": ResourceCategory.CONTAINER,
    "azurerm_app_service": ResourceCategory.WEB,
    "azurerm_app_service_plan": ResourceCategory.WEB,
    "azurerm_service_plan": ResourceCategory.WEB,
    "azurerm_linux_web_app": ResourceCategory.WEB,
    "azurerm_windows_web_app": ResourceCategory.WEB,
    "azurerm_function_app": ResourceCategory.WEB,
    "azurerm_linux_function_app": ResourceCategory.WEB,
    "azurerm_windows_function_app": ResourceCategory.WEB,
    "azurerm_function_app_function": ResourceCategory.WEB,
    "azurerm_logic_app_workflow": ResourceCategory.WEB,
    "azurerm_logic_app_action_custom": ResourceCategory.WEB,
    "azurerm_logic_app_action_http": ResourceCategory.WEB,
    "azurerm_logic_app_trigger_custom": ResourceCategory.WEB,
    "azurerm_logic_app_trigger_http_request": ResourceCategory.WEB,
    "azurerm_logic_app_trigger_recurrence": ResourceCategory.WEB,
}


@dataclass
class TerraformAttribute:
    name: str
    value: Any
    is_sensitive: bool = False
    is_computed: bool = False


@dataclass
class TerraformResource:
    resource_type: str
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    azure_resource_id: str | None = None

    @property
    def category(self) -> ResourceCategory:
        return RESOURCE_TYPE_CATEGORIES.get(self.resource_type, ResourceCategory.OTHER)

    @property
    def address(self) -> str:
        return f"{self.resource_type}.{self.name}"


@dataclass
class TerraformVariable:
    name: str
    var_type: str = "string"
    default: Any = None
    description: str = ""
    sensitive: bool = False
    validation: dict[str, Any] | None = None


@dataclass
class TerraformOutput:
    name: str
    value: str
    description: str = ""
    sensitive: bool = False


@dataclass
class TerraformModule:
    name: str
    source: str
    variables: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportBlock:
    id: str
    to: str


@dataclass
class TerraformProvider:
    name: str
    version: str | None = None
    configuration: dict[str, Any] = field(default_factory=dict)


@dataclass
class TerraformState:
    resources: list[TerraformResource] = field(default_factory=list)
    variables: list[TerraformVariable] = field(default_factory=list)
    outputs: list[TerraformOutput] = field(default_factory=list)
    providers: list[TerraformProvider] = field(default_factory=list)
    modules: list[TerraformModule] = field(default_factory=list)
    import_blocks: list[ImportBlock] = field(default_factory=list)


@dataclass
class ExportConfig:
    resource_groups: list[str]
    output_dir: Path
    subscription_id: str | None = None
    use_modules: bool = True
    module_strategy: ModuleStrategy = ModuleStrategy.CATEGORY
    extract_variables: bool = True
    naming_convention: str = "snake_case"
    group_by_category: bool = True
    include_import_block: bool = True
    terraform_version: str = ">= 1.5.0"
    azurerm_version: str = "~> 4.0"


@dataclass
class ExportResult:
    success: bool
    output_path: Path
    resources_exported: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
