from pathlib import Path

import pytest

from infra_export_kit.models import (
    ExportConfig,
    ImportBlock,
    ResourceCategory,
    TerraformResource,
    TerraformState,
)
from infra_export_kit.transformer import TerraformTransformer


@pytest.fixture
def config() -> ExportConfig:
    return ExportConfig(
        resource_groups=["test-rg"],
        output_dir=Path("/tmp/output"),
    )


@pytest.fixture
def transformer(config: ExportConfig) -> TerraformTransformer:
    return TerraformTransformer(config)


class TestTerraformTransformer:
    def test_transform_empty_state(self, transformer: TerraformTransformer) -> None:
        state = TerraformState()
        result = transformer.transform(state)
        assert result.state.resources == []
        var_names = [v.name for v in result.extracted_variables]
        assert "environment" in var_names

    def test_transform_creates_category_modules(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_virtual_network",
                    name="vnet1",
                    attributes={"name": "vnet1", "location": "eastus"},
                ),
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "storage1", "location": "eastus"},
                ),
            ]
        )
        result = transformer.transform(state)

        module_names = [m.name for m in result.modules]
        assert "network" in module_names
        assert "storage" in module_names
        assert result.remaining_resources == []

    def test_transform_groups_by_category_without_modules(self, config: ExportConfig) -> None:
        config.use_modules = False
        transformer = TerraformTransformer(config)
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_virtual_network",
                    name="vnet1",
                    attributes={"location": "eastus"},
                ),
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"location": "eastus"},
                ),
            ]
        )
        result = transformer.transform(state)
        assert ResourceCategory.NETWORK in result.resources_by_category
        assert ResourceCategory.STORAGE in result.resources_by_category

    def test_extract_common_variables(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_virtual_network",
                    name="vnet1",
                    attributes={
                        "location": "eastus",
                        "resource_group_name": "rg1",
                    },
                ),
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={
                        "location": "eastus",
                        "resource_group_name": "rg1",
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        var_names = [v.name for v in result.extracted_variables]
        assert "location" in var_names
        assert "resource_group_name" in var_names
        assert "environment" in var_names

    def test_extract_common_variables_omits_reference_default(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={
                        "location": "westeurope",
                        "resource_group_name": "azurerm_resource_group.res_0.name",
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        resource_group_var = next(
            var
            for var in result.extracted_variables
            if var.name == "resource_group_name"
        )
        assert resource_group_var.default is None

    def test_extract_common_variables_infers_rg_default_from_single_rg_resource(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_resource_group",
                    name="res_0",
                    attributes={"name": "rg-example-app-test"},
                ),
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={
                        "location": "westeurope",
                        "resource_group_name": "azurerm_resource_group.res_0.name",
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        resource_group_var = next(
            var
            for var in result.extracted_variables
            if var.name == "resource_group_name"
        )
        assert resource_group_var.default == "rg-example-app-test"

    def test_build_category_call_params_infers_rg_literal_from_single_rg_resource(
        self, transformer: TerraformTransformer
    ) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_resource_group",
                name="res_0",
                attributes={"name": "rg-app-test"},
            ),
            TerraformResource(
                resource_type="azurerm_storage_account",
                name="storage1",
                attributes={
                    "location": "westeurope",
                    "resource_group_name": "${azurerm_resource_group.res_0.name}",
                },
            ),
        ]

        params = transformer._build_category_call_params(resources)
        assert params["storage"]["resource_group_name"] == "rg-app-test"

    def test_warns_on_sensitive_attributes(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={
                        "primary_access_key": "secret123",
                    },
                ),
            ]
        )
        result = transformer.transform(state)
        assert any("primary_access_key" in w for w in result.warnings)

    def test_sanitize_api_management_backend_removes_empty_tls(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_api_management_backend",
                    name="backend1",
                    attributes={
                        "name": "backend1",
                        "resource_group_name": "rg1",
                        "api_management_name": "apim1",
                        "protocol": "http",
                        "url": "https://example.com",
                        "tls": {},
                    },
                ),
            ]
        )
        result = transformer.transform(state)
        backend = next(
            r for r in result.state.resources if r.resource_type == "azurerm_api_management_backend"
        )
        assert "tls" not in backend.attributes

    def test_sanitize_api_management_named_value_sets_value_placeholder(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_api_management_named_value",
                    name="named1",
                    attributes={
                        "name": "named1",
                        "resource_group_name": "rg1",
                        "api_management_name": "apim1",
                        "display_name": "named1",
                        "secret": True,
                    },
                ),
            ]
        )
        result = transformer.transform(state)
        named = next(
            r for r in result.state.resources if r.resource_type == "azurerm_api_management_named_value"
        )
        assert named.attributes["value"] == 'var.api_management_named_values["named1"].value'
        other_module = next(m for m in result.modules if m.name == "other")
        map_name = other_module.resource_type_vars["azurerm_api_management_named_value"]
        assert other_module.call_params[map_name]["named1"]["value"] == "__import_only__"

    def test_log_analytics_custom_log_is_excluded_from_management(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_log_analytics_workspace_table_custom_log",
                    name="table1",
                    attributes={
                        "name": "Table_CL",
                        "display_name": "Table",
                        "workspace_id": "azurerm_log_analytics_workspace.ws1.id",
                    },
                ),
            ]
        )
        result = transformer.transform(state)
        assert all(
            r.resource_type != "azurerm_log_analytics_workspace_table_custom_log"
            for r in result.state.resources
        )

    def test_skipped_logger_drops_unmapped_import_target(
        self, transformer: TerraformTransformer
    ) -> None:
        logger_id = (
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/"
            "service/apim/loggers/ExampleLogger"
        )
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_api_management_logger",
                    name="examplelogger",
                    attributes={
                        "name": "ExampleLogger",
                        "resource_group_name": "rg",
                        "api_management_name": "apim",
                        "eventhub": [{"name": "eventhub-example"}],
                    },
                    azure_resource_id=logger_id,
                ),
            ],
            import_blocks=[
                ImportBlock(
                    id=logger_id,
                    to="azurerm_api_management_logger.examplelogger",
                )
            ],
        )
        result = transformer.transform(state)
        assert result.rewritten_imports == []

    def test_sanitize_api_management_logger_skips_incomplete_eventhub_logger(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_api_management_logger",
                    name="examplelogger",
                    attributes={
                        "name": "ExampleLogger",
                        "resource_group_name": "rg1",
                        "api_management_name": "apim1",
                        "eventhub": [{"name": "eventhub-example"}],
                    },
                ),
            ]
        )
        result = transformer.transform(state)
        assert all(
            r.resource_type != "azurerm_api_management_logger" for r in result.state.resources
        )

    def test_windows_function_app_strips_empty_site_config_default_actions(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_windows_function_app",
                    name="func1",
                    attributes={
                        "name": "func1",
                        "resource_group_name": "rg1",
                        "location": "westeurope",
                        "service_plan_id": "sp1",
                        "storage_account_name": "st1",
                        "storage_account_access_key": "key",
                        "site_config": [
                            {
                                "ip_restriction_default_action": "",
                                "scm_ip_restriction_default_action": "",
                                "ftps_state": "FtpsOnly",
                            }
                        ],
                    },
                ),
            ]
        )
        result = transformer.transform(state)
        app = next(r for r in result.state.resources if r.resource_type == "azurerm_windows_function_app")
        site_config = app.attributes["site_config"][0]
        assert "ip_restriction_default_action" not in site_config
        assert "scm_ip_restriction_default_action" not in site_config

    def test_normalize_resource_name_snake_case(self, transformer: TerraformTransformer) -> None:
        name = transformer._normalize_resource_name(
            "My-Resource-Name", "azurerm_resource_group", {}
        )
        assert name == "my_resource_name"

    def test_normalize_resource_name_from_azure_name(
        self, transformer: TerraformTransformer
    ) -> None:
        name = transformer._normalize_resource_name(
            "res-0", "azurerm_resource_group", {"name": "rg-my-app"}
        )
        assert name == "my_app"

    def test_normalize_resource_name_from_descriptive_attr(
        self, transformer: TerraformTransformer
    ) -> None:
        name = transformer._normalize_resource_name(
            "res-53",
            "azurerm_api_management_api_operation",
            {"operation_id": "status-update"},
        )
        assert name == "status_update"

    def test_normalize_resource_name_uses_type_fallback_for_generated_name(
        self, transformer: TerraformTransformer
    ) -> None:
        name = transformer._normalize_resource_name("res-0", "azurerm_resource_group", {})
        assert name == "resource_group_0"


class TestCategoryModuleFeatures:
    @pytest.fixture
    def transformer(self) -> TerraformTransformer:
        config = ExportConfig(
            resource_groups=["test-rg"],
            output_dir=Path("/tmp/output"),
        )
        return TerraformTransformer(config)

    def test_string_hoisting_creates_per_type_maps(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "mystorageacct", "location": "eastus"},
                ),
            ]
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        assert "azurerm_storage_account" in storage_module.resource_type_vars
        map_name = storage_module.resource_type_vars["azurerm_storage_account"]
        assert map_name in storage_module.call_params

    def test_defaults_extraction_for_common_values(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={
                        "name": "storage1",
                        "location": "eastus",
                        "account_tier": "Standard",
                    },
                ),
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage2",
                    attributes={
                        "name": "storage2",
                        "location": "eastus",
                        "account_tier": "Standard",
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        var_names = [v.name for v in storage_module.variables]
        map_name = storage_module.resource_type_vars["azurerm_storage_account"]
        defaults_var_name = f"{map_name}_defaults"
        assert defaults_var_name in var_names

    def test_typed_object_shapes_in_map_variables(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "storage1", "sku_name": "Standard_LRS"},
                ),
            ]
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        map_var = next(
            v
            for v in storage_module.variables
            if v.name == storage_module.resource_type_vars["azurerm_storage_account"]
        )
        assert "map(" in map_var.var_type
        assert "object(" in map_var.var_type
        assert "optional(" in map_var.var_type

    def test_reference_rewriting_for_foreach(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "mystorageacct", "location": "eastus"},
                ),
                TerraformResource(
                    resource_type="azurerm_storage_container",
                    name="container1",
                    attributes={
                        "name": "data",
                        "storage_account_id": "azurerm_storage_account.storage1.id",
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        container = next(
            r for r in storage_module.resources if r.resource_type == "azurerm_storage_container"
        )
        storage_ref = container.attributes.get("storage_account_id", "")
        assert "azurerm_storage_account.this[var.storage_containers" in storage_ref
        map_name = storage_module.resource_type_vars["azurerm_storage_container"]
        assert storage_module.call_params[map_name]["container1"]["storage_account_id"] == "storage1"

    def test_api_operation_tag_rewrites_policy_id_reference_to_operation(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_api_management_api_operation",
                    name="res-53",
                    attributes={
                        "resource_group_name": "rg1",
                        "api_management_name": "apim1",
                        "api_name": "sample-api",
                        "operation_id": "status-update",
                        "display_name": "status-update",
                        "method": "POST",
                        "url_template": "/status-update",
                    },
                ),
                TerraformResource(
                    resource_type="azurerm_api_management_api_operation_policy",
                    name="res-54",
                    attributes={
                        "resource_group_name": "rg1",
                        "api_management_name": "apim1",
                        "api_name": "sample-api",
                        "operation_id": "status-update",
                    },
                ),
                TerraformResource(
                    resource_type="azurerm_api_management_api_operation_tag",
                    name="sample_ops_tag_5",
                    attributes={
                        "name": "SampleOps",
                        "api_operation_id": "azurerm_api_management_api_operation_policy.res-54.id",
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        other_module = next(m for m in result.modules if m.name == "other")
        tag_resource = next(
            r
            for r in other_module.resources
            if r.resource_type == "azurerm_api_management_api_operation_tag"
        )
        assert "azurerm_api_management_api_operation.this[" in tag_resource.attributes[
            "api_operation_id"
        ]
        map_name = other_module.resource_type_vars["azurerm_api_management_api_operation_tag"]
        assert (
            other_module.call_params[map_name]["sample_ops_tag_5"]["api_operation_id"]
            == "status_update"
        )

    def test_arm_id_rewritten_to_resource_reference(self, transformer: TerraformTransformer) -> None:
        storage_account_id = (
            "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/"
            "storageAccounts/stacmeaccount"
        )
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "stacmeaccount"},
                    azure_resource_id=storage_account_id,
                ),
                TerraformResource(
                    resource_type="azurerm_storage_container",
                    name="container1",
                    attributes={
                        "name": "examplecontainer",
                        "storage_account_id": storage_account_id,
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        container = next(
            r for r in storage_module.resources if r.resource_type == "azurerm_storage_container"
        )
        storage_ref = container.attributes.get("storage_account_id", "")
        assert storage_ref == (
            'azurerm_storage_account.this[var.storage_containers["container1"].'
            "storage_account_id].id"
        )
        map_name = storage_module.resource_type_vars["azurerm_storage_container"]
        assert storage_module.call_params[map_name]["container1"]["storage_account_id"] == "storage1"

    def test_duplicate_azure_id_does_not_override_original_owner(
        self, transformer: TerraformTransformer
    ) -> None:
        storage_account_id = (
            "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/"
            "storageAccounts/stacmeaccount"
        )
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "stacmeaccount"},
                    azure_resource_id=storage_account_id,
                ),
                TerraformResource(
                    resource_type="azurerm_storage_container",
                    name="examplecontainer",
                    attributes={
                        "name": "examplecontainer",
                        "storage_account_id": storage_account_id,
                    },
                    # Simulates parser fallback extracting a parent ID from attributes.
                    azure_resource_id=storage_account_id,
                ),
            ]
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        container = next(
            r
            for r in storage_module.resources
            if r.resource_type == "azurerm_storage_container"
            and r.name == "examplecontainer"
        )
        storage_ref = container.attributes.get("storage_account_id", "")
        assert storage_ref == (
            'azurerm_storage_account.this[var.storage_containers["examplecontainer"].'
            "storage_account_id].id"
        )
        map_name = storage_module.resource_type_vars["azurerm_storage_container"]
        assert (
            storage_module.call_params[map_name]["examplecontainer"]["storage_account_id"]
            == "storage1"
        )

    def test_duplicate_azure_id_prefers_best_name_match_even_if_ordered_late(
        self, transformer: TerraformTransformer
    ) -> None:
        storage_account_id = (
            "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/"
            "storageAccounts/stacmeaccount"
        )
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_container",
                    name="examplecontainer",
                    attributes={
                        "name": "examplecontainer",
                        "storage_account_id": storage_account_id,
                    },
                    azure_resource_id=storage_account_id,
                ),
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "stacmeaccount"},
                    azure_resource_id=storage_account_id,
                ),
            ]
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        container = next(
            r
            for r in storage_module.resources
            if r.resource_type == "azurerm_storage_container"
            and r.name == "examplecontainer"
        )
        storage_ref = container.attributes.get("storage_account_id", "")
        assert storage_ref == (
            'azurerm_storage_account.this[var.storage_containers["examplecontainer"].'
            "storage_account_id].id"
        )
        map_name = storage_module.resource_type_vars["azurerm_storage_container"]
        assert (
            storage_module.call_params[map_name]["examplecontainer"]["storage_account_id"]
            == "storage1"
        )

    def test_import_blocks_define_azure_id_owner_for_reference_rewrite(
        self, transformer: TerraformTransformer
    ) -> None:
        storage_account_id = (
            "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/"
            "storageAccounts/stacmeaccount"
        )
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="res-1",
                    attributes={"name": "stacmeaccount"},
                    azure_resource_id=None,
                ),
                TerraformResource(
                    resource_type="azurerm_storage_container",
                    name="res-2",
                    attributes={
                        "name": "examplecontainer",
                        "storage_account_id": storage_account_id,
                    },
                    # Simulates parser extracting parent ID from child attributes.
                    azure_resource_id=storage_account_id,
                ),
            ],
            import_blocks=[
                ImportBlock(
                    id=storage_account_id,
                    to="azurerm_storage_account.res-1",
                ),
                ImportBlock(
                    id=f"{storage_account_id}/blobServices/default/containers/examplecontainer",
                    to="azurerm_storage_container.res-2",
                ),
            ],
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        container = next(
            r
            for r in storage_module.resources
            if r.resource_type == "azurerm_storage_container"
            and r.name == "examplecontainer"
        )
        storage_ref = container.attributes.get("storage_account_id", "")
        assert storage_ref == (
            'azurerm_storage_account.this[var.storage_containers["examplecontainer"].'
            "storage_account_id].id"
        )
        map_name = storage_module.resource_type_vars["azurerm_storage_container"]
        assert (
            storage_module.call_params[map_name]["examplecontainer"]["storage_account_id"]
            == "stacmeaccount"
        )

    def test_id_key_prefers_matching_resource_type_when_id_is_shared(
        self, transformer: TerraformTransformer
    ) -> None:
        storage_account_id = (
            "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/"
            "storageAccounts/stacmeaccount"
        )
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="stacmeaccount",
                    attributes={"name": "stacmeaccount"},
                    azure_resource_id=None,
                ),
                TerraformResource(
                    resource_type="azurerm_storage_account_queue_properties",
                    name="res-34",
                    attributes={
                        "storage_account_id": storage_account_id,
                        "hour_metrics": [{"version": "1.0"}],
                    },
                    azure_resource_id=storage_account_id,
                ),
                TerraformResource(
                    resource_type="azurerm_storage_container",
                    name="examplecontainer",
                    attributes={
                        "name": "examplecontainer",
                        "storage_account_id": storage_account_id,
                    },
                ),
            ],
            import_blocks=[
                ImportBlock(
                    id=storage_account_id,
                    to="azurerm_storage_account.stacmeaccount",
                ),
                ImportBlock(
                    id=storage_account_id,
                    to="azurerm_storage_account_queue_properties.res-34",
                ),
            ],
        )
        result = transformer.transform(state)

        storage_module = next(m for m in result.modules if m.name == "storage")
        container = next(
            r
            for r in storage_module.resources
            if r.resource_type == "azurerm_storage_container"
            and r.name == "examplecontainer"
        )
        storage_ref = container.attributes.get("storage_account_id", "")
        assert storage_ref == (
            'azurerm_storage_account.this[var.storage_containers["examplecontainer"].'
            "storage_account_id].id"
        )
        map_name = storage_module.resource_type_vars["azurerm_storage_container"]
        assert (
            storage_module.call_params[map_name]["examplecontainer"]["storage_account_id"]
            == "stacmeaccount"
        )

    def test_key_vault_secret_keeps_import_only_attributes(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_key_vault",
                    name="kv1",
                    attributes={"name": "kv-auto-certs-001", "location": "eastus"},
                ),
                TerraformResource(
                    resource_type="azurerm_key_vault_secret",
                    name="secret1",
                    attributes={
                        "name": "acme-account-key",
                        "key_vault_id": "azurerm_key_vault.kv1.id",
                        "value": "super-secret-value",
                        "content_type": "application/x-pem-file",
                        "not_before_date": "2026-02-15T00:00:00Z",
                        "expiration_date": "2027-02-15T00:00:00Z",
                        "tags": {"file-encoding": "utf-8"},
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        security_module = next(m for m in result.modules if m.name == "security")
        secret = next(
            r for r in security_module.resources if r.resource_type == "azurerm_key_vault_secret"
        )
        assert sorted(secret.attributes.keys()) == [
            "content_type",
            "expiration_date",
            "key_vault_id",
            "name",
            "not_before_date",
            "tags",
            "value",
        ]
        assert secret.attributes["value"] == 'var.key_vault_secrets["secret1"].value'
        assert secret.attributes["tags"] == {'file-encoding': 'var.key_vault_secrets["secret1"].tags["file-encoding"]'}
        assert (
            secret.attributes["content_type"]
            == 'var.key_vault_secrets["secret1"].content_type'
        )
        assert (
            secret.attributes["not_before_date"]
            == 'var.key_vault_secrets["secret1"].not_before_date'
        )
        assert (
            secret.attributes["expiration_date"]
            == 'var.key_vault_secrets["secret1"].expiration_date'
        )

        secret_map_name = security_module.resource_type_vars["azurerm_key_vault_secret"]
        secret_params = security_module.call_params[secret_map_name]["secret1"]
        assert sorted(secret_params.keys()) == [
            "content_type",
            "expiration_date",
            "key_vault_id",
            "name",
            "not_before_date",
            "tags",
            "value",
        ]
        assert secret_params["value"] == "__import_only__"
        assert secret_params["key_vault_id"] == "kv1"
        assert secret_params["tags"] == {"file-encoding": "utf-8"}
        assert secret_params["content_type"] == "application/x-pem-file"
        assert secret_params["not_before_date"] == "2026-02-15T00:00:00Z"
        assert secret_params["expiration_date"] == "2027-02-15T00:00:00Z"


class TestImportBlockRewriting:
    @pytest.fixture
    def transformer(self) -> TerraformTransformer:
        config = ExportConfig(
            resource_groups=["test-rg"],
            output_dir=Path("/tmp/output"),
        )
        return TerraformTransformer(config)

    def test_address_mapping_flat_to_module(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "mystorageacct"},
                ),
            ]
        )
        result = transformer.transform(state)

        assert "azurerm_storage_account.storage1" in result.address_mapping
        new_addr = result.address_mapping["azurerm_storage_account.storage1"]
        assert new_addr == 'module.storage.azurerm_storage_account.this["storage1"]'

    def test_import_blocks_rewritten_to_module_addresses(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "mystorageacct"},
                ),
            ],
            import_blocks=[
                ImportBlock(
                    id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorageacct",
                    to="azurerm_storage_account.storage1",
                ),
            ],
        )
        result = transformer.transform(state)

        assert len(result.rewritten_imports) == 1
        rewritten = result.rewritten_imports[0]
        assert rewritten.id.startswith("/subscriptions/")
        assert rewritten.to == 'module.storage.azurerm_storage_account.this["storage1"]'

    def test_multiple_resources_address_mapping(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "storage1"},
                ),
                TerraformResource(
                    resource_type="azurerm_key_vault",
                    name="kv1",
                    attributes={"name": "mykv"},
                ),
            ],
            import_blocks=[
                ImportBlock(id="storage-id", to="azurerm_storage_account.storage1"),
                ImportBlock(id="kv-id", to="azurerm_key_vault.kv1"),
            ],
        )
        result = transformer.transform(state)

        assert len(result.rewritten_imports) == 2
        storage_import = next(i for i in result.rewritten_imports if i.id == "storage-id")
        kv_import = next(i for i in result.rewritten_imports if i.id == "kv-id")

        assert storage_import.to == 'module.storage.azurerm_storage_account.this["storage1"]'
        assert kv_import.to == 'module.security.azurerm_key_vault.this["kv1"]'

    def test_unresolved_import_target_is_dropped(self, transformer: TerraformTransformer) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "storage1"},
                ),
            ],
            import_blocks=[
                ImportBlock(
                    id="missing-id",
                    to="azurerm_storage_container.res-9999",
                ),
                ImportBlock(
                    id="storage-id",
                    to="azurerm_storage_account.storage1",
                ),
            ],
        )
        result = transformer.transform(state)
        assert len(result.rewritten_imports) == 1
        assert result.rewritten_imports[0].id == "storage-id"

    def test_excluded_azure_managed_resource_is_not_managed_or_imported(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_log_analytics_workspace_table_custom_log",
                    name="azuredevopsauditing",
                    attributes={
                        "name": "AzureDevOpsAuditing_CL",
                        "workspace_id": "azurerm_log_analytics_workspace.ws.id",
                    },
                ),
                TerraformResource(
                    resource_type="azurerm_log_analytics_workspace",
                    name="ws",
                    attributes={"name": "log-workspace", "location": "westeurope"},
                ),
            ],
            import_blocks=[
                ImportBlock(
                    id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/log-workspace/tables/AzureDevOpsAuditing_CL",
                    to="azurerm_log_analytics_workspace_table_custom_log.azuredevopsauditing",
                ),
                ImportBlock(
                    id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/log-workspace",
                    to="azurerm_log_analytics_workspace.ws",
                ),
            ],
        )

        result = transformer.transform(state)
        managed_types = {resource.resource_type for resource in result.state.resources}
        assert "azurerm_log_analytics_workspace_table_custom_log" not in managed_types
        assert all(
            "workspace_table_custom_log" not in block.to for block in result.rewritten_imports
        )


class TestTypeInference:
    @pytest.fixture
    def transformer(self) -> TerraformTransformer:
        config = ExportConfig(
            resource_groups=["test-rg"],
            output_dir=Path("/tmp/output"),
        )
        return TerraformTransformer(config)

    def test_type_node_with_invalid_object_keys_falls_back_to_map_any(
        self, transformer: TerraformTransformer
    ) -> None:
        node = {
            "kind": "object",
            "fields": {
                "Custom:ApiKey": {"kind": "string"},
                "normal_key": {"kind": "string"},
            },
        }

        result = transformer._type_node_to_hcl(node)
        assert result == "map(any)"

    def test_embedded_interpolation_reference_is_kept_in_module_not_hoisted(
        self, transformer: TerraformTransformer
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_function_app_function",
                    name="func1",
                    attributes={
                        "name": "func1",
                        "function_app_id": "some-id",
                    },
                ),
                TerraformResource(
                    resource_type="azurerm_logic_app_action_custom",
                    name="action1",
                    attributes={
                        "name": "action1",
                        "body": '{"function": {"id": "${azurerm_function_app_function.func1.id}"}}',
                    },
                ),
            ]
        )

        result = transformer.transform(state)
        other_module = next(m for m in result.modules if m.name == "web")
        function = next(
            r
            for r in other_module.resources
            if r.resource_type == "azurerm_function_app_function"
        )
        assert function is not None
        action = next(
            r
            for r in other_module.resources
            if r.resource_type == "azurerm_logic_app_action_custom"
        )
        body = action.attributes.get("body", "")
        assert 'azurerm_function_app_function.this["func1"].id' in body
        map_name = other_module.resource_type_vars["azurerm_logic_app_action_custom"]
        assert "body" not in other_module.call_params[map_name]["action1"]
