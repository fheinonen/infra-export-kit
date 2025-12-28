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

    def test_normalize_resource_name_preserves_res_pattern_without_name_attr(
        self, transformer: TerraformTransformer
    ) -> None:
        name = transformer._normalize_resource_name("res-0", "azurerm_resource_group", {})
        assert name == "res-0"


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
        assert 'this["storage1"]' in storage_ref


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
