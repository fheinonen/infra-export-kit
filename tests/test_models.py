from pathlib import Path

from infra_export_kit.models import (
    ExportConfig,
    ResourceCategory,
    TerraformResource,
    TerraformVariable,
)


class TestTerraformResource:
    def test_category_compute(self) -> None:
        resource = TerraformResource(
            resource_type="azurerm_linux_virtual_machine",
            name="vm1",
        )
        assert resource.category == ResourceCategory.COMPUTE

    def test_category_network(self) -> None:
        resource = TerraformResource(
            resource_type="azurerm_virtual_network",
            name="vnet1",
        )
        assert resource.category == ResourceCategory.NETWORK

    def test_category_unknown(self) -> None:
        resource = TerraformResource(
            resource_type="azurerm_unknown_resource",
            name="unknown",
        )
        assert resource.category == ResourceCategory.OTHER

    def test_category_storage_queue_properties(self) -> None:
        resource = TerraformResource(
            resource_type="azurerm_storage_account_queue_properties",
            name="queue_props",
        )
        assert resource.category == ResourceCategory.STORAGE

    def test_category_dns_resources(self) -> None:
        dns_types = [
            "azurerm_dns_zone",
            "azurerm_dns_a_record",
            "azurerm_dns_cname_record",
            "azurerm_private_dns_zone",
            "azurerm_private_dns_a_record",
            "azurerm_private_dns_zone_virtual_network_link",
        ]
        for dns_type in dns_types:
            resource = TerraformResource(resource_type=dns_type, name="test")
            assert resource.category == ResourceCategory.NETWORK, f"{dns_type} should be NETWORK"

    def test_address(self) -> None:
        resource = TerraformResource(
            resource_type="azurerm_resource_group",
            name="rg1",
        )
        assert resource.address == "azurerm_resource_group.rg1"


class TestTerraformVariable:
    def test_basic_variable(self) -> None:
        var = TerraformVariable(
            name="location",
            var_type="string",
            default="eastus",
            description="Azure region",
        )
        assert var.name == "location"
        assert var.default == "eastus"
        assert not var.sensitive


class TestExportConfig:
    def test_default_config(self) -> None:
        config = ExportConfig(
            resource_groups=["rg1", "rg2"],
            output_dir=Path("/tmp/output"),
        )
        assert config.use_modules is True
        assert config.extract_variables is True
        assert config.naming_convention == "snake_case"
        assert config.group_by_category is True
