from __future__ import annotations

import pytest

from infra_export_kit.models import TerraformResource
from infra_export_kit.modules import (
    ModuleGenerator,
    ModuleType,
)


@pytest.fixture
def module_generator() -> ModuleGenerator:
    return ModuleGenerator()


class TestModuleGenerator:
    def test_detect_modules_empty_resources(self, module_generator: ModuleGenerator) -> None:
        modules = module_generator.detect_modules([])
        assert modules == []

    def test_detect_network_module(self, module_generator: ModuleGenerator) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_virtual_network",
                name="vnet1",
                attributes={"name": "main-vnet", "location": "eastus"},
            ),
            TerraformResource(
                resource_type="azurerm_subnet",
                name="subnet1",
                attributes={
                    "name": "default",
                    "virtual_network_name": "main-vnet",
                },
            ),
            TerraformResource(
                resource_type="azurerm_subnet",
                name="subnet2",
                attributes={
                    "name": "apps",
                    "virtual_network_name": "main-vnet",
                },
            ),
        ]
        modules = module_generator.detect_modules(resources)

        assert len(modules) == 1
        assert modules[0].module_type == ModuleType.NETWORK
        assert len(modules[0].resources) == 3
        assert modules[0].name == "network_main_vnet"

    def test_detect_storage_module(self, module_generator: ModuleGenerator) -> None:
        resources = [
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
                    "storage_account_name": "mystorageacct",
                },
            ),
        ]
        modules = module_generator.detect_modules(resources)

        assert len(modules) == 1
        assert modules[0].module_type == ModuleType.STORAGE
        assert len(modules[0].resources) == 2

    def test_single_resource_no_module(self, module_generator: ModuleGenerator) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_virtual_network",
                name="vnet1",
                attributes={"name": "standalone-vnet"},
            ),
        ]
        modules = module_generator.detect_modules(resources)
        assert modules == []

    def test_get_remaining_resources(self, module_generator: ModuleGenerator) -> None:
        vnet = TerraformResource(
            resource_type="azurerm_virtual_network",
            name="vnet1",
            attributes={"name": "main-vnet"},
        )
        subnet = TerraformResource(
            resource_type="azurerm_subnet",
            name="subnet1",
            attributes={"virtual_network_name": "main-vnet"},
        )
        standalone_rg = TerraformResource(
            resource_type="azurerm_resource_group",
            name="rg1",
            attributes={"name": "my-rg"},
        )

        all_resources = [vnet, subnet, standalone_rg]
        modules = module_generator.detect_modules(all_resources)
        remaining = module_generator.get_remaining_resources(all_resources, modules)

        assert len(remaining) == 1
        assert remaining[0].name == "rg1"

    def test_module_variables_generated(self, module_generator: ModuleGenerator) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_virtual_network",
                name="vnet1",
                attributes={
                    "name": "main-vnet",
                    "location": "eastus",
                    "resource_group_name": "my-rg",
                },
            ),
            TerraformResource(
                resource_type="azurerm_subnet",
                name="subnet1",
                attributes={"virtual_network_name": "main-vnet"},
            ),
        ]
        modules = module_generator.detect_modules(resources)

        assert len(modules) == 1
        var_names = [v.name for v in modules[0].variables]
        assert "location" in var_names
        assert "resource_group_name" in var_names
        assert "tags" in var_names

    def test_module_outputs_generated(self, module_generator: ModuleGenerator) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_virtual_network",
                name="vnet1",
                attributes={"name": "main-vnet"},
            ),
            TerraformResource(
                resource_type="azurerm_subnet",
                name="subnet1",
                attributes={"virtual_network_name": "main-vnet"},
            ),
        ]
        modules = module_generator.detect_modules(resources)

        assert len(modules) == 1
        output_names = [o.name for o in modules[0].outputs]
        assert "id" in output_names
        assert "name" in output_names
        assert "subnet_ids" in output_names

    def test_multiple_modules_detected(self, module_generator: ModuleGenerator) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_virtual_network",
                name="vnet1",
                attributes={"name": "vnet-a"},
            ),
            TerraformResource(
                resource_type="azurerm_subnet",
                name="subnet1",
                attributes={"virtual_network_name": "vnet-a"},
            ),
            TerraformResource(
                resource_type="azurerm_storage_account",
                name="storage1",
                attributes={"name": "storageacct"},
            ),
            TerraformResource(
                resource_type="azurerm_storage_container",
                name="container1",
                attributes={"storage_account_name": "storageacct"},
            ),
        ]
        modules = module_generator.detect_modules(resources)

        assert len(modules) == 2
        module_types = {m.module_type for m in modules}
        assert ModuleType.NETWORK in module_types
        assert ModuleType.STORAGE in module_types


class TestCategoryModuleGenerator:
    @pytest.fixture
    def module_generator(self) -> ModuleGenerator:
        return ModuleGenerator()

    def test_generate_category_modules_groups_by_category(
        self, module_generator: ModuleGenerator
    ) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_storage_account",
                name="storage1",
                attributes={"name": "storage1"},
            ),
            TerraformResource(
                resource_type="azurerm_storage_container",
                name="container1",
                attributes={"name": "container1"},
            ),
            TerraformResource(
                resource_type="azurerm_virtual_network",
                name="vnet1",
                attributes={"name": "vnet1"},
            ),
        ]
        modules = module_generator.generate_category_modules(resources)

        module_names = {m.name for m in modules}
        assert "storage" in module_names
        assert "network" in module_names

    def test_category_modules_include_all_resources_of_category(
        self, module_generator: ModuleGenerator
    ) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_storage_account",
                name="storage1",
                attributes={},
            ),
            TerraformResource(
                resource_type="azurerm_storage_account",
                name="storage2",
                attributes={},
            ),
            TerraformResource(
                resource_type="azurerm_storage_container",
                name="container1",
                attributes={},
            ),
        ]
        modules = module_generator.generate_category_modules(resources)

        storage_module = next(m for m in modules if m.name == "storage")
        assert len(storage_module.resources) == 3

    def test_storage_queue_properties_grouped_with_storage(
        self, module_generator: ModuleGenerator
    ) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_storage_account",
                name="storage1",
                attributes={},
            ),
            TerraformResource(
                resource_type="azurerm_storage_account_queue_properties",
                name="queue_props",
                attributes={},
            ),
        ]
        modules = module_generator.generate_category_modules(resources)

        storage_module = next(m for m in modules if m.name == "storage")
        resource_types = {r.resource_type for r in storage_module.resources}
        assert "azurerm_storage_account" in resource_types
        assert "azurerm_storage_account_queue_properties" in resource_types

    def test_dns_resources_grouped_with_network(self, module_generator: ModuleGenerator) -> None:
        resources = [
            TerraformResource(
                resource_type="azurerm_dns_zone",
                name="zone1",
                attributes={},
            ),
            TerraformResource(
                resource_type="azurerm_dns_a_record",
                name="record1",
                attributes={},
            ),
        ]
        modules = module_generator.generate_category_modules(resources)

        network_module = next(m for m in modules if m.name == "network")
        resource_types = {r.resource_type for r in network_module.resources}
        assert "azurerm_dns_zone" in resource_types
        assert "azurerm_dns_a_record" in resource_types
