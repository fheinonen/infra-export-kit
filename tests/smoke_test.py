#!/usr/bin/env python3
"""
Full smoke test for infra-export-kit pipeline.

This test simulates the full export workflow:
1. Creates mock .tf files (like aztfexport would produce)
2. Parses them with TerraformParser
3. Transforms with TerraformTransformer (including module detection)
4. Writes output with TerraformWriter
5. Verifies output structure and content
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from infra_export_kit.models import ExportConfig
from infra_export_kit.parser import TerraformParser
from infra_export_kit.transformer import TerraformTransformer
from infra_export_kit.writer import TerraformWriter

MOCK_MAIN_TF = """
resource "azurerm_resource_group" "rg1" {
  name     = "test-resource-group"
  location = "eastus"
  tags = {
    Environment = "Production"
    Project     = "TestProject"
  }
}

resource "azurerm_virtual_network" "vnet1" {
  name                = "test-vnet"
  location            = "eastus"
  resource_group_name = "test-resource-group"
  address_space       = ["10.0.0.0/16"]
  tags = {
    Environment = "Production"
  }
}

resource "azurerm_subnet" "subnet1" {
  name                 = "default"
  resource_group_name  = "test-resource-group"
  virtual_network_name = "test-vnet"
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "subnet2" {
  name                 = "apps"
  resource_group_name  = "test-resource-group"
  virtual_network_name = "test-vnet"
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_security_group" "nsg1" {
  name                = "test-nsg"
  location            = "eastus"
  resource_group_name = "test-resource-group"
}

resource "azurerm_storage_account" "storage1" {
  name                     = "teststorageacct123"
  resource_group_name      = "test-resource-group"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags = {
    Environment = "Production"
  }
}

resource "azurerm_storage_container" "container1" {
  name                  = "data"
  storage_account_name  = "teststorageacct123"
  container_access_type = "private"
}

resource "azurerm_storage_container" "container2" {
  name                  = "logs"
  storage_account_name  = "teststorageacct123"
  container_access_type = "private"
}

resource "azurerm_key_vault" "kv1" {
  name                = "test-keyvault"
  location            = "eastus"
  resource_group_name = "test-resource-group"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
}

resource "azurerm_log_analytics_workspace" "law1" {
  name                = "test-law"
  location            = "eastus"
  resource_group_name = "test-resource-group"
  sku                 = "PerGB2018"
  retention_in_days   = 30
}
"""

MOCK_IMPORT_TF = """
import {
  id = "/subscriptions/xxx/resourceGroups/test-resource-group"
  to = azurerm_resource_group.rg1
}

import {
  id = "/subscriptions/xxx/resourceGroups/test-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet"
  to = azurerm_virtual_network.vnet1
}

import {
  id = "/subscriptions/xxx/resourceGroups/test-resource-group/providers/Microsoft.Storage/storageAccounts/teststorageacct123"
  to = azurerm_storage_account.storage1
}
"""


def run_smoke_test() -> None:
    print("=" * 60)
    print("Infra Export Kit - Full Smoke Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        mock_dir = Path(tmpdir) / "mock_aztfexport"
        mock_dir.mkdir()

        output_dir = Path(tmpdir) / "output"
        output_dir.mkdir()

        print("\n[1/5] Creating mock .tf files...")
        (mock_dir / "main.tf").write_text(MOCK_MAIN_TF)
        (mock_dir / "import.tf").write_text(MOCK_IMPORT_TF)
        print(f"  Created: {mock_dir}/main.tf")
        print(f"  Created: {mock_dir}/import.tf")

        print("\n[2/5] Parsing terraform files...")
        parser = TerraformParser()
        state = parser.parse_directory(mock_dir)
        print(f"  Parsed {len(state.resources)} resources")
        for r in state.resources:
            print(f"    - {r.address}")

        print("\n[3/5] Transforming with best practices...")
        config = ExportConfig(
            resource_groups=["test-rg"],
            output_dir=output_dir,
            use_modules=True,
            extract_variables=True,
            group_by_category=True,
        )
        transformer = TerraformTransformer(config)
        result = transformer.transform(state)

        print(f"  Extracted {len(result.extracted_variables)} variables:")
        for v in result.extracted_variables:
            print(f"    - {v.name}: {v.var_type}")

        print(f"  Detected {len(result.modules)} modules:")
        for m in result.modules:
            print(f"    - {m.name} ({m.module_type.value}): {len(m.resources)} resources")

        print(f"  Remaining resources: {len(result.remaining_resources)}")
        for r in result.remaining_resources:
            print(f"    - {r.address}")

        if result.warnings:
            print(f"  Warnings: {len(result.warnings)}")
            for w in result.warnings:
                print(f"    ! {w}")

        print("\n[4/5] Writing output files...")
        writer = TerraformWriter(config)
        tf_output = output_dir / "terraform"
        writer.write(result, tf_output)

        print("  Generated files:")
        for f in sorted(tf_output.rglob("*.tf")):
            rel_path = f.relative_to(tf_output)
            size = f.stat().st_size
            print(f"    - {rel_path} ({size} bytes)")

        print("\n[5/5] Verifying output structure...")
        errors = []

        expected_root_files = [
            "versions.tf",
            "provider.tf",
            "variables.tf",
            "locals.tf",
            "outputs.tf",
        ]
        for fname in expected_root_files:
            if not (tf_output / fname).exists():
                errors.append(f"Missing root file: {fname}")
            else:
                print(f"  ✓ {fname}")

        if result.modules:
            if not (tf_output / "modules.tf").exists():
                errors.append("Missing modules.tf with module calls")
            else:
                print("  ✓ modules.tf")

            modules_dir = tf_output / "modules"
            if not modules_dir.exists():
                errors.append("Missing modules/ directory")
            else:
                print("  ✓ modules/")
                for module in result.modules:
                    mod_dir = modules_dir / module.name
                    if not mod_dir.exists():
                        errors.append(f"Missing module directory: {module.name}")
                    else:
                        for mod_file in ["main.tf", "variables.tf", "outputs.tf"]:
                            if (mod_dir / mod_file).exists():
                                print(f"    ✓ {module.name}/{mod_file}")
                            elif mod_file == "outputs.tf" and not module.outputs:
                                print(f"    - {module.name}/{mod_file} (no outputs)")
                            else:
                                errors.append(f"Missing {module.name}/{mod_file}")

        if result.resources_by_category:
            for category in result.resources_by_category:
                cat_file = tf_output / f"{category.value}.tf"
                if cat_file.exists():
                    print(f"  ✓ {category.value}.tf")

        print("\n" + "=" * 60)
        if errors:
            print("SMOKE TEST FAILED")
            for e in errors:
                print(f"  ✗ {e}")
            raise SystemExit(1)
        else:
            print("SMOKE TEST PASSED")
            print(f"  Resources parsed: {len(state.resources)}")
            print(f"  Modules generated: {len(result.modules)}")
            print(f"  Variables extracted: {len(result.extracted_variables)}")
            print(f"  Output files: {len(list(tf_output.rglob('*.tf')))}")
        print("=" * 60)


if __name__ == "__main__":
    run_smoke_test()
