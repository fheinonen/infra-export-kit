from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from infra_export_kit.models import ExportConfig, TerraformResource, TerraformState
from infra_export_kit.transformer import TerraformTransformer
from infra_export_kit.writer import TerraformWriter


class TestTerraformWriter:
    @pytest.fixture
    def config(self) -> ExportConfig:
        return ExportConfig(
            resource_groups=["test-rg"],
            output_dir=Path("/tmp/output"),
        )

    @pytest.fixture
    def transformer(self, config: ExportConfig) -> TerraformTransformer:
        return TerraformTransformer(config)

    @pytest.fixture
    def writer(self, config: ExportConfig) -> TerraformWriter:
        return TerraformWriter(config)

    def test_category_module_import_uses_foreach_address(
        self, transformer: TerraformTransformer, writer: TerraformWriter
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "mystorageacct"},
                    azure_resource_id="/subscriptions/sub/providers/Microsoft.Storage/storageAccounts/mystorageacct",
                ),
            ]
        )
        result = transformer.transform(state)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            writer.write(result, output_dir)

            imports_content = (output_dir / "imports.tf").read_text()
            assert 'module.storage.azurerm_storage_account.this["storage1"]' in imports_content

    def test_module_calls_include_per_type_maps(
        self, transformer: TerraformTransformer, writer: TerraformWriter
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_key_vault",
                    name="kv1",
                    attributes={"name": "mykv", "location": "eastus"},
                ),
            ]
        )
        result = transformer.transform(state)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            writer.write(result, output_dir)

            modules_content = (output_dir / "modules.tf").read_text()
            assert "key_vaults" in modules_content or "key_vault" in modules_content

    def test_category_module_main_uses_foreach(
        self, transformer: TerraformTransformer, writer: TerraformWriter
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "storage1", "location": "eastus"},
                ),
            ]
        )
        result = transformer.transform(state)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            writer.write(result, output_dir)

            main_content = (output_dir / "modules" / "storage" / "main.tf").read_text()
            assert "for_each" in main_content
            assert 'resource "azurerm_storage_account" "this"' in main_content

    def test_module_variables_have_typed_shapes(
        self, transformer: TerraformTransformer, writer: TerraformWriter
    ) -> None:
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

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            writer.write(result, output_dir)

            vars_content = (output_dir / "modules" / "storage" / "variables.tf").read_text()
            assert "object(" in vars_content
            assert "optional(" in vars_content

    def test_each_value_references_in_module(
        self, transformer: TerraformTransformer, writer: TerraformWriter
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_storage_account",
                    name="storage1",
                    attributes={"name": "mystorageacct", "sku_name": "Standard_LRS"},
                ),
            ]
        )
        result = transformer.transform(state)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            writer.write(result, output_dir)

            main_content = (output_dir / "modules" / "storage" / "main.tf").read_text()
            assert "each.value" in main_content

    def test_key_vault_secret_lifecycle_does_not_ignore_tags(
        self, transformer: TerraformTransformer, writer: TerraformWriter
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_key_vault",
                    name="kv1",
                    attributes={
                        "name": "kv-auto-certs-001",
                        "location": "eastus",
                        "resource_group_name": "rg1",
                    },
                ),
                TerraformResource(
                    resource_type="azurerm_key_vault_secret",
                    name="secret1",
                    attributes={
                        "name": "acme-fheinonen-eu-ca",
                        "key_vault_id": "azurerm_key_vault.kv1.id",
                        "value": "placeholder",
                        "tags": {"file-encoding": "utf-8"},
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            writer.write(result, output_dir)

            main_content = (output_dir / "modules" / "security" / "main.tf").read_text()
            assert "ignore_changes = [value, value_wo, value_wo_version]" in main_content
            assert "tags = {" in main_content
            assert 'each.value.tags["file-encoding"]' in main_content
