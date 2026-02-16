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
                        "name": "example-secret",
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

    def test_map_attributes_render_with_assignment_and_quoted_keys(
        self, writer: TerraformWriter
    ) -> None:
        lines = writer._format_attribute(
            "app_settings",
            {
                "Custom:ApiKey": "secret",
                "normal_key": "value",
            },
            indent=1,
        )
        content = "\n".join(lines)
        assert "app_settings = {" in content
        assert '"Custom:ApiKey" = "secret"' in content

    def test_collapses_indexed_each_value_list_to_full_list_reference(
        self, writer: TerraformWriter
    ) -> None:
        lines = writer._format_attribute(
            "authorization_methods",
            [
                "each.value.authorization_methods[0]",
                "each.value.authorization_methods[1]",
            ],
            indent=1,
        )
        assert lines == ["  authorization_methods = each.value.authorization_methods"]

    def test_optional_nested_list_blocks_render_as_dynamic(
        self, writer: TerraformWriter
    ) -> None:
        lines = writer._format_attribute(
            "contact",
            [
                {
                    "email": "each.value.contact[0].email",
                }
            ],
            indent=1,
        )
        content = "\n".join(lines)
        assert 'dynamic "contact" {' in content
        assert "for_each = coalesce(try(each.value.contact, null), [])" in content
        assert "email = contact.value.email" in content

    def test_nested_dynamic_block_rewrites_parent_iterator_indexing(
        self, writer: TerraformWriter
    ) -> None:
        lines = writer._format_attribute(
            "representation",
            [
                {
                    "content_type": "response.value.representation[0].content_type",
                }
            ],
            indent=2,
        )
        content = "\n".join(lines)
        assert 'dynamic "representation" {' in content
        assert "for_each = coalesce(try(each.value.representation, null), [])" in content
        assert "content_type = representation.value.content_type" in content

    def test_replace_foreach_references_uses_try_for_indexed_access_without_defaults(
        self, writer: TerraformWriter
    ) -> None:
        value = 'var.logic_app_workflows["res_1"].workflow_parameters["service-endpoint-url"]'
        replaced = writer._replace_for_each_references(value, "logic_app_workflows")
        assert replaced == 'try(each.value.workflow_parameters["service-endpoint-url"], null)'

    def test_replace_foreach_references_uses_try_for_nested_dot_access_without_defaults(
        self, writer: TerraformWriter
    ) -> None:
        value = 'var.windows_function_apps["func1"].app_settings.ServiceTriggerSchedule'
        replaced = writer._replace_for_each_references(value, "windows_function_apps")
        assert replaced == "try(each.value.app_settings.ServiceTriggerSchedule, null)"

    def test_api_management_api_injects_display_name_and_protocols_fallbacks(
        self, transformer: TerraformTransformer, writer: TerraformWriter
    ) -> None:
        state = TerraformState(
            resources=[
                TerraformResource(
                    resource_type="azurerm_api_management_api",
                    name="sample_api",
                    attributes={
                        "name": "sample-api",
                        "resource_group_name": "rg1",
                        "api_management_name": "apim1",
                    },
                ),
            ]
        )
        result = transformer.transform(state)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            writer.write(result, output_dir)

            main_content = (output_dir / "modules" / "other" / "main.tf").read_text()
            assert "display_name = try(each.value.source_api_id, null) == null ?" in main_content
            assert "protocols = try(each.value.source_api_id, null) == null ?" in main_content

    def test_replace_foreach_references_wraps_nullable_resource_index_lookup(
        self, writer: TerraformWriter
    ) -> None:
        value = (
            'azurerm_application_insights.this[var.api_management_loggers["logger1"].resource_id].id'
        )
        replaced = writer._replace_for_each_references(value, "api_management_loggers")
        assert replaced == (
            "try(each.value.resource_id, null) != null ? "
            "azurerm_application_insights.this[each.value.resource_id].id : null"
        )

    def test_format_value_treats_jsonencode_as_expression(self, writer: TerraformWriter) -> None:
        value = 'jsonencode({"a":"b"})'
        assert writer._format_value(value) == value

    def test_monitor_smart_detector_injects_required_action_group_block(
        self, writer: TerraformWriter
    ) -> None:
        patched = writer._inject_resource_required_fallbacks(
            "azurerm_monitor_smart_detector_alert_rule",
            {"name": "rule1"},
            default_var_name="monitor_smart_detector_alert_rules_defaults",
        )
        assert isinstance(patched["action_group"], dict)
        assert "coalesce(" in patched["action_group"]["ids"]

    def test_format_value_quotes_jsonencode_when_function_calls_disallowed(
        self, writer: TerraformWriter
    ) -> None:
        value = 'jsonencode({"a":"b"})'
        assert writer._format_value(value, allow_function_calls=False) == '"{\\"a\\":\\"b\\"}"'

    def test_logic_app_action_custom_injects_required_body_fallback(
        self, writer: TerraformWriter
    ) -> None:
        patched = writer._inject_resource_required_fallbacks(
            "azurerm_logic_app_action_custom",
            {"name": "action1"},
        )
        assert patched["body"] == "coalesce(try(each.value.body, null), jsonencode({}))"
