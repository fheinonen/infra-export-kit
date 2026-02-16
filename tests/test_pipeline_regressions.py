from __future__ import annotations

from pathlib import Path

from infra_export_kit.models import ExportConfig
from infra_export_kit.parser import TerraformParser
from infra_export_kit.transformer import TerraformTransformer
from infra_export_kit.writer import TerraformWriter

MOCK_MAIN_TF = """
resource "azurerm_storage_account" "stacmeaccount" {
  name                     = "stacmeaccount"
  resource_group_name      = "rg-certificate-renewal"
  location                 = "swedencentral"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "examplecontainer" {
  name               = "examplecontainer"
  storage_account_id = "/subscriptions/sub-id/resourceGroups/rg-certificate-renewal/providers/Microsoft.Storage/storageAccounts/stacmeaccount"
}

resource "azurerm_storage_account_queue_properties" "res34" {
  storage_account_id = "/subscriptions/sub-id/resourceGroups/rg-certificate-renewal/providers/Microsoft.Storage/storageAccounts/stacmeaccount"
  hour_metrics {
    version = "1.0"
  }
  logging {
    delete  = false
    read    = false
    version = "1.0"
    write   = false
  }
  minute_metrics {
    version = "1.0"
  }
}

resource "azurerm_key_vault" "auto_certs_001" {
  name                = "kv-auto-certs-001"
  location            = "swedencentral"
  resource_group_name = "rg-certificate-renewal"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
}

resource "azurerm_key_vault_secret" "example_secret" {
  name            = "example-secret"
  key_vault_id    = azurerm_key_vault.auto_certs_001.id
  content_type    = "application/x-pem-file"
  not_before_date = "2026-02-15T00:00:00Z"
  expiration_date = "2027-02-15T00:00:00Z"
  value           = "very-secret-value"
  tags = {
    file-encoding = "utf-8"
  }
}
"""

MOCK_IMPORT_TF = """
import {
  id = "/subscriptions/sub-id/resourceGroups/rg-certificate-renewal/providers/Microsoft.Storage/storageAccounts/stacmeaccount"
  to = azurerm_storage_account.stacmeaccount
}

import {
  id = "/subscriptions/sub-id/resourceGroups/rg-certificate-renewal/providers/Microsoft.Storage/storageAccounts/stacmeaccount/blobServices/default/containers/examplecontainer"
  to = azurerm_storage_container.examplecontainer
}

import {
  id = "/subscriptions/sub-id/resourceGroups/rg-certificate-renewal/providers/Microsoft.Storage/storageAccounts/stacmeaccount"
  to = azurerm_storage_account_queue_properties.res34
}

import {
  id = "/subscriptions/sub-id/resourceGroups/rg-certificate-renewal/providers/Microsoft.KeyVault/vaults/kv-auto-certs-001/secrets/example-secret/00000000000000000000000000000000"
  to = azurerm_key_vault_secret.example_secret
}
"""


def _run_pipeline(input_dir: Path, output_dir: Path) -> None:
    parser = TerraformParser()
    state = parser.parse_directory(input_dir)
    config = ExportConfig(
        resource_groups=["test-rg"],
        output_dir=output_dir,
        use_modules=True,
        extract_variables=True,
        group_by_category=True,
    )
    transformer = TerraformTransformer(config)
    result = transformer.transform(state)
    writer = TerraformWriter(config)
    writer.write(result, output_dir)


def test_pipeline_rewrites_shared_storage_id_to_storage_account(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    (input_dir / "main.tf").write_text(MOCK_MAIN_TF)
    (input_dir / "import.tf").write_text(MOCK_IMPORT_TF)

    _run_pipeline(input_dir, output_dir)

    storage_main = (output_dir / "modules" / "storage" / "main.tf").read_text()
    assert (
        "storage_account_id = try(each.value.storage_account_id, null) != null ? "
        "azurerm_storage_account.this[each.value.storage_account_id].id : null"
    ) in storage_main
    assert 'azurerm_storage_container.this["examplecontainer"].id' not in storage_main
    modules_tf = (output_dir / "modules.tf").read_text()
    assert 'storage_account_id = "stacmeaccount"' in modules_tf


def test_pipeline_key_vault_secret_keeps_metadata_and_provider_required_value(
    tmp_path: Path,
) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    (input_dir / "main.tf").write_text(MOCK_MAIN_TF)
    (input_dir / "import.tf").write_text(MOCK_IMPORT_TF)

    _run_pipeline(input_dir, output_dir)

    security_main = (output_dir / "modules" / "security" / "main.tf").read_text()
    modules_tf = (output_dir / "modules.tf").read_text()

    assert 'resource "azurerm_key_vault_secret" "this"' in security_main
    assert "content_type = each.value.content_type" in security_main
    assert "not_before_date = each.value.not_before_date" in security_main
    assert "expiration_date = each.value.expiration_date" in security_main
    assert "tags = {" in security_main
    assert "value = each.value.value" in security_main
    assert "ignore_changes = [value, value_wo, value_wo_version]" in security_main

    assert "key_vault_secrets = {" in modules_tf
    assert 'content_type = "application/x-pem-file"' in modules_tf
    assert 'not_before_date = "2026-02-15T00:00:00Z"' in modules_tf
    assert 'expiration_date = "2027-02-15T00:00:00Z"' in modules_tf
