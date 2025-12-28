from pathlib import Path

import pytest

from infra_export_kit.models import ExportConfig


@pytest.fixture
def config() -> ExportConfig:
    return ExportConfig(
        resource_groups=["test-rg"],
        output_dir=Path("/tmp/test-output"),
    )


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    output_dir = tmp_path / "terraform-output"
    output_dir.mkdir()
    return output_dir
