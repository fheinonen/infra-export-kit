from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infra_export_kit.models import ExportConfig


class AztfExportError(Exception):
    pass


class AztfExportRunner:
    def __init__(self) -> None:
        self._aztfexport_path: str | None = None
        self._terraform_path: str | None = None

    def check_aztfexport_installed(self) -> bool:
        self._aztfexport_path = shutil.which("aztfexport")
        return self._aztfexport_path is not None

    def check_terraform_installed(self) -> bool:
        self._terraform_path = shutil.which("terraform")
        return self._terraform_path is not None

    def check_azure_cli_installed(self) -> bool:
        return shutil.which("az") is not None

    def get_aztfexport_version(self) -> str | None:
        if not self._aztfexport_path:
            return None
        try:
            result = subprocess.run(
                [self._aztfexport_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()
        except (subprocess.SubprocessError, OSError):
            return None

    def get_terraform_version(self) -> str | None:
        if not self._terraform_path:
            return None
        try:
            result = subprocess.run(
                [self._terraform_path, "version", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            data: dict[str, str] = json.loads(result.stdout)
            return data.get("terraform_version")
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
            return None

    def export_resource_group(
        self,
        resource_group: str,
        output_dir: Path,
        subscription_id: str | None = None,
    ) -> Path:
        if not self.check_aztfexport_installed():
            raise AztfExportError("aztfexport is not installed")

        output_dir.mkdir(parents=True, exist_ok=True)
        rg_output_dir = output_dir / resource_group

        rg_output_dir.mkdir(parents=True, exist_ok=True)

        # Build command with options BEFORE the resource group name
        cmd = [
            self._aztfexport_path or "aztfexport",
            "resource-group",
            "-o",
            str(rg_output_dir),
            "-n",  # non-interactive
            "--plain-ui",  # for non-TTY environments
            "--generate-import-block",
            "--hcl-only",
        ]

        if subscription_id:
            cmd.extend(["-s", subscription_id])

        # Resource group name must be last
        cmd.append(resource_group)

        # Set TMPDIR to output_dir so Terraform doesn't use /tmp (which may be tmpfs)
        # Use absolute path to ensure it works regardless of cwd
        env = os.environ.copy()
        env["TMPDIR"] = str(output_dir.resolve())

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                env=env,
            )
            if result.returncode != 0:
                raise AztfExportError(f"aztfexport failed: {result.stderr}")
        except subprocess.TimeoutExpired as e:
            raise AztfExportError("aztfexport timed out after 10 minutes") from e
        except OSError as e:
            raise AztfExportError(f"Failed to run aztfexport: {e}") from e

        return rg_output_dir

    def export_resource_groups(
        self,
        config: ExportConfig,
    ) -> dict[str, Path]:
        results: dict[str, Path] = {}

        temp_path = config.output_dir / ".aztfexport_temp"
        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            for rg in config.resource_groups:
                rg_path = self.export_resource_group(
                    resource_group=rg,
                    output_dir=temp_path,
                    subscription_id=config.subscription_id,
                )
                final_path = config.output_dir / "raw" / rg
                final_path.parent.mkdir(parents=True, exist_ok=True)

                if final_path.exists():
                    shutil.rmtree(final_path)
                shutil.copytree(rg_path, final_path)

                results[rg] = final_path
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)

        return results
