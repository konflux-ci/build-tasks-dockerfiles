import json
from pathlib import Path
from typing import Any, Generator
from unittest.mock import patch

import pytest

from merge_cachi2_sboms import merge_sboms

TOOLS_METADATA = {
    "syft-cyclonedx-1.4": {
        "name": "syft",
        "vendor": "anchore",
        "version": "0.47.0",
    },
    "syft-cyclonedx-1.5": {
        "type": "application",
        "author": "anchore",
        "name": "syft",
        "version": "0.100.0",
    },
    "cachi2-cyclonedx-1.4": {
        "name": "cachi2",
        "vendor": "red hat",
    },
    "cachi2-cyclonedx-1.5": {
        "type": "application",
        "author": "red hat",
        "name": "cachi2",
    },
}


@pytest.fixture
def data_dir() -> Path:
    """Path to the directory for storing unit test data."""
    return Path(__file__).parent / "test_data"


def test_merge_sboms(data_dir: Path) -> None:
    result = merge_sboms(f"{data_dir}/cachi2.bom.json", f"{data_dir}/syft.bom.json")

    with open(f"{data_dir}/merged.bom.json") as file:
        expected_sbom = json.load(file)

    assert json.loads(result) == expected_sbom


@pytest.fixture
def isodate() -> Generator:
    with patch("datetime.datetime") as mock_datetime:
        mock_datetime.now.return_value.isoformat.return_value = "2021-07-01T00:00:00Z"
        yield mock_datetime


def test_merge_sboms_spdx(data_dir: Path, isodate: Generator) -> None:
    result = merge_sboms(f"{data_dir}/cachi2.bom.spdx.json", f"{data_dir}/syft.bom.spdx.json", format="spdx")

    with open(f"{data_dir}/merged.bom.spdx.json") as file:
        expected_sbom = json.load(file)

    assert json.loads(result) == expected_sbom


def test_merge_both_formats_equal(data_dir: Path, isodate: Generator) -> None:
    """Test that the merge result is the same for both formats."""

    result_cdx = json.loads(merge_sboms(f"{data_dir}/cachi2.bom.json", f"{data_dir}/syft.bom.json"))
    result_spdx = json.loads(
        merge_sboms(f"{data_dir}/cachi2.bom.spdx.json", f"{data_dir}/syft.bom.spdx.json", format="spdx")
    )
    cdx_components = []
    for component in result_cdx["components"]:
        cdx_components.append(
            {"name": component["name"], "version": component.get("version"), "purl": component.get("purl")}
        )
    spdx_packages = []
    for package in result_spdx["packages"]:
        purl = ""
        purl = None
        for ref in package.get("externalRefs", []):
            if ref["referenceType"] == "purl":
                purl = ref["referenceLocator"]
                spdx_packages.append({"name": package["name"], "version": package.get("versionInfo"), "purl": purl})
        if not purl and package["name"]:
            spdx_packages.append({"name": package["name"], "version": package.get("versionInfo"), "purl": None})
    cdx_components.sort(key=lambda x: (x["name"], x["version"], x["purl"]))
    spdx_packages.sort(key=lambda x: (x["name"], x["version"], x["purl"]))

    assert cdx_components == spdx_packages


@pytest.mark.parametrize(
    "syft_tools_metadata, expected_result",
    [
        (
            [TOOLS_METADATA["syft-cyclonedx-1.4"]],
            [
                TOOLS_METADATA["syft-cyclonedx-1.4"],
                TOOLS_METADATA["cachi2-cyclonedx-1.4"],
            ],
        ),
        (
            {
                "components": [TOOLS_METADATA["syft-cyclonedx-1.5"]],
            },
            {
                "components": [
                    TOOLS_METADATA["syft-cyclonedx-1.5"],
                    TOOLS_METADATA["cachi2-cyclonedx-1.5"],
                ],
            },
        ),
    ],
)
def test_merging_tools_metadata(syft_tools_metadata: str, expected_result: Any, tmpdir: Path) -> None:
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": syft_tools_metadata,
        },
        "components": [],
    }

    cachi2_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": [TOOLS_METADATA["cachi2-cyclonedx-1.4"]],
        },
        "components": [],
    }

    syft_sbom_path = f"{tmpdir}/syft.bom.json"
    cachi2_sbom_path = f"{tmpdir}/cachi2.bom.json"

    with open(syft_sbom_path, "w") as file:
        json.dump(syft_sbom, file)

    with open(cachi2_sbom_path, "w") as file:
        json.dump(cachi2_sbom, file)

    result = merge_sboms(cachi2_sbom_path, syft_sbom_path)

    assert json.loads(result)["metadata"]["tools"] == expected_result


def test_invalid_tools_format(tmpdir: Path) -> None:
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": "invalid",
        },
        "components": [],
    }

    cachi2_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": [TOOLS_METADATA["cachi2-cyclonedx-1.4"]],
        },
        "components": [],
    }

    syft_sbom_path = f"{tmpdir}/syft.bom.json"
    cachi2_sbom_path = f"{tmpdir}/cachi2.bom.json"

    with open(syft_sbom_path, "w") as file:
        json.dump(syft_sbom, file)

    with open(cachi2_sbom_path, "w") as file:
        json.dump(cachi2_sbom, file)

    with pytest.raises(RuntimeError):
        merge_sboms(cachi2_sbom_path, syft_sbom_path)
