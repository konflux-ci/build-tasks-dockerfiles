from typing import Any

import pytest
import json

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.model.document import Document


@pytest.fixture(scope="session")
def spdx_parent_sbom_bytes() -> bytes:
    with open("tests/test_data/fake_parent_sbom/parent_sbom.spdx.json", "rb") as sbom_file:
        return sbom_file.read()


@pytest.fixture(scope="session")
def inspected_parent_multiarch() -> bytes:
    with open("tests/test_data/fake_image_inspect/inspect_multiarch.json", "rb") as inspect_file:
        return inspect_file.read()


@pytest.fixture(scope="session")
def inspected_parent_singlearch() -> bytes:
    with open("tests/test_data/fake_image_inspect/inspect_singlearch.json", "rb") as inspect_file:
        return inspect_file.read()


@pytest.fixture(scope="session")
def cdx_parent_sbom_bytes() -> bytes:
    with open("tests/test_data/fake_parent_sbom/parent_sbom.cdx.json", "rb") as sbom_file:
        return sbom_file.read()


@pytest.fixture(scope="session")
def sample1_parsed_dockerfile() -> dict[str, Any]:
    with open("tests/test_data/sample1/parsed.json") as json_file:
        return json.load(json_file)


@pytest.fixture(scope="session")
def sample2_parsed_dockerfile() -> dict[str, Any]:
    with open("tests/test_data/sample2/parsed.json") as json_file:
        return json.load(json_file)


@pytest.fixture(scope="session")
def spdx_parent_sbom() -> Document:
    return parse_file("tests/test_data/fake_parent_sbom/parent_sbom_legacy_with_builder.spdx.json")


@pytest.fixture(scope="session")
def spdx_component_sbom() -> Document:
    return parse_file("tests/test_data/fake_component_sbom/component_sbom.spdx.json")
