import json
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest

from create_contextual_sbom import (
    get_base_images,
    get_parent_image_pullspec,
    identify_arch,
    use_contextual_sbom_creation,
    ARCH_TRANSLATION,
    download_parent_image_sbom,
    _get_sbom_format,
    SBOMFormat,
    load_json,
)


@pytest.fixture(scope="session")
def sample1_parsed_dockerfile() -> dict[str, Any]:
    with open("test_data/sample1/parsed.json") as json_file:
        return json.load(json_file)


@pytest.fixture(scope="session")
def sample2_parsed_dockerfile() -> dict[str, Any]:
    with open("test_data/sample2/parsed.json") as json_file:
        return json.load(json_file)


@pytest.fixture(scope="session")
def spdx_parent_sbom_bytes() -> bytes:
    with open("test_data/fake_parent_sbom/parent_sbom.spdx.json", "rb") as sbom_file:
        return sbom_file.read()


@pytest.fixture(scope="session")
def cdx_parent_sbom_bytes() -> bytes:
    with open("test_data/fake_parent_sbom/parent_sbom.cdx.json", "rb") as sbom_file:
        return sbom_file.read()


def test_get_base_images(sample1_parsed_dockerfile: dict[str, Any]) -> None:
    assert get_base_images(sample1_parsed_dockerfile) == ["alpine:3.10", None]


@pytest.mark.parametrize(
    ["sample_name", "target", "expected_spec"],
    [
        ("sample1", None, None),
        ("sample1", "build", "alpine:3.10"),
        ("sample1", "test", "alpine:3.10"),
        ("sample2", None, "registry.access.redhat.com/ubi8/ubi:latest"),
        ("sample2", "build", "alpine:3.10"),
        ("sample2", "test", "alpine:3.10"),
        (
            "sample2",
            "registry.access.redhat.com/ubi8/ubi:latest",
            "registry.access.redhat.com/ubi8/ubi:latest",
        ),
        ("sample2", "foo", "registry.access.redhat.com/ubi9/ubi:latest"),
        ("sample2", "bar", "registry.access.redhat.com/ubi8/ubi:latest"),
        ("sample2", "scratch", None),
        ("sample2", "nothing", None),
    ],
)
def test_get_parent_image(
    sample_name: str,
    target: str,
    expected_spec: str,
    sample1_parsed_dockerfile: dict[str, Any],
    sample2_parsed_dockerfile: dict[str, Any],
):
    """For tested dockerfiles, visit the `test_data` directory."""
    parsed_file = sample1_parsed_dockerfile if sample_name == "sample1" else sample2_parsed_dockerfile
    assert get_parent_image_pullspec(parsed_file, target) == expected_spec


def test_identify_arch_basic():
    res = identify_arch()
    assert isinstance(res, str)
    assert res.startswith("linux/")
    assert res.removeprefix("linux/") in ARCH_TRANSLATION
    assert any(f"linux/{arch}" == res for arch in {"amd64", "arm64", "ppc64le", "s390x"})


@pytest.mark.parametrize(
    ["uname_output", "expected_cosign_arch"],
    [
        (b"x64", "amd64"),
        (b"x86_64", "amd64"),
        (b"armv8b", "arm64"),
        (b"arm", "arm64"),
        (b"aarch64", "arm64"),
        (b"armv8l", "arm64"),
        (b"aarch64_be", "arm64"),
        (b"ppcle", "ppc64le"),
        (b"powerpc", "ppc64le"),
        (b"ppc", "ppc64le"),
        (b"ppc64", "ppc64le"),
        (b"s390", "s390x"),
    ],
)
@patch("create_contextual_sbom.subprocess")
def test_identify_arch(mock_subprocess: MagicMock, uname_output: bytes, expected_cosign_arch: str):
    mock_subprocess.run.return_value.stdout = uname_output
    assert identify_arch() == f"linux/{expected_cosign_arch}"


@pytest.mark.parametrize(
    ["sbom_name", "expected_output"],
    [("parent_sbom.spdx.json", True), ("parent_sbom.cdx.json", False)],
)
def test_use_contextual_sbom_creation(sbom_name: str, expected_output: bool):
    path_to_file = Path("test_data/fake_parent_sbom") / sbom_name
    assert use_contextual_sbom_creation(load_json(path_to_file)) == expected_output


def test_use_contextual_sbom_creation_sbom_is_none():
    assert use_contextual_sbom_creation(None) == False


@patch("create_contextual_sbom.subprocess")
def test_download_parent_image_sbom(mock_subprocess: MagicMock, spdx_parent_sbom_bytes: bytes):
    mock_subprocess.run.return_value.stdout = spdx_parent_sbom_bytes
    sbom_doc = download_parent_image_sbom("foo", "bar")
    assert _get_sbom_format(sbom_doc) is SBOMFormat.SPDX2X
