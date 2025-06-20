from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.model import RelationshipType, Relationship

from src.parent_content import (
    download_parent_image_sbom,
    adjust_parent_image_relationship_in_legacy_sbom,
    adjust_parent_image_spdx_element_ids,
    get_used_parent_image_from_legacy_sbom,
)
from src.utils import (
    identify_arch,
    load_json,
    use_contextual_sbom_creation,
    _get_sbom_format,
)
from src.parsed_dockerfile import (
    get_base_images,
    get_parent_image_pullspec,
)

from src.constants import SBOMFormat, ARCH_TRANSLATION


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
@patch("src.utils.subprocess")
def test_identify_arch(mock_subprocess: MagicMock, uname_output: bytes, expected_cosign_arch: str):
    mock_subprocess.run.return_value.stdout = uname_output
    assert identify_arch() == f"linux/{expected_cosign_arch}"


@pytest.mark.parametrize(
    ["sbom_name", "expected_output"],
    [("parent_sbom.spdx.json", True), ("parent_sbom.cdx.json", False)],
)
def test_use_contextual_sbom_creation(sbom_name: str, expected_output: bool):
    path_to_file = Path("tests/test_data/fake_parent_sbom") / sbom_name
    if expected_output:
        assert use_contextual_sbom_creation(load_json(path_to_file)) is None
    else:
        with pytest.raises(SystemExit):
            assert use_contextual_sbom_creation(load_json(path_to_file))


def test_use_contextual_sbom_creation_sbom_is_none():
    with pytest.raises(SystemExit):
        assert use_contextual_sbom_creation(None) == False


@patch("src.parent_content.subprocess")
@patch("src.parent_content.LOGGER")
def test_download_parent_image_sbom_multiarch(
    mock_logger: MagicMock,
    mock_subprocess: MagicMock,
    spdx_parent_sbom_bytes: bytes,
    inspected_parent_multiarch: bytes,
):
    def mock_subprocess_side_effect(*args, **_):
        """Mimics the functionality of both oras and cosign."""
        run_result = MagicMock()
        if args[0][0] == "/usr/bin/cosign":
            # This simulates cosign
            run_result.stdout = spdx_parent_sbom_bytes
        elif args[0][0] == "/usr/bin/oras":
            # This simulates oras
            run_result.stdout = inspected_parent_multiarch
        return run_result

    mock_subprocess.run.side_effect = mock_subprocess_side_effect
    sbom_doc = download_parent_image_sbom("foo", "bar")
    assert _get_sbom_format(sbom_doc) is SBOMFormat.SPDX2X
    mock_logger.debug.assert_any_call("The parent image pullspec points to a multiarch image")


@patch("src.parent_content.subprocess")
@patch("src.parent_content.LOGGER")
def test_download_parent_image_sbom_singlearch(
    mock_logger: MagicMock,
    mock_subprocess: MagicMock,
    spdx_parent_sbom_bytes: bytes,
    inspected_parent_singlearch: bytes,
):
    def mock_subprocess_side_effect(*args, **_):
        """Mimics the functionality of both oras and cosign."""
        run_result = MagicMock()
        if args[0][0] == "/usr/bin/cosign":
            # This simulates cosign
            run_result.stdout = spdx_parent_sbom_bytes
        elif args[0][0] == "/usr/bin/oras":
            # This simulates oras
            run_result.stdout = inspected_parent_singlearch
        return run_result

    mock_subprocess.run.side_effect = mock_subprocess_side_effect
    sbom_doc = download_parent_image_sbom("foo", "bar")
    assert _get_sbom_format(sbom_doc) is SBOMFormat.SPDX2X
    mock_logger.debug.assert_any_call("The parent image pullspec does not point to a multiarch image")


@patch("src.parent_content.subprocess")
@patch("src.parent_content.LOGGER")
def test_download_parent_image_sbom_oras_failed(
    mock_logger: MagicMock,
    mock_subprocess: MagicMock,
    spdx_parent_sbom_bytes: bytes,
    inspected_parent_singlearch: bytes,
):
    def mock_subprocess_side_effect(*args, **_):
        """Mimics the functionality of both oras and cosign."""
        run_result = MagicMock()
        if args[0][0] == "/usr/bin/cosign":
            # This simulates cosign
            run_result.stdout = spdx_parent_sbom_bytes
        elif args[0][0] == "/usr/bin/oras":
            # This simulates oras
            run_result.stdout = None
            run_result.stderr = b"something went wrong"
        return run_result

    mock_subprocess.run.side_effect = mock_subprocess_side_effect
    with pytest.raises(SystemExit):
        download_parent_image_sbom("foo", "bar")

    mock_logger.warning.assert_any_call("Could not locate manifest of the 'foo'. Raw stderr output: something went wrong")

@patch("src.parent_content.LOGGER")
def test_download_parent_image_sbom_no_pullspec(mock_logger: MagicMock, spdx_parent_sbom_bytes: bytes):
    with pytest.raises(SystemExit):
        download_parent_image_sbom(pullspec=None, arch="baroko")
    mock_logger.debug.assert_any_call("No parent image found.")

@patch("src.parent_content.subprocess")
@patch("src.parent_content.LOGGER")
def test_download_parent_image_sbom_oras_manifest_is_invalid(
        mock_logger: MagicMock,
        mock_subprocess: MagicMock,
        spdx_parent_sbom_bytes: bytes,
        inspected_parent_singlearch: bytes,
):
    def mock_subprocess_side_effect(*args, **_):
        """Mimics the functionality of both oras and cosign."""
        run_result = MagicMock()
        if args[0][0] == "/usr/bin/cosign":
            # This simulates cosign
            run_result.stdout = spdx_parent_sbom_bytes
        elif args[0][0] == "/usr/bin/oras":
            # This simulates oras
            run_result.stdout = "{invalid_json}"
        return run_result

    mock_subprocess.run.side_effect = mock_subprocess_side_effect
    with pytest.raises(SystemExit):
        download_parent_image_sbom("foo", "bar")

    mock_logger.warning.assert_any_call("Invalid image manifest found, cannot parse JSON for pullspec 'foo'.")


def test__get_sbom_format_unsupported_format():
    """
    Test that an unsupported SBOM format raises a ValueError.
    """
    assert _get_sbom_format({"spdxVersion": "SPDX-3.0"}) == SBOMFormat.UNSUPPORTED
    assert _get_sbom_format({"bomFormat": "CycloneDX", "specVersion": "2.0"}) == SBOMFormat.UNSUPPORTED


@patch("src.parent_content.subprocess")
@patch("src.parent_content.LOGGER")
def test_download_parent_image_sbom_cosign_fail(
    mock_logger: MagicMock,
    mock_subprocess: MagicMock,
    spdx_parent_sbom_bytes: bytes,
    inspected_parent_singlearch: bytes,
):
    def mock_subprocess_side_effect(*args, **_):
        """Mimics the functionality of both oras and cosign."""
        run_result = MagicMock()
        if args[0][0] == "/usr/bin/cosign":
            # This simulates cosign
            run_result.stdout = b""
            run_result.stderr = b"error"
        elif args[0][0] == "/usr/bin/oras":
            # This simulates oras
            run_result.stdout = inspected_parent_singlearch
        return run_result

    mock_subprocess.run.side_effect = mock_subprocess_side_effect
    with pytest.raises(SystemExit):
        download_parent_image_sbom(pullspec="image", arch="baroko")
    mock_logger.warning.assert_any_call("Could not locate SBOM. Raw stderr output: error")


@patch("src.parent_content.subprocess")
@patch("src.parent_content.LOGGER")
def test_download_parent_image_sbom_sbom_invalid_json(
    mock_logger: MagicMock,
    mock_subprocess: MagicMock,
    spdx_parent_sbom_bytes: bytes,
    inspected_parent_singlearch: bytes,
):
    def mock_subprocess_side_effect(*args, **_):
        """Mimics the functionality of both oras and cosign."""
        run_result = MagicMock()
        if args[0][0] == "/usr/bin/cosign":
            # This simulates cosign
            run_result.stdout = b"invalid json"
        elif args[0][0] == "/usr/bin/oras":
            # This simulates oras
            run_result.stdout = inspected_parent_singlearch
        return run_result

    mock_subprocess.run.side_effect = mock_subprocess_side_effect
    with pytest.raises(SystemExit):
        download_parent_image_sbom(pullspec="image", arch="baroko")
    mock_logger.warning.assert_any_call("Invalid SBOM found, cannot parse JSON for pullspec 'image'.")


def test_adjust_parent_image_relationship_in_legacy_sbom(
    spdx_parent_sbom: dict[str, Any],
):
    """
    Downloaded parent image has not been contextualized yet,
    but has been produced by legacy SBOM generator in konflux -
    parent of this parent is marked in packages.annotations
    Relationship needs to be adjusted to DESCENDANT_OF.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)

    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = adjust_parent_image_relationship_in_legacy_sbom(spdx_parent_edit, grandparent_spdx_id).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 1
    assert descendant_of_relationship[0].spdx_element_id == "SPDXRef-image"  # self (downloaded parent image)
    # is descendant of
    assert (
        descendant_of_relationship[0].related_spdx_element_id == "SPDXRef-image-registry.access.redhat.com/ubi9"
    )  # parent image of this parent image


@patch("src.parent_content.LOGGER")
def test_adjust_parent_image_relationship_in_legacy_sbom_no_change(
    mock_logger: MagicMock, spdx_parent_sbom: dict[str, Any]
):
    """
    Downloaded parent image has been already
    contextualized or had already DESCENDANT_OF
    relationship set.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.relationships[-1].spdx_element_id = "SPDXRef-image"
    spdx_parent_edit.relationships[-1].relationship_type = RelationshipType.DESCENDANT_OF
    spdx_parent_edit.relationships[-1].related_spdx_element_id = "SPDXRef-image-registry.access.redhat.com/ubi9"

    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = adjust_parent_image_relationship_in_legacy_sbom(spdx_parent_edit, grandparent_spdx_id).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 1
    assert descendant_of_relationship[0].spdx_element_id == "SPDXRef-image"  # self (downloaded parent image)
    # is descendant of
    assert (
        descendant_of_relationship[0].related_spdx_element_id == "SPDXRef-image-registry.access.redhat.com/ubi9"
    )  # parent image of this parent image
    mock_logger.debug.assert_any_call(
        "[Parent image content] Downloaded parent image " "content already contains DESCENDANT_OF relationship."
    )


@patch("src.parent_content.LOGGER")
def test_adjust_parent_image_relationship_in_legacy_sbom_unknown_relationship(
    mock_logger: MagicMock, spdx_parent_sbom: dict[str, Any]
):
    """
    Downloaded parent image has some unknown relationship with its parent image
    and thus we cannot use convert_to_descendant_of_relationship function.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.relationships[-1].spdx_element_id = "SPDXRef-image-registry.access.redhat.com/ubi9"
    spdx_parent_edit.relationships[-1].relationship_type = RelationshipType.OTHER
    spdx_parent_edit.relationships[-1].related_spdx_element_id = "SPDXRef-image"

    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = adjust_parent_image_relationship_in_legacy_sbom(spdx_parent_edit, grandparent_spdx_id).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 0
    mock_logger.warning.assert_any_call(
        "[Parent image content] Targeted SPDXID SPDXRef-image"
        "-registry.access.redhat.com/ubi9 does not bear "
        "BUILD_TOOL_OF relationship but RelationshipType.OTHER relationship."
    )


@patch("src.parent_content.LOGGER")
def test_adjust_parent_image_relationship_in_legacy_sbom_no_relationship(
    mock_logger: MagicMock, spdx_parent_sbom: dict[str, Any]
):
    """
    Missing relationship between parent image and its parent image.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.relationships.pop(-1)

    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = adjust_parent_image_relationship_in_legacy_sbom(spdx_parent_edit, grandparent_spdx_id).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 0
    mock_logger.warning.assert_any_call(
        "[Parent image content] Targeted SPDXID SPDXRef-image"
        "-registry.access.redhat.com/ubi9 does not bear any relationship!"
    )


@patch("src.parent_content.LOGGER")
def test_adjust_parent_image_relationship_in_legacy_sbom_multiple_relationships(
    mock_logger: MagicMock, spdx_parent_sbom: dict[str, Any]
):
    """
    Multiple relationships between parent image and its parent image.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.relationships[-1] = Relationship(
        spdx_element_id="SPDXRef-image-registry.access.redhat.com/ubi9",
        relationship_type=RelationshipType.BUILD_TOOL_OF,
        related_spdx_element_id="SPDXRef-image",
    )
    spdx_parent_edit.relationships.append(
        Relationship(
            spdx_element_id="SPDXRef-image-registry.access.redhat.com/ubi9",
            relationship_type=RelationshipType.BUILD_TOOL_OF,
            related_spdx_element_id="SPDXRef-image-what?",
        )
    )

    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = adjust_parent_image_relationship_in_legacy_sbom(spdx_parent_edit, grandparent_spdx_id).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 0
    mock_logger.warning.assert_any_call(
        "[Parent image content] Targeted SPDXID SPDXRef-image"
        "-registry.access.redhat.com/ubi9 has more than one relationship. "
        "This is not expected, skipping modification."
    )


@patch("src.parent_content.LOGGER")
def test_adjust_parent_image_relationship_in_legacy_sbom_parent_not_marked(
    mock_logger: MagicMock, spdx_parent_sbom: dict[str, Any]
):
    """
    Parent of the parent image is not marked in the
    packages.annotations, possibly because SBOM was
    generated by konflux - we cannot determine the parent.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.annotations.pop(-1)

    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = adjust_parent_image_relationship_in_legacy_sbom(spdx_parent_edit, grandparent_spdx_id).relationships
    build_tool_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.BUILD_TOOL_OF,
            relationships,
        )
    )
    assert len(build_tool_of_relationship) == 2
    mock_logger.debug.assert_any_call(
        "[Parent image content] Cannot determine parent of the "
        f"downloaded parent image SBOM. It either does "
        "not exist (it was an oci-archive or the image is built from "
        "scratch) or the downloaded SBOM is not sourced from konflux."
    )


def test_adjust_parent_image_spdx_element_ids(spdx_parent_sbom: dict[str, Any], spdx_component_sbom: dict[str, Any]):
    """
    Adjusts the parent image SPDX element IDs in the legacy SBOM.
    We have component SBOM and downloaded parent image SBOM. Both
    contain SPDXRef-image as self reference. For parent SBOM it must
    be changed to name of the parent image from component SBOM to
    differ these relationships.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    # DESCENDANT_OF relationship is already set by adjust_parent_image_relationship_in_legacy_sbom_parent
    spdx_parent_edit.relationships[-1] = Relationship(
        spdx_element_id="SPDXRef-image",  # this will be changed at the end
        relationship_type=RelationshipType.DESCENDANT_OF,
        related_spdx_element_id="SPDXRef-image-registry.access.redhat.com/ubi9",
    )
    to_be_converted_parent_packages = [
        r.related_spdx_element_id
        for r in spdx_parent_edit.relationships
        if r.relationship_type == RelationshipType.CONTAINS and r.spdx_element_id == "SPDXRef-image"
    ]
    # SPDXRef-package_grandparent, SPDXRef-package_parent
    # in parent_sbom_legacy_with_builder.spdx.json
    assert len(to_be_converted_parent_packages) == 2

    # The component SBOM is already expected to have DESCENDANT_OF
    # relationship, because it is produced after implementation of the ISV-5858
    spdx_component_edit = deepcopy(spdx_component_sbom)
    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    adjusted_parent_sbom = adjust_parent_image_spdx_element_ids(
        spdx_parent_edit, spdx_component_edit, grandparent_spdx_id
    )

    converted_parent_packages = [
        r.related_spdx_element_id
        for r in adjusted_parent_sbom.relationships
        if r.spdx_element_id == "SPDXRef-image-parent_sbom_legacy_with_builder.spdx.json"
    ]
    # SPDXRef-package_component in component_sbom.spdx.json is
    # untouched because belongs to the final component.
    # In spdxElementId it is expected to be SPDXRef-image,
    # but third SPDXRef-image-parent_sbom_legacy_with_builder.spdx.json
    # is the relationship of this parent (self) with its grandparent.
    assert len(converted_parent_packages) == 3

    # Check if the parent image's spdxElementId was
    # modified to name of the parent from component
    assert set(to_be_converted_parent_packages).issubset(set(converted_parent_packages))
    # This is the last thing that needs to be edited in parent SBOM -
    assert (
        adjusted_parent_sbom.relationships[-1].spdx_element_id
        == "SPDXRef-image-parent_sbom_legacy_with_builder.spdx.json"
    )


def test_adjust_parent_image_spdx_element_ids_missing_describes_relationship(spdx_parent_sbom: dict[str, Any], spdx_component_sbom: dict[str, Any]):
    """
    Downloaded parent SBOM is missing essential DESCRIBES relationship
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    # DESCENDANT_OF relationship is already set by adjust_parent_image_relationship_in_legacy_sbom_parent
    spdx_parent_edit.relationships.pop(0)


    # The component SBOM is already expected to have DESCENDANT_OF
    # relationship, because it is produced after implementation of the ISV-5858
    spdx_component_edit = deepcopy(spdx_component_sbom)
    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    with pytest.raises(SystemExit):
        adjust_parent_image_spdx_element_ids(
            spdx_parent_edit, spdx_component_edit, grandparent_spdx_id
        )

