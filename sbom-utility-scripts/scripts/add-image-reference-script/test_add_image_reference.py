from unittest.mock import MagicMock, patch

import pytest

import add_image_reference


def test_setup_arg_parser() -> None:
    parser = add_image_reference.setup_arg_parser()
    assert parser.description == "Add image reference to image SBOM."
    assert parser._option_string_actions["--image-url"].required
    assert parser._option_string_actions["--image-digest"].required


def test_Image() -> None:
    image = add_image_reference.Image.from_image_index_url_and_digest(
        "quay.io/namespace/repository/image:tag", "sha256:digest"
    )

    assert image.repository == "quay.io/namespace/repository/image"
    assert image.name == "image"
    assert image.digest == "sha256:digest"
    assert image.tag == "tag"

    assert image.digest_algo_cyclonedx == "SHA-256"
    assert image.digest_algo_spdx == "SHA256"
    assert image.digest_hex_val == "digest"

    assert image.purl() == ("pkg:oci/image@sha256:digest?repository_url=quay.io/namespace/repository/image")


def test_update_component_in_cyclonedx_sbom() -> None:
    sbom = {"bomFormat": "CycloneDX", "metadata": {"component": {}}, "components": [{}]}
    image = add_image_reference.Image.from_image_index_url_and_digest(
        "quay.io/namespace/repository/image:tag",
        "sha256:digest",
    )

    result = add_image_reference.update_component_in_cyclonedx_sbom(sbom=sbom, image=image)

    assert (
        result["metadata"]["component"]["purl"]
        == "pkg:oci/image@sha256:digest?repository_url=quay.io/namespace/repository/image"
    )
    assert len(result["components"]) == 2
    assert result["components"][0] == {
        "type": "container",
        "name": image.name,
        "purl": image.purl(),
        "version": image.tag,
        "hashes": [{"alg": image.digest_algo_cyclonedx, "content": image.digest_hex_val}],
    }
    assert result["metadata"]["component"] == result["components"][0]


def test_find_package_by_spdx_id() -> None:
    sbom = {"packages": [{"SPDXID": "foo"}, {"SPDXID": "bar"}]}
    assert add_image_reference.find_package_by_spdx_id(sbom, "foo") == {"SPDXID": "foo"}
    assert add_image_reference.find_package_by_spdx_id(sbom, "baz") is None


def test_delete_package_by_spdx_id() -> None:
    sbom = {"packages": [{"SPDXID": "foo"}, {"SPDXID": "bar"}]}
    add_image_reference.delete_package_by_spdx_id(sbom, "foo")
    assert sbom["packages"] == [{"SPDXID": "bar"}]


def test_redirect_virtual_root_to_new_root() -> None:
    sbom = {
        "relationships": [
            {"spdxElementId": "foo", "relationshipType": "DESCRIBES", "relatedSpdxElement": "bar"},
            {"spdxElementId": "bar", "relationshipType": "DESCRIBES", "relatedSpdxElement": "baz"},
            {"spdxElementId": "baz", "relationshipType": "DESCRIBES", "relatedSpdxElement": "qux"},
        ]
    }
    add_image_reference.redirect_virtual_root_to_new_root(sbom, "bar", "qux")

    assert sbom["relationships"] == [
        {"spdxElementId": "foo", "relationshipType": "DESCRIBES", "relatedSpdxElement": "qux"},
        {"spdxElementId": "qux", "relationshipType": "DESCRIBES", "relatedSpdxElement": "baz"},
        {"spdxElementId": "baz", "relationshipType": "DESCRIBES", "relatedSpdxElement": "qux"},
    ]


def test_delete_relationship_by_related_spdx_id() -> None:
    sbom = {
        "relationships": [
            {"spdxElementId": "foo", "relationshipType": "DESCRIBES", "relatedSpdxElement": "bar"},
            {"spdxElementId": "bar", "relationshipType": "DESCRIBES", "relatedSpdxElement": "baz"},
            {"spdxElementId": "baz", "relationshipType": "DESCRIBES", "relatedSpdxElement": "qux"},
        ]
    }
    add_image_reference.delete_relationship_by_related_spdx_id(sbom, "baz")

    assert sbom["relationships"] == [
        {"spdxElementId": "foo", "relationshipType": "DESCRIBES", "relatedSpdxElement": "bar"},
        {"spdxElementId": "baz", "relationshipType": "DESCRIBES", "relatedSpdxElement": "qux"},
    ]


def test_describes_the_document() -> None:
    relationship = {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-image",
    }

    assert add_image_reference.describes_the_document(relationship, "SPDXRef-DOCUMENT") is True

    relationship["spdxElementId"] = "foo"

    assert add_image_reference.describes_the_document(relationship, "SPDXRef-DOCUMENT") is False


def test_is_virtual_root() -> None:
    package = {"SPDXID": "foo", "name": ""}

    assert add_image_reference.is_virtual_root(package) is True

    package["name"] = "./some-dir"
    assert add_image_reference.is_virtual_root(package) is True

    package["name"] = "/some/absolute/path"
    assert add_image_reference.is_virtual_root(package) is True

    package["name"] = "bar"
    assert add_image_reference.is_virtual_root(package) is False


def test_redirect_current_roots_to_new_root() -> None:
    # Replacing a virtual root with a new root
    sbom = {
        "packages": [
            {"SPDXID": "virtual", "name": ""},
            {"SPDXID": "virtual2", "name": "./some-dir"},
            {"SPDXID": "bar", "name": "bar"},
            {"SPDXID": "baz", "name": "baz"},
            {"SPDXID": "spam", "name": "spam"},
        ],
        "relationships": [
            {"spdxElementId": "foo", "relationshipType": "DESCRIBES", "relatedSpdxElement": "virtual"},
            {"spdxElementId": "foo", "relationshipType": "DESCRIBES", "relatedSpdxElement": "virtual2"},
            {"spdxElementId": "virtual", "relationshipType": "CONTAINS", "relatedSpdxElement": "baz"},
            {"spdxElementId": "virtual2", "relationshipType": "CONTAINS", "relatedSpdxElement": "spam"},
        ],
        "SPDXID": "foo",
    }
    result = add_image_reference.redirect_current_roots_to_new_root(sbom, "bar")

    assert result == {
        "packages": [
            {"SPDXID": "bar", "name": "bar"},
            {"SPDXID": "baz", "name": "baz"},
            {"SPDXID": "spam", "name": "spam"},
        ],
        "relationships": [
            {"spdxElementId": "bar", "relationshipType": "CONTAINS", "relatedSpdxElement": "baz"},
            {"spdxElementId": "bar", "relationshipType": "CONTAINS", "relatedSpdxElement": "spam"},
        ],
        "SPDXID": "foo",
    }

    # Replacing a root with a new root and redirecting the old root to the new root
    sbom = {
        "packages": [
            {"SPDXID": "npm", "name": "npm"},
            {"SPDXID": "bar", "name": "bar"},
            {"SPDXID": "baz", "name": "baz"},
            {"SPDXID": "pip", "name": "pip"},
            {"SPDXID": "spam", "name": "spam"},
        ],
        "relationships": [
            {"spdxElementId": "foo", "relationshipType": "DESCRIBES", "relatedSpdxElement": "npm"},
            {"spdxElementId": "foo", "relationshipType": "DESCRIBES", "relatedSpdxElement": "pip"},
            {"spdxElementId": "npm", "relationshipType": "CONTAINS", "relatedSpdxElement": "baz"},
            {"spdxElementId": "pip", "relationshipType": "CONTAINS", "relatedSpdxElement": "spam"},
        ],
        "SPDXID": "foo",
    }
    result = add_image_reference.redirect_current_roots_to_new_root(sbom, "bar")

    assert result == {
        "packages": [
            {"SPDXID": "npm", "name": "npm"},
            {"SPDXID": "bar", "name": "bar"},
            {"SPDXID": "baz", "name": "baz"},
            {"SPDXID": "pip", "name": "pip"},
            {"SPDXID": "spam", "name": "spam"},
        ],
        "relationships": [
            {"spdxElementId": "bar", "relationshipType": "CONTAINS", "relatedSpdxElement": "npm"},
            {"spdxElementId": "bar", "relationshipType": "CONTAINS", "relatedSpdxElement": "pip"},
            {"spdxElementId": "npm", "relationshipType": "CONTAINS", "relatedSpdxElement": "baz"},
            {"spdxElementId": "pip", "relationshipType": "CONTAINS", "relatedSpdxElement": "spam"},
        ],
        "SPDXID": "foo",
    }


@patch("add_image_reference.redirect_current_roots_to_new_root")
@pytest.mark.parametrize(
    "generate_id,expected_spdxid",
    [(True, "SPDXRef-image-quay.io/namespace/repository/image-sha256:digest"), (False, "SPDXRef-image")],
)
def test_update_package_in_spdx_sbom(mock_root_redicret: MagicMock, generate_id, expected_spdxid) -> None:
    sbom = {"spdxVersion": "1.1.1", "SPDXID": "foo", "packages": [{}], "relationships": []}
    image = add_image_reference.Image.from_image_index_url_and_digest(
        "quay.io/namespace/repository/image:tag",
        "sha256:digest",
    )

    result = add_image_reference.update_package_in_spdx_sbom(sbom=sbom, image=image, generate_id=generate_id)

    assert len(result["packages"]) == 2
    assert result["packages"][0] == {
        "SPDXID": expected_spdxid,
        "name": image.name,
        "versionInfo": image.tag,
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "supplier": "NOASSERTION",
        "externalRefs": [
            {
                "referenceLocator": image.purl(),
                "referenceType": "purl",
                "referenceCategory": "PACKAGE-MANAGER",
            }
        ],
        "checksums": [{"algorithm": image.digest_algo_spdx, "checksumValue": image.digest_hex_val}],
    }

    assert len(result["relationships"]) == 1
    assert result["relationships"][0] == {
        "spdxElementId": sbom["SPDXID"],
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": expected_spdxid,
    }

    mock_root_redicret.assert_called_once_with(sbom, expected_spdxid)


@patch("add_image_reference.update_package_in_spdx_sbom")
@patch("add_image_reference.update_component_in_cyclonedx_sbom")
def test_extend_sbom_with_image_reference(cyclonedx_update: MagicMock, spdx_update: MagicMock) -> None:
    sbom = {"bomFormat": "CycloneDX"}
    image = MagicMock()
    add_image_reference.extend_sbom_with_image_reference(sbom, image)

    cyclonedx_update.assert_called_once_with(sbom, image)
    spdx_update.assert_not_called()

    cyclonedx_update.reset_mock()
    spdx_update.reset_mock()

    sbom = {"spdxVersion": "1.1.1"}
    add_image_reference.extend_sbom_with_image_reference(sbom, image)

    cyclonedx_update.assert_not_called()
    spdx_update.assert_called_once_with(sbom, image, False)


def test_update_name() -> None:
    image = add_image_reference.Image.from_image_index_url_and_digest(
        "quay.io/namespace/repository/image:tag", "sha256:digest"
    )

    result = add_image_reference.update_name({"spdxVersion": "1.1.1"}, image)
    assert result["name"] == "quay.io/namespace/repository/image@sha256:digest"


@patch("json.dump")
@patch("json.load")
@patch("add_image_reference.update_name")
@patch("add_image_reference.extend_sbom_with_image_reference")
@patch("add_image_reference.Image.from_image_index_url_and_digest")
@patch("builtins.open")
@patch("add_image_reference.setup_arg_parser")
def test_main(
    mock_parser: MagicMock,
    mock_open: MagicMock,
    mock_image: MagicMock,
    mock_extend_sbom: MagicMock,
    mock_name: MagicMock,
    mock_load: MagicMock,
    mock_dump: MagicMock,
) -> None:
    add_image_reference.main()

    mock_parser.assert_called_once()
    mock_parser.return_value.parse_args.assert_called_once()
    mock_image.assert_called_once()
    assert mock_open.call_count == 2

    mock_load.assert_called_once()
    mock_extend_sbom.assert_called_once()
    mock_name.assert_called_once()
    mock_dump.assert_called_once()


def test_get_spdxid_from_image():

    image = add_image_reference.Image.from_image_index_url_and_digest(
        "quay.io/namespace/repository/image:tag", "sha256:digest"
    )

    actual = add_image_reference.get_spdxid_from_image(image)
    assert actual == "SPDXRef-image-quay.io/namespace/repository/image-sha256:digest"
