from typing import Any
from unittest.mock import patch, MagicMock

import pytest

from index_image_sbom_script import create_sbom, main


@pytest.mark.parametrize(
    [
        "image_index_url",
        "image_index_digest",
        "manifests",
        "expected_sbom",
    ],
    [
        (
            "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
            "sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
            [],
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "documentNamespace": "https://redhat.com/spdxdocs/single-container-app-f2566ab-101",
                "SPDXID": "SPDXRef-DOCUMENT",
                "creationInfo": {
                    "created": "2000-00-00T00:00:00.000000",
                    "creators": ["Tool: Konflux"],
                    "licenseListVersion": "3.25",
                },
                "name": "single-container-app-f2566ab",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-image-index",
                        "name": "single-container-app",
                        "versionInfo": "f2566ab",
                        "supplier": "Organization: Red Hat",
                        "downloadLocation": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
                            }
                        ],
                        "checksums": [
                            {
                                "algorithm": "SHA256",
                                "checksumValue": "8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                            }
                        ],
                    }
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-image-index",
                    }
                ],
            },
        ),
        (
            "quay.io/ubi9-micro-container:9.4-6.1716471860",
            "sha256:1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d",
            [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:f08722139c4da653b870272a192fac700960a3315baa1f79f83a4712a436d4",
                    "size": 100,
                    "platform": {"architecture": "ppc64le", "os": "linux"},
                }
            ],
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "documentNamespace": "https://redhat.com/spdxdocs/ubi9-micro-container-9.4-6.1716471860-101",
                "SPDXID": "SPDXRef-DOCUMENT",
                "creationInfo": {
                    "created": "2000-00-00T00:00:00.000000",
                    "creators": ["Tool: Konflux"],
                    "licenseListVersion": "3.25",
                },
                "name": "ubi9-micro-container-9.4-6.1716471860",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-image-index",
                        "name": "ubi9-micro-container",
                        "versionInfo": "9.4-6.1716471860",
                        "supplier": "Organization: Red Hat",
                        "downloadLocation": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:oci/ubi9-micro-container@sha256:1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d?repository_url=quay.io/ubi9-micro-container",
                            }
                        ],
                        "checksums": [
                            {
                                "algorithm": "SHA256",
                                "checksumValue": "1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d",
                            }
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-Image-ubi9-micro-container-8358c7002e15f219c861227e97919d537e888874e7ca2b349979bc745f903195",
                        "name": "ubi9-micro-container_ppc64le",
                        "versionInfo": "9.4-6.1716471860",
                        "supplier": "Organization: Red Hat",
                        "downloadLocation": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:oci/ubi9-micro-container@sha256:1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d?arch=ppc64le&repository_url=quay.io/ubi9-micro-container",
                            },
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:oci/ubi9-micro-container@sha256:f08722139c4da653b870272a192fac700960a3315baa1f79f83a4712a436d4?repository_url=quay.io/ubi9-micro-container",
                            },
                        ],
                        "checksums": [
                            {
                                "algorithm": "SHA256",
                                "checksumValue": "f08722139c4da653b870272a192fac700960a3315baa1f79f83a4712a436d4",
                            }
                        ],
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-image-index",
                    },
                    {
                        "spdxElementId": "SPDXRef-Image-ubi9-micro-container-8358c7002e15f219c861227e97919d537e888874e7ca2b349979bc745f903195",
                        "relationshipType": "VARIANT_OF",
                        "relatedSpdxElement": "SPDXRef-image-index",
                    },
                ],
            },
        ),
    ],
)
@patch("index_image_sbom_script.datetime")
@patch("index_image_sbom_script.uuid4")
def test_create_sbom(
    mock_uuid: MagicMock,
    mock_datetime: MagicMock,
    image_index_url: str,
    image_index_digest: str,
    manifests: list[dict[str, Any]],
    expected_sbom: dict[str, Any],
):
    mock_uuid.return_value = "101"
    mock_datetime.now.return_value.isoformat.return_value = "2000-00-00T00:00:00.000000"
    assert expected_sbom == create_sbom(
        image_index_url,
        image_index_digest,
        {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests},
    )


@patch("index_image_sbom_script.argparse")
@patch("builtins.open")
@patch("index_image_sbom_script.json")
@patch("index_image_sbom_script.datetime")
@patch("index_image_sbom_script.uuid4")
def test_main(
    mock_uuid: MagicMock,
    mock_datetime: MagicMock,
    mock_json: MagicMock,
    mock_open: MagicMock,
    mock_argparse: MagicMock,
):
    mock_uuid.return_value = "101"
    mock_datetime.now.return_value.isoformat.return_value = "2000-00-00T00:00:00.000000"

    mock_args = MagicMock()
    mock_args.image_index_url = "foo/bar:v1"
    mock_args.image_index_digest = "sha256:456"
    mock_args.output_path = "sbom.spdx.json"
    mock_argparse.ArgumentParser.return_value.parse_args.return_value = mock_args

    mock_json.load.return_value = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:123",
                "size": 200,
                "platform": {
                    "architecture": "arm64",
                    "os": "linux",
                },
            }
        ],
    }

    main()
    mock_json.dump.assert_called_once_with(
        {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://redhat.com/spdxdocs/bar-v1-101",
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {
                "created": "2000-00-00T00:00:00.000000",
                "creators": ["Tool: Konflux"],
                "licenseListVersion": "3.25",
            },
            "name": "bar-v1",
            "packages": [
                {
                    "SPDXID": "SPDXRef-image-index",
                    "name": "bar",
                    "versionInfo": "v1",
                    "supplier": "Organization: Red Hat",
                    "downloadLocation": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:oci/bar@sha256:456?repository_url=foo/bar",
                        },
                    ],
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "456"}],
                },
                {
                    "SPDXID": "SPDXRef-Image-bar-f10b3378df375bc400853a24e863f9a3194a120c4789a02ba5cc53f236712eca",
                    "name": "bar_arm64",
                    "versionInfo": "v1",
                    "supplier": "Organization: Red Hat",
                    "downloadLocation": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:oci/bar@sha256:456?arch=arm64&repository_url=foo/bar",
                        },
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:oci/bar@sha256:123?repository_url=foo/bar",
                        },
                    ],
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "123"}],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-image-index",
                },
                {
                    "spdxElementId": "SPDXRef-Image-bar-f10b3378df375bc400853a24e863f9a3194a120c4789a02ba5cc53f236712eca",
                    "relationshipType": "VARIANT_OF",
                    "relatedSpdxElement": "SPDXRef-image-index",
                },
            ],
        },
        mock_open.return_value.__enter__.return_value,
        indent=4,
    )
