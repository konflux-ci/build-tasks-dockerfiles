import pytest
import json

from unittest.mock import MagicMock, patch

from base_images_sbom_script import get_base_images_sbom_components, main, parse_image_reference_to_parts, ParsedImage


@pytest.mark.parametrize(
    "base_images_digests, is_last_from_scratch, expected_result",
    [
        # two builder images, last base image is from scratch
        (
            [
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256"
                ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "registry.access.redhat.com/ubi8/ubi:latest@sha256"
                ":627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ],
            True,
            [
                {
                    "type": "container",
                    "name": "quay.io/mkosiarc_rhtap/single-container-app",
                    "purl": "pkg:oci/single-container-app@sha256"
                    ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io"
                    "/mkosiarc_rhtap/single-container-app",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "registry.access.redhat.com/ubi8/ubi",
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                    "?repository_url=registry.access.redhat.com/ubi8/ubi",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "1",
                        }
                    ],
                },
            ],
        ),
        # one builder image, one parent image
        (
            [
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256"
                ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "registry.access.redhat.com/ubi8/ubi:latest@sha256"
                ":627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ],
            False,
            [
                {
                    "type": "container",
                    "name": "quay.io/mkosiarc_rhtap/single-container-app",
                    "purl": "pkg:oci/single-container-app@sha256"
                    ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io"
                    "/mkosiarc_rhtap/single-container-app",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "registry.access.redhat.com/ubi8/ubi",
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                    "?repository_url=registry.access.redhat.com/ubi8/ubi",
                    "properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
                },
            ],
        ),
        # just one parent image
        (
            [
                "registry.access.redhat.com/ubi8/ubi:latest@sha256"
                ":627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ],
            False,
            [
                {
                    "type": "container",
                    "name": "registry.access.redhat.com/ubi8/ubi",
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                    "?repository_url=registry.access.redhat.com/ubi8/ubi",
                    "properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
                },
            ],
        ),
        # one builder, last base image from scratch
        (
            [
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256"
                ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
            ],
            True,
            [
                {
                    "type": "container",
                    "name": "quay.io/mkosiarc_rhtap/single-container-app",
                    "purl": "pkg:oci/single-container-app@sha256"
                    ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io"
                    "/mkosiarc_rhtap/single-container-app",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                },
            ],
        ),
        # four builder images, and from scratch base image
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256"
                ":2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder3/builder3:ccccccc@sha256"
                ":3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder4/builder4:ddddddd@sha256"
                ":4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944",
            ],
            True,
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941"
                    "?repository_url=quay.io/builder1/builder1",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder2/builder2",
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942"
                    "?repository_url=quay.io/builder2/builder2",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "1",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder3/builder3",
                    "purl": "pkg:oci/builder3@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943"
                    "?repository_url=quay.io/builder3/builder3",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "2",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder4/builder4",
                    "purl": "pkg:oci/builder4@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944"
                    "?repository_url=quay.io/builder4/builder4",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "3",
                        }
                    ],
                },
            ],
        ),
        # four builders and one parent image
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256"
                ":2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder3/builder3:ccccccc@sha256"
                ":3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder4/builder4:ddddddd@sha256"
                ":4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944",
                "registry.access.redhat.com/ubi8/ubi:latest@sha256"
                ":627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ],
            False,
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941"
                    "?repository_url=quay.io/builder1/builder1",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder2/builder2",
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942"
                    "?repository_url=quay.io/builder2/builder2",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "1",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder3/builder3",
                    "purl": "pkg:oci/builder3@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943"
                    "?repository_url=quay.io/builder3/builder3",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "2",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder4/builder4",
                    "purl": "pkg:oci/builder4@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944"
                    "?repository_url=quay.io/builder4/builder4",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "3",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "registry.access.redhat.com/ubi8/ubi",
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                    "?repository_url=registry.access.redhat.com/ubi8/ubi",
                    "properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
                },
            ],
        ),
        # 3 builders and one final base image. builder 1 is reused twice, resulting in multiple properties
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256"
                ":2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder3/builder3:ccccccc@sha256"
                ":3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "registry.access.redhat.com/ubi8/ubi:latest@sha256"
                ":627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ],
            False,
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941"
                    "?repository_url=quay.io/builder1/builder1",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        },
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "2",
                        },
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "4",
                        },
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder2/builder2",
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942"
                    "?repository_url=quay.io/builder2/builder2",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "1",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder3/builder3",
                    "purl": "pkg:oci/builder3@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943"
                    "?repository_url=quay.io/builder3/builder3",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "3",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "registry.access.redhat.com/ubi8/ubi",
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                    "?repository_url=registry.access.redhat.com/ubi8/ubi",
                    "properties": [
                        {
                            "name": "konflux:container:is_base_image",
                            "value": "true",
                        }
                    ],
                },
            ],
        ),
        # 3 builders and final base image is scratch. builder 1 is reused twice, resulting in multiple properties
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256"
                ":2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder3/builder3:ccccccc@sha256"
                ":3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
            ],
            True,
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941"
                    "?repository_url=quay.io/builder1/builder1",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        },
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "2",
                        },
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "4",
                        },
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder2/builder2",
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942"
                    "?repository_url=quay.io/builder2/builder2",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "1",
                        }
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder3/builder3",
                    "purl": "pkg:oci/builder3@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943"
                    "?repository_url=quay.io/builder3/builder3",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "3",
                        }
                    ],
                },
            ],
        ),
        # 2 builders and builder 1 is then reused as final base image, resulting in multiple properties
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256"
                ":2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder1/builder1:aaaaaaa@sha256"
                ":1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
            ],
            False,
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941"
                    "?repository_url=quay.io/builder1/builder1",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        },
                        {
                            "name": "konflux:container:is_base_image",
                            "value": "true",
                        },
                    ],
                },
                {
                    "type": "container",
                    "name": "quay.io/builder2/builder2",
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942"
                    "?repository_url=quay.io/builder2/builder2",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "1",
                        }
                    ],
                },
            ],
        ),
    ],
)
def test_get_base_images_sbom_components(base_images_digests, is_last_from_scratch, expected_result):
    result = get_base_images_sbom_components(base_images_digests, is_last_from_scratch)
    assert result == expected_result


def test_main_input_sbom_does_not_contain_formulation(tmp_path, mocker):
    sbom_file = tmp_path / "sbom.json"
    base_images_from_dockerfile_file = tmp_path / "base_images_from_dockerfile.txt"
    base_images_digests_file = tmp_path / "base_images_digests.txt"

    # minimal input sbom file
    sbom_file.write_text(
        """{
    "bomFormat": "CycloneDX",
    "project_name": "MyProject",
    "version": "1.0",
    "components": []
    }"""
    )

    # one builder images and one base image
    base_images_from_dockerfile_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab\nregistry.access.redhat.com/ubi8/ubi:latest"
    )
    base_images_digests_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256"
        ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941\nregistry.access.redhat.com/ubi8/ubi"
        ":latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac "
    )

    # mock the parsed args, to avoid testing parse_args function
    mock_args = MagicMock(sbom_type="cyclonedx")
    mock_args.sbom = sbom_file
    mock_args.base_images_from_dockerfile = base_images_from_dockerfile_file
    mock_args.base_images_digests = base_images_digests_file
    mocker.patch("base_images_sbom_script.parse_args", return_value=mock_args)

    main()

    expected_output = {
        "formulation": [
            {
                "components": [
                    {
                        "type": "container",
                        "name": "quay.io/mkosiarc_rhtap/single-container-app",
                        "purl": "pkg:oci/single-container-app@sha256"
                        ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url"
                        "=quay.io/mkosiarc_rhtap/single-container-app",
                        "properties": [
                            {
                                "name": "konflux:container:is_builder_image:for_stage",
                                "value": "0",
                            }
                        ],
                    },
                    {
                        "type": "container",
                        "name": "registry.access.redhat.com/ubi8/ubi",
                        "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                        "?repository_url=registry.access.redhat.com/ubi8/ubi",
                        "properties": [
                            {
                                "name": "konflux:container:is_base_image",
                                "value": "true",
                            }
                        ],
                    },
                ]
            }
        ]
    }

    with sbom_file.open("r") as f:
        sbom = json.load(f)

    assert "formulation" in sbom
    assert expected_output["formulation"] == sbom["formulation"]


@pytest.fixture
def isodate():
    with patch("datetime.datetime") as mock_datetime:
        mock_datetime.now.return_value.isoformat.return_value = "2021-07-01T00:00:00Z"
        yield mock_datetime


def test_main_input_sbom_spdx_minimal(tmp_path, mocker, isodate):
    sbom_file = tmp_path / "sbom.json"
    base_images_from_dockerfile_file = tmp_path / "base_images_from_dockerfile.txt"
    base_images_digests_file = tmp_path / "base_images_digests.txt"

    # minimal input sbom file
    sbom_file.write_text(
        """{
    "SPDXID": "SPDXRef-Document",
    "spdxVersion": "SPDX-2.3",
    "name": "MyProject",
    "documentNamespace": "http://example.com/uid-1234",
    "packages": [],
    "relationships": []
    }"""
    )

    # one builder images and one base image
    base_images_from_dockerfile_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab\nregistry.access.redhat.com/ubi8/ubi:latest"
    )
    base_images_digests_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256"
        ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941\nregistry.access.redhat.com/ubi8/ubi"
        ":latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac "
    )

    # mock the parsed args, to avoid testing parse_args function
    mock_args = MagicMock(sbom_type="spdx")
    mock_args.sbom = sbom_file
    mock_args.base_images_from_dockerfile = base_images_from_dockerfile_file
    mock_args.base_images_digests = base_images_digests_file
    mocker.patch("base_images_sbom_script.parse_args", return_value=mock_args)

    main()

    expected_output = {
        "packages": [
            {
                "SPDXID": "SPDXRef-DocumentRoot-Unknown-",
                "downloadLocation": "NOASSERTION",
                "name": "",
            },
            {
                "SPDXID": "SPDXRef-container-quay.io/mkosiarc_rhtap/single-container-app-"
                "9520a72cbb69edfca5cac88ea2a9e0e09142ec934952b9420d686e77765f002c",
                "name": "quay.io/mkosiarc_rhtap/single-container-app",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:oci/single-container-app@sha256"
                        ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url"
                        "=quay.io/mkosiarc_rhtap/single-container-app",
                        "referenceCategory": "PACKAGE-MANAGER",
                    }
                ],
                "annotations": [
                    {
                        "annotator": "Tool:konflux:jsonencoded",
                        "annotationDate": "2021-07-01T00:00:00Z",
                        "annotationType": "OTHER",
                        "comment": '{"name":"konflux:container:is_builder_image:for_stage","value":"0"}',
                    }
                ],
            },
            {
                "name": "registry.access.redhat.com/ubi8/ubi",
                "SPDXID": "SPDXRef-container-registry.access.redhat.com/ubi8/ubi-"
                "0f22256f634f8205fbd9c438c387ccf2d4859250e04104571c93fdb89a62bae1",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:oci/ubi@sha256:"
                        "627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                        "?repository_url=registry.access.redhat.com/ubi8/ubi",
                    }
                ],
                "annotations": [
                    {
                        "annotator": "Tool:konflux:jsonencoded",
                        "annotationDate": "2021-07-01T00:00:00Z",
                        "annotationType": "OTHER",
                        "comment": '{"name":"konflux:container:is_base_image","value":"true"}',
                    }
                ],
            },
        ],
        "relationships": [
            {
                "relatedSpdxElement": "SPDXRef-DocumentRoot-Unknown-",
                "relationshipType": "DESCRIBES",
                "spdxElementId": "SPDXRef-Document",
            },
            {
                "relatedSpdxElement": "SPDXRef-DocumentRoot-Unknown-",
                "relationshipType": "BUILD_TOOL_OF",
                "spdxElementId": "SPDXRef-container-quay.io/mkosiarc_rhtap/"
                "single-container-app-9520a72cbb69edfca5cac88ea2a9e0e09142ec934952b9420d686e77765f002c",
            },
            {
                "spdxElementId": "SPDXRef-container-registry.access.redhat.com/"
                "ubi8/ubi-0f22256f634f8205fbd9c438c387ccf2d4859250e04104571c93fdb89a62bae1",
                "relationshipType": "BUILD_TOOL_OF",
                "relatedSpdxElement": "SPDXRef-DocumentRoot-Unknown-",
            },
        ],
    }

    with sbom_file.open("r") as f:
        sbom = json.load(f)

    assert expected_output["packages"] == sbom["packages"]
    assert expected_output["relationships"] == sbom["relationships"]


def test_main_input_sbom_does_not_contain_formulation_and_base_image_from_scratch(tmp_path, mocker):
    sbom_file = tmp_path / "sbom.json"
    base_images_from_dockerfile_file = tmp_path / "base_images_from_dockerfile.txt"
    base_images_digests_file = tmp_path / "base_images_digests.txt"

    # minimal input sbom file
    sbom_file.write_text(
        """{
    "project_name": "MyProject",
    "bomFormat": "CycloneDX",
    "version": "1.0",
    "components": []
    }"""
    )

    # two builder images and the last one is from scratch
    base_images_from_dockerfile_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab\nregistry.access.redhat.com/ubi8/ubi:latest\nscratch"
    )
    base_images_digests_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256"
        ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941\nregistry.access.redhat.com/ubi8/ubi"
        ":latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac "
    )

    # mock the parsed args, to avoid testing parse_args function
    mock_args = MagicMock(sbom_type="cyclonedx")
    mock_args.sbom = sbom_file
    mock_args.base_images_from_dockerfile = base_images_from_dockerfile_file
    mock_args.base_images_digests = base_images_digests_file
    mocker.patch("base_images_sbom_script.parse_args", return_value=mock_args)

    main()

    expected_output = {
        "formulation": [
            {
                "components": [
                    {
                        "type": "container",
                        "name": "quay.io/mkosiarc_rhtap/single-container-app",
                        "purl": "pkg:oci/single-container-app@sha256"
                        ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url"
                        "=quay.io/mkosiarc_rhtap/single-container-app",
                        "properties": [
                            {
                                "name": "konflux:container:is_builder_image:for_stage",
                                "value": "0",
                            }
                        ],
                    },
                    {
                        "type": "container",
                        "name": "registry.access.redhat.com/ubi8/ubi",
                        "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                        "?repository_url=registry.access.redhat.com/ubi8/ubi",
                        "properties": [
                            {
                                "name": "konflux:container:is_builder_image:for_stage",
                                "value": "1",
                            }
                        ],
                    },
                ]
            }
        ]
    }

    with sbom_file.open("r") as f:
        sbom = json.load(f)

    assert "formulation" in sbom
    assert expected_output["formulation"] == sbom["formulation"]


def test_main_input_sbom_contains_formulation(tmp_path, mocker):
    sbom_file = tmp_path / "sbom.json"
    base_images_from_dockerfile_file = tmp_path / "base_images_from_dockerfile.txt"
    base_images_digests_file = tmp_path / "base_images_digests.txt"

    # minimal sbom with existing formulation that contains components item
    sbom_file.write_text(
        """
    {
        "bomFormat": "CycloneDX",
        "project_name": "MyProject",
        "version": "1.0",
        "components": [],
        "formulation": [
            {
                "components": [
                    {
                        "type": "library",
                        "name": "fresh",
                        "version": "0.5.2",
                        "purl": "pkg:npm/fresh@0.5.2"
                    }
                ]
            }
        ]
    }
    """
    )

    # two builder images and the last one is from scratch
    base_images_from_dockerfile_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab\nregistry.access.redhat.com/ubi8/ubi:latest\nscratch"
    )
    base_images_digests_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256"
        ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941\nregistry.access.redhat.com/ubi8/ubi"
        ":latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac "
    )

    # mock the parsed args, to avoid testing parse_args function
    mock_args = MagicMock(sbom_type="cyclonedx")
    mock_args.sbom = sbom_file
    mock_args.base_images_from_dockerfile = base_images_from_dockerfile_file
    mock_args.base_images_digests = base_images_digests_file
    mocker.patch("base_images_sbom_script.parse_args", return_value=mock_args)

    main()

    expected_output = {
        "components": [
            {
                "type": "container",
                "name": "quay.io/mkosiarc_rhtap/single-container-app",
                "purl": "pkg:oci/single-container-app@sha256"
                ":8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io"
                "/mkosiarc_rhtap/single-container-app",
                "properties": [
                    {
                        "name": "konflux:container:is_builder_image:for_stage",
                        "value": "0",
                    }
                ],
            },
            {
                "type": "container",
                "name": "registry.access.redhat.com/ubi8/ubi",
                "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                "?repository_url=registry.access.redhat.com/ubi8/ubi",
                "properties": [
                    {
                        "name": "konflux:container:is_builder_image:for_stage",
                        "value": "1",
                    }
                ],
            },
        ]
    }

    with sbom_file.open("r") as f:
        sbom = json.load(f)

    # we are appending an item to the formulation key, so it should be at the end
    assert expected_output == sbom["formulation"][-1]


@pytest.mark.parametrize(
    "image, expected_parsed_image",
    [
        # basic example
        (
            "registry.access.redhat.com/ubi8/ubi:latest@sha256"
            ":627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ParsedImage(
                repository="registry.access.redhat.com/ubi8/ubi",
                digest="sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
                name="ubi",
            ),
        ),
        # missing tag
        (
            "registry.access.redhat.com/ubi8/ubi:<none>@sha256"
            ":627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ParsedImage(
                repository="registry.access.redhat.com/ubi8/ubi",
                digest="sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
                name="ubi",
            ),
        ),
        # registry with port
        (
            "some_registry_with_port:5000/ubi8/ubi:latest@sha256"
            ":627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ParsedImage(
                repository="some_registry_with_port:5000/ubi8/ubi",
                digest="sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
                name="ubi",
            ),
        ),
        # multiple path components
        (
            "quay.io/redhat-user-workloads/rh-acs-tenant/acs/collector:358b6cfb019e436d1fa61a09fcca04e081e1c993"
            "@sha256:8e5d62b32a5bb6d73ca7f54941f00ee8807563ddcb424660894dea85ed1f109d",
            ParsedImage(
                repository="quay.io/redhat-user-workloads/rh-acs-tenant/acs/collector",
                digest="sha256:8e5d62b32a5bb6d73ca7f54941f00ee8807563ddcb424660894dea85ed1f109d",
                name="collector",
            ),
        ),
    ],
)
def test_parse_image_reference_to_parts(image, expected_parsed_image):
    parsed_image = parse_image_reference_to_parts(image)
    assert parsed_image == expected_parsed_image
