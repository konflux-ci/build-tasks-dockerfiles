import pytest
import json

from unittest.mock import MagicMock

from base_images_sbom_script import (
    get_base_images_sbom_components,
    get_base_images_from_dockerfile,
    main,
    parse_image_reference_to_parts,
    ParsedImage,
)


@pytest.mark.parametrize(
    "base_images, base_images_digests, expected_result",
    [
        # two builder images, last stage is from scratch
        (
            [
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                "registry.access.redhat.com/ubi8/ubi:latest",
                "scratch",
            ],
            {
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "registry.access.redhat.com/ubi8/ubi:latest": "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/mkosiarc_rhtap/single-container-app",
                    "purl": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
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
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac?repository_url=registry.access.redhat.com/ubi8/ubi",
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
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
            {
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "registry.access.redhat.com/ubi8/ubi:latest": "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/mkosiarc_rhtap/single-container-app",
                    "purl": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
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
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac?repository_url=registry.access.redhat.com/ubi8/ubi",
                    "properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
                },
            ],
        ),
        # just one parent image
        (
            ["registry.access.redhat.com/ubi8/ubi:latest"],
            {
                "registry.access.redhat.com/ubi8/ubi:latest": "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            },
            [
                {
                    "type": "container",
                    "name": "registry.access.redhat.com/ubi8/ubi",
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac?repository_url=registry.access.redhat.com/ubi8/ubi",
                    "properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
                },
            ],
        ),
        # one builder, last stage from scratch
        (
            ["quay.io/mkosiarc_rhtap/single-container-app:f2566ab", "scratch"],
            {
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/mkosiarc_rhtap/single-container-app",
                    "purl": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                },
            ],
        ),
        # four builder images, and from scratch in last stage
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944",
                "scratch",
            ],
            {
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941": "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942": "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943": "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944": "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/builder1/builder1",
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
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942?repository_url=quay.io/builder2/builder2",
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
                    "purl": "pkg:oci/builder3@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943?repository_url=quay.io/builder3/builder3",
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
                    "purl": "pkg:oci/builder4@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944?repository_url=quay.io/builder4/builder4",
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
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944",
                "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ],
            {
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941": "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942": "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943": "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944": "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944",
                "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac": "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/builder1/builder1",
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
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942?repository_url=quay.io/builder2/builder2",
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
                    "purl": "pkg:oci/builder3@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943?repository_url=quay.io/builder3/builder3",
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
                    "purl": "pkg:oci/builder4@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944?repository_url=quay.io/builder4/builder4",
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
                    "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac?repository_url=registry.access.redhat.com/ubi8/ubi",
                    "properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
                },
            ],
        ),
        # 3 builders and one final base image. builder 1 is reused three times, resulting in multiple properties
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ],
            {
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941": "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942": "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943": "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944": "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944",
                "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac": "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/builder1/builder1",
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
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942?repository_url=quay.io/builder2/builder2",
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
                    "purl": "pkg:oci/builder3@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943?repository_url=quay.io/builder3/builder3",
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
        # 3 builders and final base image is scratch. builder 1 is reused three times, resulting in multiple properties
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "scratch",
            ],
            {
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941": "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942": "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943": "quay.io/builder3/builder3:ccccccc@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943",
                "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944": "quay.io/builder4/builder4:ddddddd@sha256:4f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420944",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/builder1/builder1",
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
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942?repository_url=quay.io/builder2/builder2",
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
                    "purl": "pkg:oci/builder3@sha256:3f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420943?repository_url=quay.io/builder3/builder3",
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
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
            ],
            {
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941": "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942": "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/builder1/builder1",
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
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942?repository_url=quay.io/builder2/builder2",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "1",
                        }
                    ],
                },
            ],
        ),
        # Two images, both reused and several oci-archives and from scratch layers
        (
            [
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "scratch",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "scratch",
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "oci-archive:export/out.ociarchive",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
                "oci-archive:export/out.ociarchive",
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
            ],
            {
                "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941": "quay.io/builder1/builder1:aaaaaaa@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
                "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942": "quay.io/builder2/builder2:bbbbbbb@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/builder1/builder1",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        },
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "4",
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
                    "purl": "pkg:oci/builder2@sha256:2f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420942?repository_url=quay.io/builder2/builder2",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "2",
                        },
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "6",
                        },
                    ],
                },
            ],
        ),
        # one builder, last stage from oci-archive
        (
            [
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                "oci-archive:export/out.ociarchive",
            ],
            {
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941",
            },
            [
                {
                    "type": "container",
                    "name": "quay.io/mkosiarc_rhtap/single-container-app",
                    "purl": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
                    "properties": [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                },
            ],
        ),
        # just from scratch
        (
            ["scratch"],
            {},  # empty base_images_digests
            [],  # SBOM not created
        ),
    ],
)
def test_get_base_images_sbom_components(base_images, base_images_digests, expected_result):
    result = get_base_images_sbom_components(base_images, base_images_digests)
    assert result == expected_result


def test_main_input_sbom_does_not_contain_formulation(tmp_path, mocker):
    sbom_file = tmp_path / "sbom.json"
    parsed_dockerfile = tmp_path / "parsed_dockerfile.json"
    base_images_digests_raw_file = tmp_path / "base_images_digests.txt"

    # minimal input sbom file
    sbom_file.write_text(
        """{
    "bomFormat": "CycloneDX",
    "version": "1.0",
    "components": []
    }"""
    )

    # one builder images and one base image
    parsed_dockerfile.write_text(
        """
        {
            "Stages": [
                {
                    "From": {
                        "Image": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab"
                    }
                },
                {
                    "From": {
                        "Image": "registry.access.redhat.com/ubi8/ubi:latest"
                    }
                }
            ]
        }
        """
    )
    base_images_digests_raw_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941\n"
        "registry.access.redhat.com/ubi8/ubi:latest registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
    )

    # mock the parsed args, to avoid testing parse_args function
    mock_args = MagicMock()
    mock_args.sbom = sbom_file
    mock_args.parsed_dockerfile = parsed_dockerfile
    mock_args.base_images_digests = base_images_digests_raw_file
    mocker.patch("base_images_sbom_script.parse_args", return_value=mock_args)

    main()

    expected_output = {
        "formulation": [
            {
                "components": [
                    {
                        "type": "container",
                        "name": "quay.io/mkosiarc_rhtap/single-container-app",
                        "purl": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
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
                        "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac?repository_url=registry.access.redhat.com/ubi8/ubi",
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


def test_main_input_sbom_does_not_contain_formulation_and_base_image_from_scratch(tmp_path, mocker):
    sbom_file = tmp_path / "sbom.json"
    parsed_dockerfile = tmp_path / "parsed_dockerfile.json"
    base_images_digests_raw_file = tmp_path / "base_images_digests.txt"

    # minimal input sbom file
    sbom_file.write_text(
        """{
    "bomFormat": "CycloneDX",
    "version": "1.0",
    "components": []
    }"""
    )

    # two builder images and the last one is from scratch
    parsed_dockerfile.write_text(
        """
        {
            "Stages": [
                {
                    "From": {
                        "Image": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab"
                    }
                },
                {
                    "From": {
                        "Image": "registry.access.redhat.com/ubi8/ubi:latest"
                    }
                },
                {
                    "From": {
                        "Scratch": true
                    }
                }
            ]
        }
        """
    )
    base_images_digests_raw_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941\n"
        "registry.access.redhat.com/ubi8/ubi:latest registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
    )

    # mock the parsed args, to avoid testing parse_args function
    mock_args = MagicMock()
    mock_args.sbom = sbom_file
    mock_args.parsed_dockerfile = parsed_dockerfile
    mock_args.base_images_digests = base_images_digests_raw_file
    mocker.patch("base_images_sbom_script.parse_args", return_value=mock_args)

    main()

    expected_output = {
        "formulation": [
            {
                "components": [
                    {
                        "type": "container",
                        "name": "quay.io/mkosiarc_rhtap/single-container-app",
                        "purl": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
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
                        "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac?repository_url=registry.access.redhat.com/ubi8/ubi",
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
    parsed_dockerfile = tmp_path / "parsed_dockerfile.json"
    base_images_digests_raw_file = tmp_path / "base_images_digests.txt"

    # minimal sbom with existing formulation that contains components item
    sbom_file.write_text(
        """
    {
        "bomFormat": "CycloneDX",
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
    parsed_dockerfile.write_text(
        """
        {
            "Stages": [
                {
                    "From": {
                        "Image": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab"
                    }
                },
                {
                    "From": {
                        "Image": "registry.access.redhat.com/ubi8/ubi:latest"
                    }
                },
                {
                    "From": {
                        "Scratch": true
                    }
                }
            ]
        }
        """
    )
    base_images_digests_raw_file.write_text(
        "quay.io/mkosiarc_rhtap/single-container-app:f2566ab quay.io/mkosiarc_rhtap/single-container-app:f2566ab@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941\n"
        "registry.access.redhat.com/ubi8/ubi:latest registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
    )

    # mock the parsed args, to avoid testing parse_args function
    mock_args = MagicMock()
    mock_args.sbom = sbom_file
    mock_args.parsed_dockerfile = parsed_dockerfile
    mock_args.base_images_digests = base_images_digests_raw_file
    mocker.patch("base_images_sbom_script.parse_args", return_value=mock_args)

    main()

    expected_output = {
        "components": [
            {
                "type": "container",
                "name": "quay.io/mkosiarc_rhtap/single-container-app",
                "purl": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app",
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
                "purl": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac?repository_url=registry.access.redhat.com/ubi8/ubi",
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
            "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ParsedImage(
                repository="registry.access.redhat.com/ubi8/ubi",
                digest="sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
                name="ubi",
            ),
        ),
        # missing tag
        (
            "registry.access.redhat.com/ubi8/ubi:<none>@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ParsedImage(
                repository="registry.access.redhat.com/ubi8/ubi",
                digest="sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
                name="ubi",
            ),
        ),
        # registry with port
        (
            "some_registry_with_port:5000/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
            ParsedImage(
                repository="some_registry_with_port:5000/ubi8/ubi",
                digest="sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac",
                name="ubi",
            ),
        ),
        # multiple path components
        (
            "quay.io/redhat-user-workloads/rh-acs-tenant/acs/collector:358b6cfb019e436d1fa61a09fcca04e081e1c993@sha256:8e5d62b32a5bb6d73ca7f54941f00ee8807563ddcb424660894dea85ed1f109d",
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


@pytest.mark.parametrize(
    "parsed_dockerfile, expected_base_images",
    [
        # basic example
        # FROM quay.io/mkosiarc_rhtap/single-container-app:f2566ab
        # ...
        # FROM registry.access.redhat.com/ubi8/ubi:latest
        # ...
        (
            {
                "Stages": [
                    {
                        "BaseName": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                        "From": {"Image": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab"},
                    },
                    {
                        "BaseName": "registry.access.redhat.com/ubi8/ubi:latest",
                        "From": {"Image": "registry.access.redhat.com/ubi8/ubi:latest"},
                    },
                ]
            },
            [
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
        ),
        # basic example with scratch stage
        # FROM quay.io/mkosiarc_rhtap/single-container-app:f2566ab
        # ...
        # FROM registry.access.redhat.com/ubi8/ubi:latest
        # ...
        # FROM scratch
        # ...
        (
            {
                "Stages": [
                    {
                        "BaseName": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                        "From": {"Image": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab"},
                    },
                    {
                        "BaseName": "registry.access.redhat.com/ubi8/ubi:latest",
                        "From": {"Image": "registry.access.redhat.com/ubi8/ubi:latest"},
                    },
                    {"BaseName": "scratch", "From": {"Scratch": True}},
                ]
            },
            [
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                "registry.access.redhat.com/ubi8/ubi:latest",
                "scratch",
            ],
        ),
        # just from scratch
        (
            {
                "Stages": [
                    {"BaseName": "scratch", "From": {"Scratch": True}},
                ]
            },
            [
                "scratch",
            ],
        ),
        # Multiple images which are reused, including two scratch stages and two oci-archive stages
        # FROM quay.io/mkosiarc_rhtap/single-container-app:f2566ab
        # ...
        # FROM scratch
        # ...
        # FROM quay.io/mkosiarc_rhtap/single-container-app:f2566ab
        # ...
        # FROM oci-archive:export/out.ociarchive
        # ...
        # FROM registry.access.redhat.com/ubi8/ubi:latest
        # ...
        # FROM scratch
        # ...
        # FROM oci-archive:export/out.ociarchive
        # ...
        (
            {
                "Stages": [
                    {
                        "BaseName": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                        "From": {"Image": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab"},
                    },
                    {"BaseName": "scratch", "From": {"Scratch": True}},
                    {
                        "BaseName": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                        "From": {"Image": "quay.io/mkosiarc_rhtap/single-container-app:f2566ab"},
                    },
                    {
                        "BaseName": "oci-archive:export/out.ociarchive",
                        "From": {"Image": "oci-archive:export/out.ociarchive"},
                    },
                    {
                        "BaseName": "registry.access.redhat.com/ubi8/ubi:latest",
                        "From": {"Image": "registry.access.redhat.com/ubi8/ubi:latest"},
                    },
                    {"BaseName": "scratch", "From": {"Scratch": True}},
                    {
                        "BaseName": "oci-archive:export/out.ociarchive",
                        "From": {"Image": "oci-archive:export/out.ociarchive"},
                    },
                ]
            },
            [
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                "scratch",
                "quay.io/mkosiarc_rhtap/single-container-app:f2566ab",
                "oci-archive:export/out.ociarchive",
                "registry.access.redhat.com/ubi8/ubi:latest",
                "scratch",
                "oci-archive:export/out.ociarchive",
            ],
        ),
        # alias/named stage, so something like
        # FROM registry.access.redhat.com/ubi8/ubi:latest as builder
        # ...
        # FROM builder
        # ...
        (
            {
                "Stages": [
                    {
                        "BaseName": "registry.access.redhat.com/ubi8/ubi:latest",
                        "As": "builder",
                        "From": {"Image": "registry.access.redhat.com/ubi8/ubi:latest"},
                    },
                    {
                        "BaseName": "builder",
                        "From": {"Stage": {"Named": "builder", "Index": 0}},
                    },
                ]
            },
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
        ),
        # alias to an alias, so something like
        # FROM registry.access.redhat.com/ubi8/ubi:latest as builder
        # ...
        # FROM builder as stage1
        # ...
        # FROM stage1 as stage2
        # ...
        (
            {
                "Stages": [
                    {
                        "BaseName": "registry.access.redhat.com/ubi8/ubi:latest",
                        "As": "builder",
                        "From": {"Image": "registry.access.redhat.com/ubi8/ubi:latest"},
                    },
                    {
                        "BaseName": "builder",
                        "As": "stage1",
                        "From": {"Stage": {"Named": "builder", "Index": 0}},
                    },
                    {
                        "BaseName": "stage1",
                        "As": "stage2",
                        "From": {"Stage": {"Named": "stage1", "Index": 1}},
                    },
                ]
            },
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "registry.access.redhat.com/ubi8/ubi:latest",
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
        ),
    ],
)
def test_get_base_images_from_dockerfile(parsed_dockerfile, expected_base_images):
    actual_base_images = get_base_images_from_dockerfile(parsed_dockerfile)
    assert actual_base_images == expected_base_images
