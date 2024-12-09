# base images sbom script

This is a script that creates sbom data for base images. It is used in 
[buildah task](https://github.com/konflux-ci/build-definitions/tree/main/task/buildah) in Konflux pipelines.

It takes several inputs:
1. path to the sbom file, that will be updated in place with the base image data
2. path to a json file containing parsed Dockerfile via dockerfile-json
3. path to a file containing base images references as used during in the Dockerfile mapped to the full image references 
with digests. This mapping is expected to be in the format `<image-reference-used-in-dockerfile> <full-image-reference-with-digest>`.
The full image reference with digest is generated from the output of `buildah images --format '{{ .Name }}:{{ .Tag }}@{{ .Digest }}'`.

## CycloneDX

The base images data will be added in the [formulation attribute](https://cyclonedx.org/docs/1.5/json/#formulation), by appending new item with the **components** array.
This will not affect any other items in the formulation array. If the formulation part of the sbom does not exist, it is created.
The result might look like this:

```
    ...
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
                    ]
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
                    ]
                }
            ]
        }
    ]
    ...
```

If a base image is used multiple times, only one component with multiple properties will be created e.g.:
```
{
                    "type": "container",
                    "name": "quay.io/builder1/builder1",
                    "purl": "pkg:oci/builder1@sha256:1f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941"?repository_url=quay.io/builder1/builder1",
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
```

## SPDX

The script adds the base images to the `.packages` array in the SBOM and adds
`<BASE_IMAGE> BUILD_TOOL_OF <ROOT>` relationships to the `.relationships` array.

Where the CycloneDX SBOM uses `.properties` to indicate whether the image is a "builder"
image or a base image for SPDX we use annotations instead
(see the [relevant section of the ADR][spdx-adr-properties]).

The result might look something like this:

```
{
    // ...
    "packages": [
        // ...
        {
            "SPDXID": "SPDXRef-image-quay.io/mkosiarc_rhtap/single-container-app-9520a72cbb69edfca5cac88ea2a9e0e09142ec934952b9420d686e77765f002c",
            "name": "quay.io/mkosiarc_rhtap/single-container-app",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:oci/single-container-app@sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941?repository_url=quay.io/mkosiarc_rhtap/single-container-app"
                }
            ],
            "annotations": [
                {
                    "annotator": "Tool: konflux:jsonencoded",
                    "comment": "{\"name\":\"konflux:container:is_builder_image:for_stage\",\"value\":\"0\"}",
                    "annotationDate": "2024-12-09T12:00:00Z",
                    "annotationType": "OTHER"
                }
            ]
        },
        {
            "SPDXID": "SPDXRef-image-registry.access.redhat.com/ubi8/ubi-0f22256f634f8205fbd9c438c387ccf2d4859250e04104571c93fdb89a62bae1",
            "name": "registry.access.redhat.com/ubi8/ubi",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:oci/ubi@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac?repository_url=registry.access.redhat.com/ubi8/ubi"
                }
            ],
            "annotations": [
                {
                    "annotator": "Tool: konflux:jsonencoded",
                    "comment": "{\"name\":\"konflux:container:is_builder_image:for_stage\",\"value\":\"1\"}",
                    "annotationDate": "2024-12-09T12:00:00Z",
                    "annotationType": "OTHER"
                }
            ]
        }
    ],
    "relationships": [
        // ...
        {
            "spdxElementId": "SPDXRef-image-quay.io/mkosiarc_rhtap/single-container-app-9520a72cbb69edfca5cac88ea2a9e0e09142ec934952b9420d686e77765f002c",
            "relationshipType": "BUILD_TOOL_OF",
            "relatedSpdxElement": "SPDXRef-main"
        },
        {
            "spdxElementId": "SPDXRef-image-registry.access.redhat.com/ubi8/ubi-0f22256f634f8205fbd9c438c387ccf2d4859250e04104571c93fdb89a62bae1",
            "relationshipType": "BUILD_TOOL_OF",
            "relatedSpdxElement": "SPDXRef-main"
        }
    ]
}
```

## The image
The image that is used in the buildah task in Konflux is built by the Github CI and pushed to
**quay.io/redhat-appstudio/base-images-sbom-script** tagged with the commit sha.

## Tests
The unit tests are triggered on each pull requests in Github CI via tox. You can run them locally
during development with:

```
tox -e test
```

[spdx-adr-properties]: https://github.com/konflux-ci/architecture/blob/main/ADR/0044-spdx-support.md#componentproperties
