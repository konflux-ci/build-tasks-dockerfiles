import argparse
import datetime
import hashlib
import json
import pathlib
from typing import Any, Literal, NamedTuple, NewType, TypedDict

from packageurl import PackageURL


class ParsedImage(NamedTuple):
    repository: str
    digest: str
    name: str


class CDXComponent(TypedDict):
    """The relevant attributes of a CycloneDX Component."""

    type: str
    name: str
    purl: str
    properties: list[dict[str, str]]


SPDXID = NewType("SPDXID", str)


class SPDXPackage(TypedDict):
    """The relevant attributes of an SPDX Package (the equivalent of a CycloneDX Component)."""

    # SPDXID, name and downloadLocation are required per the SPDX 2.3 schema
    # https://github.com/spdx/spdx-spec/blob/ed8c9b520963b651fce3c86422b387e92e6d9a8f/schemas/spdx-schema.json#L438
    SPDXID: SPDXID
    name: str
    downloadLocation: str
    externalRefs: list[dict[str, str]]
    annotations: list[dict[str, str]]


def parse_image_reference_to_parts(image: str) -> ParsedImage:
    """
    This function expects that the image is in the expected format
    as generated from the output of
    "buildah images --format '{{ .Name }}:{{ .Tag }}@{{ .Digest }}'"

    :param image: (str) image reference
    :return: ParsedImage (namedTuple): the image parsed into individual parts
    """

    # example image: registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac
    # repository_with_tag = registry.access.redhat.com/ubi8/ubi:latest
    # digest = sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac
    # repository = registry.access.redhat.com/ubi8/ubi
    # name = ubi
    repository_with_tag, digest = image.split("@")
    # splitting from the right side once on colon to get rid of the tag,
    # as the repository part might contain registry url containing a port (host:port)
    repository, _ = repository_with_tag.rsplit(":", 1)
    # name is the last fragment of the repository
    name = repository.split("/")[-1]

    return ParsedImage(repository=repository, digest=digest, name=name)


def get_base_images_sbom_components(base_images: list[str], base_images_digests: dict[str, str]) -> list[CDXComponent]:
    """
    Creates the base images sbom data

    :param base_images: List of base images used during build, in the order they were used. The values here
                        are the keys in the base_images_digests dict.
                        For example:
                        ["registry.access.redhat.com/ubi8/ubi:latest"]
    :param base_images_digests: Dict of base images references, where the key is the image reference as
                                used in the original Dockerfile (The elements of base_images param)
                                and the values are the full image reference with digests that was
                                actually used by buildah during build time.
                                For example:
                                {
                                  "registry.access.redhat.com/ubi8/ubi:latest":
                                  "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                                }
    :return: List of dict items in which each item contains sbom data about each base image
    """

    components: list[CDXComponent] = []
    already_used_base_images: set[str] = set()

    for index, image in enumerate(base_images):
        # flatpak archive and scratch are not real base images. So we skip them, but
        # in a way that allows us to keep the correct track of index variable that
        # refers to stage number.
        if image.startswith("oci-archive") or image == "scratch":
            continue

        # property_name shows whether the image was used only in the building process
        # or if it is the final base image.
        property_name = "konflux:container:is_builder_image:for_stage"
        property_value = str(index)

        # This is not reached if the last "image" was scratch or oci-archive.
        # That is because we don't consider them base images, and we aren't putting
        # them in SBOM
        if index == len(base_images) - 1:
            property_name = "konflux:container:is_base_image"
            property_value = "true"

        # It could happen that we have a base image from the parsed Dockerfile, but we don't have
        # a digest reference for it. This could happen when buildah skipped the stage, due to optimization
        # when it is unreachable, or redundant. Since in this case, it was not used in the actual build,
        # it is ok to just skip these stages
        base_image_digest = base_images_digests.get(image)
        if not base_image_digest:
            continue
        parsed_image = parse_image_reference_to_parts(base_image_digest)

        purl = PackageURL(
            type="oci",
            name=parsed_image.name,
            version=parsed_image.digest,
            qualifiers={
                "repository_url": parsed_image.repository,
            },
        )
        purl_str = purl.to_string()

        # If the base image is used in multiple stages then instead of adding another component
        # only additional property is added to the existing component
        if purl_str in already_used_base_images:
            property = {"name": property_name, "value": property_value}
            for component in components:
                if component["purl"] == purl_str:
                    component["properties"].append(property)
        else:
            component: CDXComponent = {
                "type": "container",
                "name": parsed_image.repository,
                "purl": purl_str,
                "properties": [{"name": property_name, "value": property_value}],
            }
            components.append(component)
            already_used_base_images.add(purl_str)

    return components


def get_base_images_from_dockerfile(parsed_dockerfile: dict[str, Any]) -> list[str]:
    """
    Reads the base images from provided parsed dockerfile

    :param parsed_dockerfile: Contents of the parsed dockerfile
    :return: base_images List of base images used during build as extracted
                         from the dockerfile in the order they were used.

    Example:
    If the Dockerfile looks like
    FROM registry.access.redhat.com/ubi8/ubi:latest as builder
    ...
    FROM builder
    ...

    Then the relevant part of parsed_dockerfile look like
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
    """
    base_images: list[str] = []

    # this part of the json is the relevant one that contains the
    # info about base images
    stages = parsed_dockerfile["Stages"]

    for stage in stages:
        if "Image" in stage["From"]:
            base_images.append(stage["From"]["Image"])
        elif "Scratch" in stage["From"]:
            base_images.append("scratch")
        elif "Stage" in stage["From"]:
            stage_index = stage["From"]["Stage"]["Index"]
            # Find the original stage/image. Named stage can refer to another named stage,
            # so continue looking until we find the image those stages refer to.
            while stage_index is not None:
                refered_stage = stages[stage_index]
                stage_index = refered_stage.get("From").get("Stage", {}).get("Index", None)
                if stage_index is None:
                    base_images.append(refered_stage["From"]["Image"])

    return base_images


def cdx_to_spdx(cdx: CDXComponent, annotation_date: datetime.datetime) -> SPDXPackage:
    name = cdx["name"]
    purl = cdx["purl"]
    # consistent with index_image_sbom_script.py
    spdxid = SPDXID(f"SPDXRef-image-{name}-{hashlib.sha256(purl.encode()).hexdigest()}")

    return {
        "SPDXID": spdxid,
        "name": name,
        "downloadLocation": "NOASSERTION",
        # https://github.com/konflux-ci/architecture/blob/main/ADR/0044-spdx-support.md#componentpurl
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            },
        ],
        # https://github.com/konflux-ci/architecture/blob/main/ADR/0044-spdx-support.md#componentproperties
        "annotations": [
            {
                "annotator": "Tool: konflux:jsonencoded",
                "comment": json.dumps(cdx_property, separators=(",", ":")),
                # https://spdx.github.io/spdx-spec/v2.3/annotations/#122-annotation-date-field
                "annotationDate": annotation_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "annotationType": "OTHER",
            }
            for cdx_property in cdx["properties"]
        ],
    }


def find_spdx_root_package(sbom: dict[str, Any]) -> SPDXID:
    """Find the element that's in relationship <DOCUMENT> DESCRIBES <ELEMENT>.

    If there isn't exactly one such element, raise an error.
    """
    doc_spxid = sbom["SPDXID"]
    doc_describes = [
        r["relatedSpdxElement"]
        for r in sbom.get("relationships", [])
        if r["spdxElementId"] == doc_spxid and r["relationshipType"] == "DESCRIBES"
    ]
    if len(doc_describes) != 1:
        raise ValueError(
            "Expected to find exactly one <DOCUMENT> DESCRIBES <ROOT> relationship. "
            f"Found {len(doc_describes)} ROOTs: {doc_describes}"
        )
    return SPDXID(doc_describes[0])


def update_cyclonedx_sbom(sbom: dict[str, Any], base_images: list[CDXComponent]) -> None:
    """Update (in-place) a CycloneDX SBOM with a list of base images.

    Add an item containing the base image list into the .formulation section.

    :param base_images: list of base images in CycloneDX format
    """
    sbom.setdefault("formulation", []).append({"components": base_images})


def update_spdx_sbom(sbom: dict[str, Any], base_images: list[SPDXPackage]) -> None:
    """Update (in-place) an SPDX SBOM with a list of base images.

    Add the base images to the .packages section.
    Add <BASE_IMAGE> BUILD_TOOL_OF <ROOT> relationships to the .relationships section.

    :param base_images: list of base images in SPDX format
    """
    root = find_spdx_root_package(sbom)
    relationships = [
        {
            "spdxElementId": base_image["SPDXID"],
            "relationshipType": "BUILD_TOOL_OF",
            "relatedSpdxElement": root,
        }
        for base_image in base_images
    ]

    sbom.setdefault("packages", []).extend(base_images)
    sbom.setdefault("relationships", []).extend(relationships)


def detect_sbom_type(sbom: dict[str, Any]) -> Literal["cyclonedx", "spdx"]:
    if sbom.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    elif sbom.get("spdxVersion"):
        return "spdx"
    else:
        raise ValueError("Unknown SBOM format")


def _datetime_utc_now() -> datetime.datetime:
    # a mockable datetime.datetime.now (just for tests):
    return datetime.datetime.now(datetime.UTC)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Updates the sbom file with base images data based on the provided files"
    )
    parser.add_argument("--sbom", type=pathlib.Path, help="Path to the sbom file", required=True)
    parser.add_argument(
        "--parsed-dockerfile",
        type=pathlib.Path,
        help="Path to the file containing parsed Dockerfile in json format extracted "
        "from dockerfile-json in buildah task",
        required=True,
    )
    parser.add_argument(
        "--base-images-digests",
        type=pathlib.Path,
        help="Path to the file containing base images digests."
        " This is taken from the base_images_digests file that was generated from"
        "the output of 'buildah images'",
        required=True,
    )
    args = parser.parse_args()

    return args


def main() -> None:
    args = parse_args()

    with args.parsed_dockerfile.open("r") as f:
        parsed_dockerfile = json.load(f)

    base_images = get_base_images_from_dockerfile(parsed_dockerfile)

    base_images_digests_raw = args.base_images_digests.read_text().splitlines()
    base_images_digests = dict(item.split() for item in base_images_digests_raw)

    base_images_sbom_components = get_base_images_sbom_components(base_images, base_images_digests)
    # base_images_sbom_components could be empty, when having just one stage FROM scratch
    if not base_images_sbom_components:
        return

    with args.sbom.open("r") as f:
        sbom = json.load(f)

    if detect_sbom_type(sbom) == "cyclonedx":
        update_cyclonedx_sbom(sbom, base_images_sbom_components)
    else:
        annotation_date = _datetime_utc_now()
        base_images_spdx = [cdx_to_spdx(c, annotation_date) for c in base_images_sbom_components]
        update_spdx_sbom(sbom, base_images_spdx)

    with args.sbom.open("w") as f:
        json.dump(sbom, f, indent=4)


if __name__ == "__main__":
    main()
