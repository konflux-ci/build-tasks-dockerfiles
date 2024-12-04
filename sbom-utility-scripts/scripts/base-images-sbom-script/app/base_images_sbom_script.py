import json
import argparse
import pathlib

from collections import namedtuple
from packageurl import PackageURL

ParsedImage = namedtuple("ParsedImage", "repository, digest, name")


def parse_image_reference_to_parts(image):
    """
    This function expects that the image is in the expected format
    as generated from the output of
    "buildah images --format '{{ .Name }}:{{ .Tag }}@{{ .Digest }}'"

    :param image: (str) image reference
    :return: ParsedImage (namedTuple): the image parsed into individual parts
    """

    # example image: registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac # noqa
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


def get_base_images_sbom_components(base_images, base_images_digests):
    """
    Creates the base images sbom data

    :param base_images: (List) - List of base images used during build, in the order they were used. The values here
                                 are the keys in the base_images_digests dict.
                                 For example:
                                 ["registry.access.redhat.com/ubi8/ubi:latest"]
    :param base_images_digests: (Dict) - Dict of base images references, where the key is the image reference as
                                         used in the original Dockerfile (The elements of base_images param)
                                         and the values are the full image reference with digests that was
                                         actually used by buildah during build time.
                                         For example:
                                         {
                                           "registry.access.redhat.com/ubi8/ubi:latest":
                                           "registry.access.redhat.com/ubi8/ubi:latest@sha256:627867e53ad6846afba2dfbf5cef1d54c868a9025633ef0afd546278d4654eac"
                                         }
    :return: components (List) - List of dict items in which each item contains sbom data about each base image
    """

    components = []
    already_used_base_images = set()

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
            component = {
                "type": "container",
                "name": parsed_image.repository,
                "purl": purl_str,
                "properties": [{"name": property_name, "value": property_value}],
            }
            components.append(component)
            already_used_base_images.add(purl_str)

    return components


def get_base_images_from_dockerfile(parsed_dockerfile):
    """
    Reads the base images from provided parsed dockerfile

    :param parsed_dockerfile: (Dict) - Contents of the parsed dockerfile
    :return: base_images (List) - List of base images used during build as extracted
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
    base_images = []

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


def parse_args():
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


def main():

    args = parse_args()

    with args.parsed_dockerfile.open("r") as f:
        parsed_dockerfile = json.load(f)

    base_images = get_base_images_from_dockerfile(parsed_dockerfile)

    base_images_digests_raw = args.base_images_digests.read_text().splitlines()
    base_images_digests = dict(item.split() for item in base_images_digests_raw)

    with args.sbom.open("r") as f:
        sbom = json.load(f)

    base_images_sbom_components = get_base_images_sbom_components(base_images, base_images_digests)

    # base_images_sbom_components could be empty, when having just one stage FROM scratch
    if base_images_sbom_components:
        if "formulation" in sbom:
            sbom["formulation"].append({"components": base_images_sbom_components})
        else:
            sbom.update({"formulation": [{"components": base_images_sbom_components}]})

    with args.sbom.open("w") as f:
        json.dump(sbom, f, indent=4)


if __name__ == "__main__":
    main()
