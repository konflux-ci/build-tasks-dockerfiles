import argparse
import hashlib
import json
import datetime
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


def get_base_images_sbom_components(base_images_digests, is_last_from_scratch):
    """
    Creates the base images sbom data

    :param base_images_digests: (List) - list of base images digests, same as BASE_IMAGE_DIGESTS tekton result
    :param is_last_from_scratch: (Boolean) - Is the last stage/base image from scratch?
    :return: components (List) - List of dict items in which each item contains sbom data about each base image
    """

    components = []
    already_used_base_images = set()

    # property_name shows whether the image was used only in the building process
    # or if it is the final base image. If the final base image is scratch, then
    # this is omitted, because we aren't including scratch in the sbom.
    for index, image in enumerate(base_images_digests):
        property_name = "konflux:container:is_builder_image:for_stage"
        property_value = str(index)
        if index == len(base_images_digests) - 1 and not is_last_from_scratch:
            property_name = "konflux:container:is_base_image"
            property_value = "true"

        parsed_image = parse_image_reference_to_parts(image)

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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Updates the sbom file with base images data based on the provided files"
    )
    parser.add_argument("--sbom", type=pathlib.Path, help="Path to the sbom file", required=True)
    parser.add_argument(
        "--sbom-type",
        choices=["spdx", "cyclonedx"],
        default="cyclonedx",
        help="Type of the sbom file",
        required=True,
    )
    parser.add_argument(
        "--base-images-from-dockerfile",
        type=pathlib.Path,
        help="Path to the file containing base images extracted from Dockerfile via grep, sed and awk in the buildah "
        "task",
        required=True,
    )
    parser.add_argument(
        "--base-images-digests",
        type=pathlib.Path,
        help="Path to the file containing base images digests."
        " This is taken from the BASE_IMAGES_DIGEST tekton result that was generated from"
        "the output of 'buildah images'",
        required=True,
    )
    args = parser.parse_args()

    return args


def map_relationships(relationships):
    """Map relationships of spdx element.
    Method returns triplet containing root element, map of relations and inverse map of relations.
    Root element is considered as element which is not listed as related document
    in any of the relationships. Relationship map is dict of {key: value} where key is spdx
    element and list of related elements is the value.
    Inverse map is dict of {key: value} where key is related spdx element in the relation ship
    and value is spdx element.
    """

    relations_map = {}
    relations_inverse_map = {}

    for relation in relationships:
        relations_map.setdefault(relation["spdxElementId"], []).append(relation["relatedSpdxElement"])
        relations_inverse_map[relation["relatedSpdxElement"]] = relation["spdxElementId"]

    parent_element = None
    for parent_element in relations_map.keys():
        if parent_element not in relations_inverse_map:
            break
    return parent_element, relations_map, relations_inverse_map


def main():

    args = parse_args()

    base_images_from_dockerfile = args.base_images_from_dockerfile.read_text().splitlines()
    base_images_digests = args.base_images_digests.read_text().splitlines()

    is_last_from_scratch = False
    if base_images_from_dockerfile[-1] == "scratch":
        is_last_from_scratch = True

    with args.sbom.open("r") as f:
        sbom = json.load(f)

    base_images_sbom_components = get_base_images_sbom_components(base_images_digests, is_last_from_scratch)
    if args.sbom_type == "cyclonedx":
        if "formulation" in sbom:
            sbom["formulation"].append({"components": base_images_sbom_components})
        else:
            sbom.update({"formulation": [{"components": base_images_sbom_components}]})
    else:
        root_element1, map1, inverse_map1 = map_relationships(sbom["relationships"])

        packages = []
        relationships = []

        # Try to calculate middle element based on the relationships maps.
        # SPDX has usually root element which contains a wrapper element which then contains
        # all of the other elements
        middle_element1 = None
        for r, contains in map1.items():
            if contains and inverse_map1.get(r) == root_element1:
                middle_element1 = r
        if not middle_element1:
            middle_element1 = "SPDXRef-DocumentRoot-Unknown-"
            packages.append(
                {
                    "SPDXID": "SPDXRef-DocumentRoot-Unknown-",
                    "name": "",
                }
            )
            relationships.append(
                {
                    "spdxElementId": root_element1 or sbom["SPDXID"],
                    "relatedSpdxElement": "SPDXRef-DocumentRoot-Unknown-",
                    "relationshipType": "DESCRIBES",
                }
            )

        annotation_date = datetime.datetime.now().isoformat()
        for component in base_images_sbom_components:
            # Calculate unique identifier SPDXID based on the component name and purl
            SPDXID = (
                f"SPDXRef-{component['type']}-{component['name']}-"
                + f"{hashlib.sha256(component['purl'].encode()).hexdigest()}"
            )
            packages.append(
                {
                    "SPDXID": SPDXID,
                    "name": component["name"],
                    # See more info about external refs here:
                    # https://spdx.github.io/spdx-spec/v2.3/package-information/#7211-description
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": component["purl"],
                        }
                    ],
                    # Annotations are used to provide cyclonedx custom properties
                    # as json string
                    "annotations": [
                        {
                            "annotator": "konflux",
                            "annotationDate": annotation_date,
                            "annotationType": "OTHER",
                            "comment": json.dumps(
                                {"name": property["name"], "value": property["value"]},
                                separators=(",", ":"),
                            ),
                        }
                        for property in component["properties"]
                    ],
                }
            )
            # Add relationship for parsed base image components and "middle" element which wraps
            # all spdx packages, but it's not spdx document itself.
            relationships.append(
                {
                    "spdxElementId": SPDXID,
                    "relatedSpdxElement": middle_element1,
                    "relationshipType": "BUILD_TOOL_OF",
                }
            )
        sbom["packages"] = sbom.get("packages", []) + packages
        sbom["relationships"] = sbom.get("relationships", []) + relationships

    with args.sbom.open("w") as f:
        json.dump(sbom, f, indent=4)


if __name__ == "__main__":
    main()
