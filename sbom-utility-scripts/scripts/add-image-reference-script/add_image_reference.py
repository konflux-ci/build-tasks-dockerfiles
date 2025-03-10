#!/usr/bin/env python3
import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from packageurl import PackageURL


@dataclass
class Image:
    repository: str
    name: str
    digest: str
    tag: str

    @staticmethod
    def from_image_index_url_and_digest(
        image_url_and_tag: str,
        image_digest: str,
    ) -> "Image":
        """
        Create an instance of the Image class from the image URL and digest.

        Args:
            image_url_and_tag (str): Image URL in the format 'registry.com/repository/image:tag'.
            image_digest (str): Manifest digest of the image. (sha256:digest)

        Returns:
            Image: An instance of the Image class representing the image.
        """
        repository, tag = image_url_and_tag.rsplit(":", 1)
        _, name = repository.rsplit("/", 1)
        return Image(
            repository=repository,
            name=name,
            digest=image_digest,
            tag=tag,
        )

    @property
    def digest_algo_cyclonedx(self) -> str:
        """
        Get the digest algorithm used for the image in cyclonedx format.
        The output is in uppercase.

        Returns:
            str: Algorithm used for the digest.
        """
        algo, _ = self.digest.split(":")
        mapping = {"sha256": "SHA-256", "sha512": "SHA-512"}
        return mapping.get(algo, algo.upper())

    @property
    def digest_algo_spdx(self) -> str:
        """
        Get the digest algorithm used for the image in SPDX format.

        Returns:
            str: Algorithm used for the digest in SPDX format.
        """
        algo, _ = self.digest.split(":")
        return algo.upper()

    @property
    def digest_hex_val(self) -> str:
        """
        Get the digest value of the image in hexadecimal format.

        Returns:
            str: Digest value in hexadecimal format.
        """
        _, val = self.digest.split(":")
        return val

    def purl(self) -> str:
        """
        Get the Package URL (PURL) for the image.

        Returns:
            str: A string representing the PURL for the image.
        """
        return PackageURL(
            type="oci",
            name=self.name,
            version=self.digest,
            qualifiers={"repository_url": self.repository},
        ).to_string()


def setup_arg_parser() -> argparse.ArgumentParser:
    """
    Setup the argument parser for the script.

    Returns:
        argparse.ArgumentParser: Argument parser for the script.
    """
    parser = argparse.ArgumentParser(description="Add image reference to image SBOM.")
    parser.add_argument(
        "--image-url",
        type=str,
        help="Image URL in the format 'registry.com/repository/image:tag'.",
        required=True,
    )
    parser.add_argument(
        "--image-digest",
        type=str,
        help="Image manifest digest in a form sha256:xxxx.",
        required=True,
    )
    parser.add_argument(
        "--input-file",
        "-i",
        type=Path,
        help="SBOM file in JSON format.",
        required=True,
    )
    parser.add_argument(
        "--output-file",
        "-o",
        type=str,
        help="Path to save the output SBOM in JSON format.",
    )
    parser.add_argument(
        "--generate-id",
        default="store_true",
        help="Whether to generate a SPDX ID out of the image name and digest. Defaults to False.",
    )
    return parser


def update_component_in_cyclonedx_sbom(sbom: dict, image: Image) -> dict:
    """
    Update the CycloneDX SBOM with the image reference.

    The reference to the image is added to the SBOM in the form of a component and
    purl is added to the metadata.

    Args:
        sbom (dict): SBOM in JSON format.
        image (Image): An instance of the Image class that represents the image.

    Returns:
        dict: Updated SBOM with the image reference added.
    """
    # Add the image component to the components list
    image_component = {
        "type": "container",
        "name": image.name,
        "purl": image.purl(),
        "version": image.tag,
        "hashes": [{"alg": image.digest_algo_cyclonedx, "content": image.digest_hex_val}],
    }
    sbom["components"].insert(0, image_component)
    sbom["metadata"]["component"] = image_component
    return sbom


def find_package_by_spdx_id(sbom: dict, spdx_id: str) -> Optional[dict]:
    """
    Find the package in the SBOM by SPDX ID.

    Args:
        sbom (dict): SBOM in JSON format.
        spdx_id (str): SPDX ID of the package to find.

    Returns:
        dict: The package with the given SPDX ID.
    """
    for package in sbom["packages"]:
        if package["SPDXID"] == spdx_id:
            return package
    return None


def delete_package_by_spdx_id(sbom: dict, spdx_id: str) -> dict:
    """
    Delete the package in the SBOM by SPDX ID.

    Args:
        sbom (dict): SBOM in JSON format.
        spdx_id (str): SPDX ID of the package to delete.

    Returns:
        dict: Updated SBOM with the package deleted.
    """
    for package in sbom["packages"]:
        if package["SPDXID"] == spdx_id:
            sbom["packages"].remove(package)
            break
    return sbom


def redirect_virtual_root_to_new_root(sbom: dict, virtual_root: str, new_root: str) -> dict:
    """
    Redirect the relationship describing the document to a new root node.

    Args:
        sbom (dict): SBOM in JSON format.
        virtual_root (str): A virtual root node identifier that needs to be replaced.
        new_root (str): A new root node identifier that will replace the virtual root node.

    Returns:
        dict: Updated SBOM with the virtual root node replaced.
    """
    for relationship in sbom["relationships"]:
        if relationship["spdxElementId"] == virtual_root:
            relationship["spdxElementId"] = new_root

        if relationship["relatedSpdxElement"] == virtual_root:
            relationship["relatedSpdxElement"] = new_root


def delete_relationship_by_related_spdx_id(sbom: dict, spdx_id: str) -> dict:
    """
    Delete the relationship in the SBOM by SPDX ID.

    Args:
        sbom (dict): SBOM in JSON format.
        spdx_id (str): SPDX ID of the relationship to delete.

    Returns:
        dict: Updated SBOM with the relationship deleted.
    """
    for relationship in sbom["relationships"]:
        if relationship["relatedSpdxElement"] == spdx_id:
            sbom["relationships"].remove(relationship)
            break
    return sbom


def describes_the_document(relationship_element: dict, doc_spdx_id: str) -> bool:
    """
    Check if the relationship describes the document.

    Args:
        relationship_element (dict): A relationship element from the SBOM that needs to be checked.
        doc_spdx_id (str): A SPDX ID of the document.

    Returns:
        bool: A boolean indicating if the relationship describes the document.
    """
    return (
        relationship_element["spdxElementId"] == doc_spdx_id and relationship_element["relationshipType"] == "DESCRIBES"
    )


def is_virtual_root(package: dict) -> bool:
    """
    Check if the package is a virtual root - usually a package with empty values.

    For example:

        {
            "SPDXID": "SPDXRef-DocumentRoot-Unknown",
            "name": "",
            "versionInfo": ""
        }

        {
            "SPDXID": "SPDXRef-DocumentRoot-Directory-.-some-directory",
            "name": "./some-directory",
            "versionInfo": ""
        }

    Args:
        package (dict): A package element from the SBOM.

    Returns:
        bool: A boolean indicating if the package is a virtual root.
    """
    name = package.get("name")
    return not name or name.startswith((".", "/"))


def redirect_current_roots_to_new_root(sbom: dict, new_root: str) -> dict:
    """
    Redirect all the current root nodes to a new root node.

    Args:
        sbom (dict): SBOM in JSON format.
        new_root (str): New root node identifier.

    Returns:
        dict: Updated SBOM with the new root node identifier.
    """
    for relationship in sbom["relationships"].copy():
        if not describes_the_document(relationship, sbom["SPDXID"]):
            continue

        current_root = find_package_by_spdx_id(sbom, relationship["relatedSpdxElement"])

        if is_virtual_root(current_root):
            # In case the document is described by the virtual root node let's remove it and replace it with
            # the new root node

            # Remove the virtual root node from the packages list
            delete_package_by_spdx_id(sbom, relationship["relatedSpdxElement"])

            # Remove the relationship between the document and the virtual root node
            delete_relationship_by_related_spdx_id(sbom, relationship["relatedSpdxElement"])

            # Redirect a existing relationship to the new root node
            redirect_virtual_root_to_new_root(sbom, relationship["relatedSpdxElement"], new_root)
        else:
            # Make an edge between the new root node and the current root node
            relationship["spdxElementId"] = new_root
            relationship["relationshipType"] = "CONTAINS"
    return sbom


def get_spdxid_from_image(image: Image) -> str:
    """
    Generate a SPDX ID from an image repository and digest

    Args:
        image (Image): Image to generate the SPDX ID from.

    Returns:
        str: SPDX ID in the format SPDXRef-image-{image.repository}-{image.digest}.
    """
    return f"SPDXRef-image-{image.repository}-{image.digest}"


def update_package_in_spdx_sbom(sbom: dict, image: Image, generate_id: bool = False) -> dict:
    """
    Update the SPDX SBOM with the image reference.

    The reference to the image is added to the SBOM in the form of a package and
    appropriate relationships are added to the SBOM.

    Args:
        sbom (dict): SBOM in JSON format.
        image (Image): An instance of the Image class that represents the image.
        generate_id (bool): Indicate if the SPDX ID should be generated.

    Returns:
        dict: Updated SBOM with the image reference added.
    """

    spdxid = get_spdxid_from_image(image) if generate_id else "SPDXRef-image"

    # Add the image package to the packages list
    package = {
        "SPDXID": spdxid,
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
    sbom["packages"].insert(0, package)

    # Check existing relationships and redirect the current roots to the new root
    redirect_current_roots_to_new_root(sbom, package["SPDXID"])

    # Add the relationship between the image and the package
    sbom["relationships"].insert(
        0,
        {
            "spdxElementId": sbom["SPDXID"],
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        },
    )
    return sbom


def extend_sbom_with_image_reference(sbom: dict, image: Image, generate_id: bool = False) -> dict:
    """
    Extend the SBOM with the image reference.
    Based on the SBOM format, the image reference is added to the SBOM in
    a different way.

    Args:
        sbom (dict): SBOM in JSON format.
        image (Image): An instance of the Image class that represents the image.
        generate_id (bool): Indicate if the SPDX ID should be generated.

    Returns:
        dict: Updated SBOM with the image reference added.
    """
    if sbom.get("bomFormat") == "CycloneDX":
        update_component_in_cyclonedx_sbom(sbom, image)
    elif "spdxVersion" in sbom:
        update_package_in_spdx_sbom(sbom, image, generate_id)

    return sbom


def update_name(sbom: dict, image: Image) -> dict:
    """
    Update the SBOM name with the image reference in the format 'repository@digest'.

    Args:
        sbom (dict): SBOM in JSON format.
        image (Image): An instance of the Image class that represents the image.

    Returns:
        dict: Updated SBOM with the name field updated.
    """
    if "spdxVersion" in sbom:
        sbom["name"] = f"{image.repository}@{image.digest}"
    return sbom


def main():
    """
    Main function to add image reference to SBOM.
    """
    arg_parser = setup_arg_parser()
    args = arg_parser.parse_args()

    with open(args.input_file, "r") as inp_file:
        sbom = json.load(inp_file)

    image = Image.from_image_index_url_and_digest(
        args.image_url,
        args.image_digest,
    )

    # Update the input SBOM with the image reference and name attributes
    sbom = extend_sbom_with_image_reference(sbom, image, args.generate_id)
    sbom = update_name(sbom, image)

    # Save the updated SBOM to the output file
    if args.output_file:
        with open(args.output_file, "w") as out_file:
            json.dump(sbom, out_file)


if __name__ == "__main__":  # pragma: no cover
    main()
