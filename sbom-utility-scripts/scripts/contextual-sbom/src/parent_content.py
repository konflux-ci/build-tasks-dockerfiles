"""Module accessing and modifying parent image content in SBOMs."""

import subprocess
import json

from typing import Optional
from json import JSONDecodeError

from src.constants import SBOM_DOC, LOGGER, ContentType

from src.utils import find_relationships, modify_relationship


def get_used_parent_image_from_legacy_sbom(data: SBOM_DOC) -> Optional[str]:
    """
    Identifies SPDXID of the parent image in legacy non-contextual SBOM.
    Counts on legacy marking in the downloaded parent image SBOM.

    Args:
        data:
            The SBOM data in dictionary format.
            We cannot use spdx-tools here because after parsing
            annotations are lost.
    Returns:
        SPDXID of the parent image if found, `None` otherwise.
    """
    for package in data["packages"]:
        if annotations := package.get("annotations", {}):
            for annotation in annotations:
                if annotation.get("comment") == '{"name":"konflux:container:is_base_image","value":"true"}':
                    return package["SPDXID"]

    LOGGER.debug(
        "[Parent image content] Cannot determine parent of the "
        "downloaded parent image SBOM. It either does "
        "not exist (it was an oci-archive or the image is built from "
        "scratch) or the downloaded SBOM is not sourced from konflux."
    )
    return None


def convert_to_descendant_of_relationship(sbom_doc: SBOM_DOC, grandparent_spdx_id: str) -> SBOM_DOC:
    """
    This function converts BUILD_TOOL_OF legacy relationship
    of the parent image to the DESCENDANT_OF relationship.

    1. Modifies relationshipType form BUILD_TOOL_OF to DESCENDANT_OF
    2. Flips spdxElementId and relatedSpdxElement

    Args:
        sbom_doc:
            The SBOM data in dictionary format.
        grandparent_spdx_id:
            The SPDXID of the targeted relationship to modify.
    Returns:
        The modified SBOM document with the DESCENDANT_OF relationship set.
    """
    # not filtering a BUILD_TOOL_OF relationship right
    # away here is actually defensive approach and
    # gives us opportunity for more granular error
    # handling in case of inconsistencies in legacy SBOMs
    original_relationship = find_relationships(
        sbom_doc["relationships"],
        search=("spdxElementId", grandparent_spdx_id),
    )

    if not original_relationship:
        LOGGER.warning(f"[Parent image content] Targeted SPDXID {grandparent_spdx_id} does not bear any relationship!")
        return sbom_doc

    if len(original_relationship) > 1:
        LOGGER.warning(
            f"[Parent image content] Targeted SPDXID {grandparent_spdx_id} has more than one relationship. "
            "This is not expected, skipping modification."
        )
        return sbom_doc

    original_relationship_type = original_relationship[0]["relationshipType"]
    if not original_relationship_type == "BUILD_TOOL_OF":
        LOGGER.warning(
            f"[Parent image content] Targeted SPDXID {grandparent_spdx_id} does not bear BUILD_TOOL_OF "
            f"relationship but {original_relationship_type} relationship."
        )
        return sbom_doc

    # This updates the relationship i.e. BUILD_TOOL_OF -> DESCENDANT_OF
    sbom_doc = modify_relationship(
        sbom_doc,
        search=("spdxElementId", grandparent_spdx_id),
        modify=("relationshipType", "DESCENDANT_OF"),
        content_type=ContentType.PARENT.value,
    )

    # Following code flips spdxElementId and relatedSpdxElement
    # It is needed because BUILD_TOOL_OF and DESCENDANT_OF
    # relationship is contradictory
    original_related_spdx_element = original_relationship[0]["relatedSpdxElement"]
    # Transfer spdx_id to relatedSpdxElement
    sbom_doc = modify_relationship(
        sbom_doc,
        search=("spdxElementId", grandparent_spdx_id),
        modify=("relatedSpdxElement", grandparent_spdx_id),
        content_type=ContentType.PARENT.value,
    )

    # Transfer original_related_spdx_element to spdxElementId
    sbom_doc = modify_relationship(
        sbom_doc,
        search=("relatedSpdxElement", grandparent_spdx_id),
        modify=("spdxElementId", original_related_spdx_element),
        content_type=ContentType.PARENT.value,
    )

    return sbom_doc


def adjust_parent_image_relationship_in_legacy_sbom(sbom_doc: SBOM_DOC, grandparent_spdx_id: str) -> SBOM_DOC:
    """
    Identifies package marked as used parent image in legacy
    SBOM and modifies its relationship accordingly.
    Args:
        sbom_doc:
            The SBOM data in dictionary format.
            We cannot use spdx-tools here because after parsing
            annotations are lost.
        grandparent_spdx_id:
            The SPDXID of the grandparent image of the processed parent image.
    Returns:
        The modified SBOM document with the parent image relationship set
        to DESCENDANT_OF.
    """
    # When DESCENDANT_OF is present SBOM already
    # has properly assigned relationship with its parent
    # so we do not need to modify it.
    # n+1 count of DESCENDANT_OF relationships means that
    # this parent (1) and potentially its parents (n) were
    # already contextualized or at least DESCENDANT_OF
    # relationship has been set for its parent.
    if find_relationships(sbom_doc["relationships"], search=("relationshipType", "DESCENDANT_OF")):
        LOGGER.debug(
            "[Parent image content] Downloaded parent image content already contains DESCENDANT_OF relationship."
        )
        return sbom_doc

    if not grandparent_spdx_id:
        return sbom_doc

    sbom_doc = convert_to_descendant_of_relationship(sbom_doc, grandparent_spdx_id)
    return sbom_doc


def adjust_parent_image_spdx_element_ids(
    parent_sbom_doc: SBOM_DOC, component_sbom_doc: SBOM_DOC, grandparent_spdx_id: str
) -> SBOM_DOC:
    """
    This function modifies downloaded used parent image SBOM. We need to
    distinguish downloaded parent component-only content ("spdxElementId":
    "SPDXRef-image") and current component component-only content (also
    "spdxElementId": "SPDXRef-image"). We achieve this by taking the name
    of the parent from component ("relatedSpdxElement": "parent-name") and
    substitute every "spdxElementId": "SPDXRef-image" in downloaded parent
    content.

    Function initially identifies the name of the parent image in component
    image SBOM.

    TODO ISV-5858:
    At this stage, component image SBOM is expected to bear
    DESCENDANT_OF relationship for proper identification of the parent name.
    TODO END

    Obtained parent image name from component is used to exchange any
    spdxElementId in parent content bearing "spdxElementId": "SPDXRef-image"
    Parent's (contextualized or not) component-only packages
    (packages installed in final layer of the parent) contain
    "spdxElementId": "SPDXRef-image"
    This is allowed only for currently-build-component packages
    (component_sbom_doc).
    This might be extended in the future to cover hermeto-provided
    spdxElementId if differs.

    TODO ISV-5709 OR KONFLUX-3515:
    This function is used for modification of the used parent content
    after resolution and application of the ISV-5709 - we need to have
    diff first OR during the implementation of KONFLUX-3515
    TODO END

    Workflow:
    1. Obtain parent image name as relatedSpdxElement (or SPDXID)
    from component SBOM (this expects component SBOM already with
    DESCENDANT_OF correctly set)
    2. Obtain all packages (CONTAINS) from downloaded parent SBOM
    that are bearing "spdxElementId": "SPDXRef-image"
    3. Modify every package spdxElementId from point 2. with value
    from 1. in downloaded parent SBOM
    """
    # Get parent name from already built component SBOM, naturally there will be just one
    parent_name_from_component_sbom = find_relationships(
        component_sbom_doc["relationships"], search=("relationshipType", "DESCENDANT_OF")
    )[0]["relatedSpdxElement"]

    # If parent not contextualized: all packages with
    # CONTAINS relationship are filtered
    # If parent already contextualized: only packages that belongs
    # to this parent but not to its grandparent representing
    # component-only content of the parent
    # (it has already changed spdxElementId, and it is
    # different than SPDXRef-image)
    component_only_content_of_the_parent = find_relationships(
        find_relationships(parent_sbom_doc["relationships"], search=("relationshipType", "CONTAINS")),
        search=("spdxElementId", "SPDXRef-image"),
    )

    for relationship in component_only_content_of_the_parent:
        # this counts on the fact that every relatedSpdxElement
        # is unique and has only single CONTAINS relationship
        parent_sbom_doc = modify_relationship(
            parent_sbom_doc,
            modify=("spdxElementId", parent_name_from_component_sbom),
            search=("relatedSpdxElement", relationship["relatedSpdxElement"]),
            content_type=ContentType.PARENT.value,
        )

    if not grandparent_spdx_id:
        return parent_sbom_doc

    # we also need to modify the DESCENDANT_OF relationship
    # of the parent if grandparent exists saying instead of
    # SPDXRef-image DESCENDANT_OF grandparent_spdx_id but rather
    # parent_name_from_component_sbom DESCENDANT_OF grandparent_spdx_id
    # we do not need to modify the builders of this parent content (BUILD_TOOL_OF),
    # because they will be removed anyway at later stage from this parent content
    parent_sbom_doc = modify_relationship(
        parent_sbom_doc,
        modify=("spdxElementId", parent_name_from_component_sbom),
        search=("relatedSpdxElement", grandparent_spdx_id),
        content_type=ContentType.PARENT.value,
    )

    return parent_sbom_doc


def download_parent_image_sbom(pullspec: str | None, arch: str) -> SBOM_DOC | None:
    """
    Downloads parent SBOM. First tries to download arch-specific SBOM, then image index
    as a fallback.
    Args:
        pullspec:
            Which image to download.
        arch:
            Architecture of the target system. Will be the same as the current runtime arch.
    Returns:
        The found SBOM or `None`.
    """
    if not pullspec:
        LOGGER.debug("No parent image found.")
        return None

    skopeo_output = subprocess.run(["/usr/bin/skopeo", "inspect", "--raw", f"docker://{pullspec}"], capture_output=True)
    inspected_image = json.loads(skopeo_output.stdout)

    cosign_command = ["/usr/bin/cosign", "download", "sbom", pullspec]
    if inspected_image.get("manifests"):
        LOGGER.debug("The parent image pullspec points to a multiarch image")
        cosign_command.insert(-1, f"--platform={arch}")
    else:
        LOGGER.debug("The parent image pullspec does not point to a multiarch image")
    cmd_result = subprocess.run(cosign_command, capture_output=True)

    if not cmd_result.stdout:
        LOGGER.warning("Could not locate SBOM. Raw stderr output: " + cmd_result.stderr.decode())
        return None
    try:
        result = json.loads(cmd_result.stdout)
        LOGGER.debug(f"Successfully downloaded parent SBOM for pullspec '{pullspec}'.")
        return result
    except JSONDecodeError:
        LOGGER.warning(f"Invalid SBOM found, cannot parse JSON for pullspec '{pullspec}'.")
        return None
