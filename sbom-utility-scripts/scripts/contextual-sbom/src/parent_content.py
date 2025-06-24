"""Module accessing and modifying parent image content in SBOMs."""

import subprocess
import json

from typing import Optional
from json import JSONDecodeError

from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import RelationshipType

from src.constants import SBOM_DOC, LOGGER, ContentType


def get_used_parent_image_from_legacy_sbom(data: Document) -> Optional[str]:
    """
    Identifies SPDXID of the parent image in legacy non-contextual SBOM.
    Counts on legacy marking in the downloaded parent image SBOM.

    Args:
        data:
            SPDX Document object containing the annotations.
    Returns:
        SPDXID of the parent image if found, `None` otherwise.
    """
    for annotation in data.annotations:
        if annotation.annotation_comment == '{"name":"konflux:container:is_base_image","value":"true"}':
            return annotation.spdx_id

    LOGGER.debug(
        "[Parent image content] Cannot determine parent of the "
        "downloaded parent image SBOM. It either does "
        "not exist (it was an oci-archive or the image is built from "
        "scratch) or the downloaded SBOM is not sourced from konflux."
    )
    return None


def convert_to_descendant_of_relationship(sbom_doc: Document, grandparent_spdx_id: str) -> Document:
    """
    This function converts BUILD_TOOL_OF legacy relationship
    of the parent image to the DESCENDANT_OF relationship.

    1. Modifies relationshipType form BUILD_TOOL_OF to DESCENDANT_OF
    2. Flips spdxElementId and relatedSpdxElement

    Args:
        sbom_doc:
            The SBOM data.
        grandparent_spdx_id:
            The SPDXID of the targeted relationship to modify.
    Returns:
        The modified SBOM Document with the DESCENDANT_OF relationship set.
    """
    # not filtering a BUILD_TOOL_OF relationship right
    # away here is actually defensive approach and
    # gives us opportunity for more granular error
    # handling in case of inconsistencies in legacy SBOMs
    original_relationship = [r for r in sbom_doc.relationships if r.spdx_element_id == grandparent_spdx_id]

    if not original_relationship:
        LOGGER.warning(f"[Parent image content] Targeted SPDXID {grandparent_spdx_id} does not bear any relationship!")
        return sbom_doc

    if len(original_relationship) > 1:
        LOGGER.warning(
            f"[Parent image content] Targeted SPDXID {grandparent_spdx_id} has more than one relationship. "
            "This is not expected, skipping modification."
        )
        return sbom_doc

    original_relationship_type = original_relationship[0].relationship_type
    if not original_relationship_type == RelationshipType.BUILD_TOOL_OF:
        LOGGER.warning(
            f"[Parent image content] Targeted SPDXID {grandparent_spdx_id} does not bear BUILD_TOOL_OF "
            f"relationship but {original_relationship_type} relationship."
        )
        return sbom_doc

    original_relationship[0].relationship_type = RelationshipType.DESCENDANT_OF
    original_relationship[0].spdx_element_id = original_relationship[0].related_spdx_element_id
    original_relationship[0].related_spdx_element_id = grandparent_spdx_id
    LOGGER.debug(
        f"[{ContentType.PARENT.value}] Modified relationship_type: from "
        f"BUILD_TOOL_OF to DESCENDANT_OF for spdx_element_id={grandparent_spdx_id}"
    )

    return sbom_doc


def adjust_parent_image_relationship_in_legacy_sbom(sbom_doc: Document, grandparent_spdx_id: str) -> SBOM_DOC:
    """
    Identifies packages marked as used parent image in legacy
    SBOM and modifies its relationships accordingly.
    Args:
        sbom_doc:
            The SBOM data.
        grandparent_spdx_id:
            The SPDXID of the grandparent image of the processed parent image.
    Returns:
        The modified SBOM document with the parent image relationship set
        to DESCENDANT_OF.
    """
    if not grandparent_spdx_id:
        return sbom_doc

    # When DESCENDANT_OF is present SBOM already
    # has properly assigned relationship with its parent
    # so we do not need to modify it.
    # n+1 count of DESCENDANT_OF relationships means that
    # this parent (1) and potentially its parents (n) were
    # already contextualized or at least DESCENDANT_OF
    # relationship has been set for its parent.
    if any([r.relationship_type == RelationshipType.DESCENDANT_OF for r in sbom_doc.relationships]):
        LOGGER.debug(
            "[Parent image content] Downloaded parent image content already contains DESCENDANT_OF relationship."
        )
        return sbom_doc

    sbom_doc = convert_to_descendant_of_relationship(sbom_doc, grandparent_spdx_id)
    return sbom_doc


def get_content_self_reference(parent_sbom_doc: Document) -> Optional[str]:
    """
    Get the content self reference.
    """
    for relationship in parent_sbom_doc.relationships:
        if relationship.relationship_type == RelationshipType.DESCRIBES:
            return relationship.related_spdx_element_id

    LOGGER.error("Sbom is missing DESCRIBES relationship")
    exit(1)


def adjust_parent_image_spdx_element_ids(
    parent_sbom_doc: Document, component_sbom_doc: Document, grandparent_spdx_id: str
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
    diff first OR used for modification during the implementation of
    KONFLUX-3515
    TODO END

    Workflow:
    1. Obtain parent image name as related_spdx_element_id (or SPDXID)
    from component SBOM (this expects component SBOM already with
    DESCENDANT_OF correctly set)
    2. Modify every package's spdx_element_id containing CONTAINS
    and bearing "spdxElementId": "SPDXRef-image" from downloaded
    parent SBOM with value from step 1.
    """
    # Get parent name from already built component
    # SBOM, naturally there will be just one
    parent_name_from_component_sbom = [
        r.related_spdx_element_id
        for r in component_sbom_doc.relationships
        if r.relationship_type == RelationshipType.DESCENDANT_OF
    ][0]

    # If parent not contextualized: all packages with
    # CONTAINS relationship are modified
    # If parent already contextualized: only packages that belongs
    # to this parent but not to its grandparent representing
    # component-only content of the parent will be modified
    # (it has already changed spdxElementId, and it is
    # different than SPDXRef-image)
    counter = 0
    parent_self_reference = get_content_self_reference(parent_sbom_doc)
    for relationship in parent_sbom_doc.relationships:
        if (
            relationship.relationship_type == RelationshipType.CONTAINS
            and relationship.spdx_element_id == parent_self_reference
        ):
            relationship.spdx_element_id = parent_name_from_component_sbom
            counter += 1

        # We also need to modify the DESCENDANT_OF relationship
        # of the parent if grandparent exists saying instead of
        # SPDXRef-image DESCENDANT_OF grandparent_spdx_id but rather
        # parent_name_from_component_sbom DESCENDANT_OF grandparent_spdx_id
        # we do not need to modify the builders of this parent content (BUILD_TOOL_OF),
        # because they will be removed anyway at later stage from this parent content
        if grandparent_spdx_id and relationship.related_spdx_element_id == grandparent_spdx_id:
            relationship.spdx_element_id = parent_name_from_component_sbom
            counter += 1

    LOGGER.debug(
        f"[{ContentType.PARENT.value}] Modified {counter} relationships. "
        "Transformed spdx_element_id: from SPDXRef-image to "
        f"{parent_name_from_component_sbom}."
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
        exit(0)

    oras_output = subprocess.run(
        ["/usr/bin/oras", "manifest", "fetch", pullspec],
        capture_output=True,
    )
    if not oras_output.stdout:
        LOGGER.warning(
            f"Could not locate manifest of the '{pullspec}'. Raw stderr output: {oras_output.stderr.decode()}"
        )
        exit(0)

    try:
        inspected_image = json.loads(oras_output.stdout)
    except JSONDecodeError:
        LOGGER.warning(f"Invalid image manifest found, cannot parse JSON for pullspec '{pullspec}'.")
        exit(0)

    cosign_command = ["/usr/bin/cosign", "download", "sbom", pullspec]
    if inspected_image.get("manifests"):
        LOGGER.debug("The parent image pullspec points to a multiarch image")
        cosign_command.insert(-1, f"--platform={arch}")
    else:
        LOGGER.debug("The parent image pullspec does not point to a multiarch image")
    cmd_result = subprocess.run(cosign_command, capture_output=True)

    if not cmd_result.stdout:
        LOGGER.warning("Could not locate SBOM. Raw stderr output: " + cmd_result.stderr.decode())
        exit(0)
    try:
        result = json.loads(cmd_result.stdout)
        LOGGER.debug(f"Successfully downloaded parent SBOM for pullspec '{pullspec}'.")
        return result
    except JSONDecodeError:
        LOGGER.warning(f"Invalid SBOM found, cannot parse JSON for pullspec '{pullspec}'.")
        exit(0)


def remove_parent_image_builder_records(parent_sbom_doc: Document) -> SBOM_DOC:
    """
    Remove BUILD_TOOL_OF packages and relationships from parent image.
    Note: This must only be done after the parent image's DESCENDANT_OF relationship has been updated.
    """
    build_tool_ids = []
    new_relationships = []
    for relationship in parent_sbom_doc.relationships:
        if relationship.relationship_type == RelationshipType.BUILD_TOOL_OF:
            build_tool_ids.append(relationship.spdx_element_id)
        else:
            new_relationships.append(relationship)
    LOGGER.debug(f"Removing BUILD_TOOL_OF relationships and packages for {build_tool_ids}")
    parent_sbom_doc.relationships = new_relationships

    new_packages = [p for p in parent_sbom_doc.packages if p.spdx_id not in build_tool_ids]
    parent_sbom_doc.packages = new_packages
    # annotations have to be explicitly removed, or they'll remain in a detached list
    new_annotations = [a for a in parent_sbom_doc.annotations if a.spdx_id not in build_tool_ids]
    parent_sbom_doc.annotations = new_annotations

    return parent_sbom_doc
