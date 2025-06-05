from typing import List
from src.constants import SBOM_DOC


def get_component_sbom() -> dict[str, List[dict[str, str]]]:
    """
    This is only mock of the output of the ISV-5858.
    Expected is component SBOM already generated with properly set
    DESCENDANT_OF of relationship identified by dockerfile-json output
    """
    return {
        "relationships": [
            {
                "spdxElementId": "SPDXRef-image",
                "relationshipType": "DESCENDANT_OF",
                "relatedSpdxElement": "SPDXRef-image-registry.access." "redhat.com/parent-of-component:latest",
            }
        ]
    }


def calculate_component_only_content(parent_sbom_doc: SBOM_DOC, component_sbom_doc: SBOM_DOC) -> SBOM_DOC:
    """
    Function calculates diff between component content
    and parent content and produces component only content.
    """
    return {}
