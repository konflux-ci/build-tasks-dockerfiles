from typing import List
from pathlib import Path

from spdx_tools.spdx.parser.parse_anything import parse_file

from src.constants import SBOM_DOC


this_dir = Path(__file__).resolve().parent


def get_component_sbom() -> dict[str, List[dict[str, str]]]:
    """
    This is only mock of the output of the ISV-5858.
    Expected is component SBOM already generated with properly set
    DESCENDANT_OF of relationship identified by dockerfile-json output
    """
    return parse_file(str(this_dir.parent / "tests" / "test_data" / "fake_component_sbom" / "component_sbom.spdx.json"))


def calculate_component_only_content(parent_sbom_doc: SBOM_DOC, component_sbom_doc: SBOM_DOC) -> SBOM_DOC:
    """
    Function calculates diff between component content
    and parent content and produces component only content.
    """
    return {}
