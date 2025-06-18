from argparse import Namespace, ArgumentParser
from pathlib import Path

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file

from src.utils import use_contextual_sbom_creation, load_json, identify_arch, save_json
from src.parent_content import (
    adjust_parent_image_relationship_in_legacy_sbom,
    adjust_parent_image_spdx_element_ids,
    download_parent_image_sbom,
    get_used_parent_image_from_legacy_sbom,
)
from src.mock import calculate_component_only_content
from src.parsed_dockerfile import get_base_images, get_parent_image_pullspec
from src.constants import (
    setup_logger,
    ORIGINAL_PARENT_SBOM_FILE_PATH,
    MODIFIED_PARENT_SBOM_FILE_PATH,
)
from src.mock import get_component_sbom


def parse_args() -> Namespace:
    """
    Parse arguments from Argparse.

    Returns:
        Parsed arguments in `argparse.Namespace` object.

    """
    parser = ArgumentParser()
    parser.add_argument("parsed_dockerfile", type=Path)
    parser.add_argument("-t", "--target-stage", type=str, default=None)

    return parser.parse_args()


def main():
    """
    Main function.

    Returns:
        `None`
    """
    setup_logger()
    args = parse_args()
    parsed_dockerfile = load_json(args.parsed_dockerfile)
    target_stage = args.target_stage
    # This may be reused in the future
    base_images = get_base_images(parsed_dockerfile)
    parent_image = get_parent_image_pullspec(parsed_dockerfile, target_stage, base_images)
    arch = identify_arch()
    parent_sbom_doc = download_parent_image_sbom(parent_image, arch)

    # Save original parent SBOM
    if parent_sbom_doc and not save_json(parent_sbom_doc, ORIGINAL_PARENT_SBOM_FILE_PATH):
        exit(1)

    use_contextual_sbom_creation(parent_sbom_doc)

    parent_sbom_doc = parse_file(str(ORIGINAL_PARENT_SBOM_FILE_PATH))

    # mocked functions
    component_sbom_doc = get_component_sbom()
    component_only_sbom_doc = calculate_component_only_content(parent_sbom_doc, component_sbom_doc)
    print(component_only_sbom_doc)  # remove this print after an usecase is implemented

    grandparent_spdx_id = get_used_parent_image_from_legacy_sbom(parent_sbom_doc)
    parent_sbom_doc = adjust_parent_image_relationship_in_legacy_sbom(parent_sbom_doc, grandparent_spdx_id)
    parent_sbom_doc = adjust_parent_image_spdx_element_ids(parent_sbom_doc, component_sbom_doc, grandparent_spdx_id)

    # Save modified parent SBOM
    write_file(parent_sbom_doc, str(MODIFIED_PARENT_SBOM_FILE_PATH), validate=False)


if __name__ == "__main__":
    main()
