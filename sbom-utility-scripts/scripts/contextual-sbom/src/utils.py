import json
import subprocess

from typing import Any
from pathlib import Path

from src.constants import SBOM_DOC, ARCH_TRANSLATION, LOGGER, SBOMFormat


def identify_arch() -> str:
    """
    Fetches the runtime arch. Requires `uname` command in the system/container.

    Returns:
        Cosign-compatible arch identifier.
    """
    res = subprocess.run(["/bin/uname", "-m"], capture_output=True)
    raw_arch = res.stdout.decode().strip()
    for cosign_arch, uname_arch_options in ARCH_TRANSLATION.items():
        if raw_arch in uname_arch_options:
            return f"linux/{cosign_arch}"
    return f"linux/{raw_arch}"


def load_json(path: Path) -> SBOM_DOC:
    """
    Utility to load a dictionary from a json file.

    Args:
        path:
            `pathlib.Path` object with the location to a file to load.

    Returns:
        The object loaded from the json file.
    """
    with open(path, "r") as json_file:
        return json.load(json_file)


def save_json(json_doc: dict[str, Any], path: Path) -> bool:
    """
    Saves the json to a specified path.
    Args:
        json_doc:
            The JSON doc to save.
        path:
            Location to save the json.

    Returns:
        `True` on success, `False` otherwise.
    """
    if not path.parent.is_dir():
        LOGGER.info(f"Could not save file '{path.absolute()}', directory '{path.parent.absolute()}' does not exist.")
        return False
    try:
        with open(path, "w") as write_file:
            json.dump(json_doc, write_file)
        return True
    except OSError as e:
        LOGGER.info(f"Could not save JSON to '{path.absolute()}', problem: {type(e)}, {e.args}")
        return False


def _get_sbom_format(sbom_dict: SBOM_DOC) -> SBOMFormat:
    """
    Determine SBOM format.
    Args:
        sbom_dict:
            Dictionary containing the whole SBOM.
    Returns:
        SBOMFormat enum value representing the SBOM format.
    Raises:
        ValueError: If the SBOM format is not supported.
    """
    if spdx_version := sbom_dict.get("spdxVersion"):
        if spdx_version.startswith("SPDX-2"):
            return SBOMFormat.SPDX2X
    elif sbom_dict.get("bomFormat") == "CycloneDX" and (spec_version := sbom_dict.get("specVersion")):
        if spec_version.startswith("1."):
            return SBOMFormat.CYCLONEDX1X
    return SBOMFormat.UNSUPPORTED


def use_contextual_sbom_creation(sbom_doc: SBOM_DOC | None) -> None:
    """
    Based on the SBOM file of a parent image,
    determine if the contextual SBOM mechanism should be used.

    Args:
        sbom_doc:
            Loaded SBOM doc or `None`.
    Returns:
        `True` if contextual SBOM mechanism should be used. `False` otherwise.
    """
    if not sbom_doc:
        LOGGER.debug("Contextual mechanism won't be used, there is no parent image SBOM.")
        exit(0)
    parent_image_sbom_format = _get_sbom_format(sbom_doc)
    if parent_image_sbom_format is SBOMFormat.SPDX2X:
        LOGGER.debug("Contextual mechanism will be used.")
        return
    else:
        LOGGER.debug("Contextual mechanism won't be used, SBOM format is not supported for this workflow.")
        exit(0)
