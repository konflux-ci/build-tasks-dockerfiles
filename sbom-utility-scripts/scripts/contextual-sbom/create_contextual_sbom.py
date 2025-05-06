import json
import logging
import subprocess
import sys
from argparse import Namespace, ArgumentParser
from enum import Enum
from json import JSONDecodeError
from pathlib import Path
from typing import Any

SBOM_DOC = dict[str, Any]

LOGGER = logging.getLogger(__name__)

# The `uname -m` and cosign each use different naming conventions
# for cpu arches. This table translates from uname format to cosign one
# reference: https://stackoverflow.com/questions/45125516/possible-values-for-uname-m
# Also cosign expects format `kernel/arch`, so don't forget to add 'linux/' prefix
ARCH_TRANSLATION = {
    "amd64": {"x86_64", "x64"},
    "arm64": {"arm", "aarch64_be", "aarch64", "armv8b", "armv8l"},
    "ppc64le": {"powerpc", "ppc", "ppc64", "ppcle"},
    "s390x": {"s390"},
}


class SBOMFormat(Enum):
    """Enum for SBOM formats."""

    SPDX2X = "SPDX 2.X"
    CYCLONEDX1X = "CycloneDX 1.X"


def setup_logger():
    """
    Set up logger to produce debug information to STDOUT.

    Returns:
        None
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.DEBUG)


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


def get_base_images(parsed_dockerfile: dict[str, Any]) -> list[str | None]:
    """
    Fetches a list of base images.

    Args:
        parsed_dockerfile:
            The loaded output of `dockerfile-json` command.
            See https://github.com/keilerkonzept/dockerfile-json.

    Returns:
        A list of pullspecs of base images from all stages.
        If the stage is built `FROM SCRATCH`, the base image
        will be represented by `None`.
    """
    base_images_pullspecs: list[str | None] = []
    for stage in parsed_dockerfile.get("Stages", []):
        from_field = stage.get("From", {})
        # Ignore scratch image as well as
        # references to previous stages
        if "Stage" in from_field:
            continue
        if from_field.get("Scratch"):
            # It is an empty image
            base_images_pullspecs.append(None)
            continue
        base_name: str = stage.get("BaseName")
        if base_name and not base_name.startswith("oci-archive:"):
            base_images_pullspecs.append(base_name)
    return base_images_pullspecs


def _get_base_image_for_target(parsed_dockerfile: dict[str, Any], target_stage: str) -> str | None:
    """
    Fetches the image pullspec referenced by a stage. Resolves transitive references to previous stages.

    Args:
        parsed_dockerfile:
            The loaded output of `dockerfile-json` command.
            See https://github.com/keilerkonzept/dockerfile-json.
        target_stage:
            The pullspec or alias of the target stage.

    Returns:
        Pullspec for the base image mentioned in the target.
        Returns None if the image is built `FROM SCRATCH`.
    """
    last_ref = target_stage
    # This resolves transitive aliases. If the target mentions
    # a stage by its alias, it grabs the base name of that stage.
    # That can also be an alias of a previous stage. So this
    # iterates until no alias is found. The BaseName must hold
    # a pullspec in that case.
    for stage in reversed(parsed_dockerfile["Stages"]):
        # Only previous stages can get referenced,
        # let's iterate in reverse
        if stage.get("As") == last_ref:
            last_ref = stage.get("BaseName")
    if last_ref.lower() == "scratch":
        return None
    return last_ref


def get_parent_image_pullspec(
    parsed_dockerfile: dict[str, Any],
    target_stage: str | None = None,
    base_images: list[str | None] | None = None,
) -> str | None:
    """
    Gets the pullspec of the parent image from the parsed SBOM file.
    Args:
        parsed_dockerfile: The loaded output of `dockerfile-json` command.
            See https://github.com/keilerkonzept/dockerfile-json.
        target_stage:
            The pullspec or alias of the target stage. Optional argument.
        base_images:
            The list of base images. Optional argument, providing it
            only improves the performance. If not provided, it will be
            computed automatically. Use output of `get_base_images()`.
    Returns:
        A pullspec of the base image or `None` if the image is built
        FROM SCRATCH.
    """
    base_images = base_images or get_base_images(parsed_dockerfile)
    if not base_images:
        raise ValueError("The Dockerfile is invalid. There are no stages with pullspecs present!")
    if not target_stage:
        # It's the last base image
        return base_images[-1]
    return _get_base_image_for_target(parsed_dockerfile, target_stage)


def download_parent_image_sbom(pullspec: str | None, arch: str) -> SBOM_DOC | None:
    """
    Downloads parent pullspec. First tries to download arch-specific SBOM, then image index
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
    cmd_result = subprocess.run(
        ["/usr/bin/cosign", "download", "sbom", f"--platform={arch}", pullspec], capture_output=True
    )
    if "specified reference is not a multiarch image" in cmd_result.stderr.decode():
        LOGGER.debug("Not a multiarch image, trying without version...")
        cmd_result = subprocess.run(["/usr/bin/cosign", "download", "sbom", pullspec], capture_output=True)
    if not cmd_result.stdout:
        LOGGER.debug("Could not locate SBOM.")
        return None
    try:
        return json.loads(cmd_result.stdout)
    except JSONDecodeError:
        LOGGER.warning(f"Invalid SBOM found, cannot parse JSON for pullspec '{pullspec}'.")
        return None


def _get_sbom_format(sbom_dict: SBOM_DOC) -> SBOMFormat:
    """
    Determine SBOM format.
    Args:
        sbom_dict:
            Dictionary containing the whole SBOM.
    Returns:

    """
    if spdx_version := sbom_dict.get("spdxVersion"):
        if spdx_version.startswith("SPDX-2"):
            return SBOMFormat.SPDX2X
    elif sbom_dict.get("bomFormat") == "CycloneDX" and (spec_version := sbom_dict.get("specVersion")):
        if spec_version.startswith("1."):
            return SBOMFormat.CYCLONEDX1X
    raise ValueError("Unsupported SBOM format!")


def use_contextual_sbom_creation(sbom_doc: SBOM_DOC | None) -> bool:
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
        return False
    parent_image_sbom_format = _get_sbom_format(sbom_doc)
    if parent_image_sbom_format is SBOMFormat.SPDX2X:
        LOGGER.debug("Contextual mechanism will be used.")
        return True
    LOGGER.debug("Contextual mechanism won't be used, parent SBOM is in CycloneDX format.")
    return False


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
    sbom = download_parent_image_sbom(parent_image, arch)
    use_contextual = use_contextual_sbom_creation(sbom)
    print(use_contextual)  # Remove this print after this value has a use case


if __name__ == "__main__":
    main()
