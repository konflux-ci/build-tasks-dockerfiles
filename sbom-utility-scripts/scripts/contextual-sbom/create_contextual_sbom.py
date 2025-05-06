import json
import subprocess
from argparse import Namespace, ArgumentParser
from pathlib import Path
from typing import Any


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
    Fetches the runtime arch. Requires uname command in the system/container.

    Returns:
        String output of the `/bin/uname -m` command.
    """
    res = subprocess.run(["/bin/uname", "-m"], capture_output=True)
    return res.stdout.decode().strip()


def load_json(path: Path) -> dict[str, Any]:
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
    Fetches the image referenced by a stage. Resolves transitive references to previous stages.

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


def get_parent_image(
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


def main():
    """
    Main function.

    Returns:
        `None`
    """
    args = parse_args()
    parsed_dockerfile = load_json(args.parsed_dockerfile)
    target_stage = args.target_stage
    # This may be reused in the future
    base_images = get_base_images(parsed_dockerfile)

    parent_image = get_parent_image(parsed_dockerfile, target_stage, base_images)
    print(parent_image)
    # TODO continue with other tasks


if __name__ == "__main__":
    main()
