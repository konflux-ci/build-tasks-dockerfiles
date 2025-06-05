from typing import Any

import logging
import sys

from pathlib import Path

from enum import Enum

SBOM_DOC = dict[str, Any]

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

ORIGINAL_PARENT_SBOM_FILE_PATH = Path("./shared/sbom-used-parent-image.json")
MODIFIED_PARENT_SBOM_FILE_PATH = Path("./shared/sbom-modified-parent-image.json")


class SBOMFormat(Enum):
    """Enum for SBOM formats."""

    SPDX2X = "SPDX 2.X"
    CYCLONEDX1X = "CycloneDX 1.X"


class ContentType(Enum):
    """Enum for content types."""

    COMPONENT = "COMPONENT CONTENT"
    COMPONENT_ONLY = "COMPONENT-ONLY CONTENT"
    PARENT = "PARENT CONTENT"
    BUILDER = "BUILDER CONTENT"
    EXTERNAL = "EXTERNAL CONTENT"


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


LOGGER = logging.getLogger(__name__)
