import json
from typing import Any

import pytest

from create_contextual_sbom import get_base_images, get_parent_image, identify_arch


@pytest.fixture(scope="session")
def sample1_parsed_dockerfile() -> dict[str, Any]:
    with open("test_data/sample1/parsed.json") as json_file:
        return json.load(json_file)


@pytest.fixture(scope="session")
def sample2_parsed_dockerfile() -> dict[str, Any]:
    with open("test_data/sample2/parsed.json") as json_file:
        return json.load(json_file)


def test_get_base_images(sample1_parsed_dockerfile: dict[str, Any]) -> None:
    assert get_base_images(sample1_parsed_dockerfile) == ["alpine:3.10", None]


@pytest.mark.parametrize(
    ["sample_name", "target", "expected_spec"],
    [
        ("sample1", None, None),
        ("sample1", "build", "alpine:3.10"),
        ("sample1", "test", "alpine:3.10"),
        ("sample2", None, "registry.access.redhat.com/ubi8/ubi:latest"),
        ("sample2", "build", "alpine:3.10"),
        ("sample2", "test", "alpine:3.10"),
        (
            "sample2",
            "registry.access.redhat.com/ubi8/ubi:latest",
            "registry.access.redhat.com/ubi8/ubi:latest",
        ),
        ("sample2", "foo", "registry.access.redhat.com/ubi9/ubi:latest"),
        ("sample2", "bar", "registry.access.redhat.com/ubi8/ubi:latest"),
        ("sample2", "scratch", None),
        ("sample2", "nothing", None),
    ],
)
def test_get_parent_image(
    sample_name: str,
    target: str,
    expected_spec: str,
    sample1_parsed_dockerfile: dict[str, Any],
    sample2_parsed_dockerfile: dict[str, Any],
):
    """For tested dockerfiles, visit the `test_data` directory."""
    parsed_file = sample1_parsed_dockerfile if sample_name == "sample1" else sample2_parsed_dockerfile
    assert get_parent_image(parsed_file, target) == expected_spec

def test_identify_arch():
    res = identify_arch()
    assert isinstance(res, str) and res
