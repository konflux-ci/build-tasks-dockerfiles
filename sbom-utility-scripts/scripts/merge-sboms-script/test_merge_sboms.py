import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from merge_sboms import (
    SBOMItem,
    detect_sbom_type,
    fallback_key,
    main,
    merge_by_apparent_sameness,
    merge_cyclonedx_sboms,
    wrap_as_cdx,
    wrap_as_spdx,
)

TOOLS_METADATA = {
    "syft-cyclonedx-1.4": {
        "name": "syft",
        "vendor": "anchore",
        "version": "0.47.0",
    },
    "syft-cyclonedx-1.5": {
        "type": "application",
        "author": "anchore",
        "name": "syft",
        "version": "0.100.0",
    },
    "hermeto-cyclonedx-1.4": {
        "name": "hermeto",
        "vendor": "red hat",
    },
    "hermeto-cyclonedx-1.5": {
        "type": "application",
        "author": "red hat",
        "name": "hermeto",
    },
}

# relative to data_dir/{sbom_type}
INDIVIDUAL_SYFT_SBOMS = [
    "syft-sboms/gomod-pandemonium.bom.json",
    "syft-sboms/npm-cachi2-smoketest.bom.json",
    "syft-sboms/pip-e2e-test.bom.json",
    "syft-sboms/ubi-micro.bom.json",
]


@pytest.fixture
def data_dir() -> Path:
    """Path to the directory for storing unit test data."""
    return Path(__file__).parent / "test_data"


def count_components(sbom: dict[str, Any]) -> Counter[str]:
    def key(component: SBOMItem) -> str:
        purl = component.purl()
        if purl:
            return purl.to_string()
        return fallback_key(component)

    if detect_sbom_type(sbom) == "cyclonedx":
        components = wrap_as_cdx(sbom["components"])
    else:
        components = wrap_as_spdx(sbom["packages"])

    return Counter(map(key, components))


def count_relationships(spdx_sbom: dict[str, Any]) -> Counter[str]:
    package_spdxids = {p["SPDXID"] for p in spdx_sbom["packages"]}

    def relationship_key(r: dict[str, Any]) -> str | None:
        element = r["spdxElementId"]
        relationship = r["relationshipType"]
        related_element = r["relatedSpdxElement"]

        if related_element not in package_spdxids:
            # The Syft SBOM also contains relationships referencing elements of the .files array,
            # for which we have no handling. As well as relationships referencing non-existent
            # SPDXIDs. Exclude those from the comparison, keep only those we care about.
            return None

        if relationship == "DESCRIBES":
            return f"{element} {relationship} {related_element}"
        else:
            return f"{element} {relationship} *"

    return Counter(filter(None, map(relationship_key, spdx_sbom["relationships"])))


def diff_counts(a: Counter[str], b: Counter[str]) -> dict[str, int]:
    a = a.copy()
    a.subtract(b)
    return {key: count for key, count in a.items() if count != 0}


def run_main(args: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> tuple[str, str]:
    monkeypatch.setattr(sys, "argv", ["unused_script_name", *args])
    main()
    return capsys.readouterr()


@pytest.mark.parametrize(
    "sbom_type, expect_diff",
    [
        (
            "cyclonedx",
            {
                # All of these golang purls appear twice in the SBOM merged by syft
                # (they already appear twice in the individual gomod SBOM).
                # They only appear once in the SBOM merged by us, which seems better.
                "pkg:golang/github.com/Azure/go-ansiterm@v0.0.0-20210617225240-d185dfc1b5a1": -1,
                "pkg:golang/github.com/moby/term@v0.0.0-20221205130635-1aeaba878587": -1,
                "pkg:golang/golang.org/x/sys@v0.6.0": -1,
                # The rhel@9.5 component doesn't have a purl. Syft drops it when merging, we keep it.
                "rhel@9.5": 1,
            },
        ),
        (
            "spdx",
            {
                # This is the "made-up root" that Syft uses for the merged SBOM
                "SPDXRef-DocumentRoot-Directory-.-syft-sboms": -1,
                # We instead keep the original "made-up root", as well as the root of the
                # ubi-micro.bom.json document (which has an actual root, not a made-up one,
                # because it comes from scanning a container image, not a directory).
                "SPDXRef-DocumentRoot-Directory-.": 1,
                "pkg:oci/registry.access.redhat.com/ubi9/ubi-micro@sha256:71c7ec827876417693bd3feb615a5c70753b78667cb27c17cb3a5346a6955da5?arch=amd64&tag=9.5": 1,
                # For some reason, Syft lowercases the purls when merging. We do not.
                "pkg:golang/github.com/masterminds/semver@v1.4.2": -1,
                "pkg:golang/github.com/Masterminds/semver@v1.4.2": 1,
                "pkg:golang/github.com/microsoft/go-winio@v0.6.0": -1,
                "pkg:golang/github.com/Microsoft/go-winio@v0.6.0": 1,
                "pkg:golang/github.com/azure/go-ansiterm@v0.0.0-20210617225240-d185dfc1b5a1": -1,
                "pkg:golang/github.com/Azure/go-ansiterm@v0.0.0-20210617225240-d185dfc1b5a1": 1,
            },
        ),
    ],
)
def test_merge_n_syft_sboms(
    sbom_type: str,
    expect_diff: dict[str, int],
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.chdir(data_dir / sbom_type)

    args = [f"syft:{sbom_path}" for sbom_path in INDIVIDUAL_SYFT_SBOMS]
    result, _ = run_main(args, monkeypatch, capsys)

    with open("syft.merged-by-us.bom.json") as f:
        merged_by_us = json.load(f)

    assert json.loads(result) == merged_by_us

    with open("syft.merged-by-syft.bom.json") as f:
        merged_by_syft = json.load(f)

    compared_to_syft = diff_counts(count_components(merged_by_us), count_components(merged_by_syft))
    assert compared_to_syft == expect_diff

    if sbom_type == "spdx":
        relationships_diff = diff_counts(count_relationships(merged_by_us), count_relationships(merged_by_syft))
        assert relationships_diff == {
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Directory-.-syft-sboms": -1,
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Image-registry.access.redhat.com-ubi9-ubi-micro": 1,
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Directory-.": 1,
            # In the Syft-merged SBOM, the ./syft-sboms element contains everything
            # In our merged SBOM, the same set of packages is split between two roots
            "SPDXRef-DocumentRoot-Directory-.-syft-sboms CONTAINS *": -139,
            "SPDXRef-DocumentRoot-Directory-. CONTAINS *": 117,
            "SPDXRef-DocumentRoot-Image-registry.access.redhat.com-ubi9-ubi-micro CONTAINS *": 22,
        }


@pytest.mark.parametrize(
    "args",
    [
        ["hermeto.bom.json", "syft.merged-by-us.bom.json"],
        ["hermeto:hermeto.bom.json", "syft:syft.merged-by-us.bom.json"],
        ["syft:syft.merged-by-us.bom.json", "hermeto:hermeto.bom.json"],
        [
            "hermeto:hermeto.bom.json",
            # merging these 4 should result in syft.merged-by-us.bom.json
            # merging the result with the hermeto.bom.json should be the same as the cases above
            *INDIVIDUAL_SYFT_SBOMS,
        ],
    ],
)
@pytest.mark.parametrize(
    "sbom_type, should_take_from_syft",
    [
        (
            "cyclonedx",
            {
                # The operating system component appears only in CycloneDX Syft SBOMs, not SPDX
                "rhel@9.5": 1,
                # vvv Identical between CycloneDX and SPDX
                "pkg:golang/github.com/release-engineering/retrodep@v2.1.0#v2": 1,
                "pkg:rpm/rhel/basesystem@11-13.el9?arch=noarch&distro=rhel-9.5&upstream=basesystem-11-13.el9.src.rpm": 1,
                "pkg:rpm/rhel/bash@5.1.8-9.el9?arch=x86_64&distro=rhel-9.5&upstream=bash-5.1.8-9.el9.src.rpm": 1,
                "pkg:rpm/rhel/coreutils-single@8.32-36.el9?arch=x86_64&distro=rhel-9.5&upstream=coreutils-8.32-36.el9.src.rpm": 1,
                "pkg:rpm/rhel/filesystem@3.16-5.el9?arch=x86_64&distro=rhel-9.5&upstream=filesystem-3.16-5.el9.src.rpm": 1,
                "pkg:rpm/rhel/glibc@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/glibc-common@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/glibc-minimal-langpack@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/gpg-pubkey@5a6340b3-6229229e?distro=rhel-9.5": 1,
                "pkg:rpm/rhel/gpg-pubkey@fd431d51-4ae0493b?distro=rhel-9.5": 1,
                "pkg:rpm/rhel/libacl@2.3.1-4.el9?arch=x86_64&distro=rhel-9.5&upstream=acl-2.3.1-4.el9.src.rpm": 1,
                "pkg:rpm/rhel/libattr@2.5.1-3.el9?arch=x86_64&distro=rhel-9.5&upstream=attr-2.5.1-3.el9.src.rpm": 1,
                "pkg:rpm/rhel/libcap@2.48-9.el9_2?arch=x86_64&distro=rhel-9.5&upstream=libcap-2.48-9.el9_2.src.rpm": 1,
                "pkg:rpm/rhel/libgcc@11.5.0-2.el9?arch=x86_64&distro=rhel-9.5&upstream=gcc-11.5.0-2.el9.src.rpm": 1,
                "pkg:rpm/rhel/libselinux@3.6-1.el9?arch=x86_64&distro=rhel-9.5&upstream=libselinux-3.6-1.el9.src.rpm": 1,
                "pkg:rpm/rhel/libsepol@3.6-1.el9?arch=x86_64&distro=rhel-9.5&upstream=libsepol-3.6-1.el9.src.rpm": 1,
                "pkg:rpm/rhel/ncurses-base@6.2-10.20210508.el9?arch=noarch&distro=rhel-9.5&upstream=ncurses-6.2-10.20210508.el9.src.rpm": 1,
                "pkg:rpm/rhel/ncurses-libs@6.2-10.20210508.el9?arch=x86_64&distro=rhel-9.5&upstream=ncurses-6.2-10.20210508.el9.src.rpm": 1,
                "pkg:rpm/rhel/pcre2@10.40-6.el9?arch=x86_64&distro=rhel-9.5&upstream=pcre2-10.40-6.el9.src.rpm": 1,
                "pkg:rpm/rhel/pcre2-syntax@10.40-6.el9?arch=noarch&distro=rhel-9.5&upstream=pcre2-10.40-6.el9.src.rpm": 1,
                "pkg:rpm/rhel/redhat-release@9.5-0.6.el9?arch=x86_64&distro=rhel-9.5&upstream=redhat-release-9.5-0.6.el9.src.rpm": 1,
                "pkg:rpm/rhel/setup@2.13.7-10.el9?arch=noarch&distro=rhel-9.5&upstream=setup-2.13.7-10.el9.src.rpm": 1,
                "pkg:rpm/rhel/tzdata@2024b-2.el9?arch=noarch&distro=rhel-9.5&upstream=tzdata-2024b-2.el9.src.rpm": 1,
            },
        ),
        (
            "spdx",
            {
                # These root packages appear only in SPDX Syft SBOMs, not CycloneDX
                "SPDXRef-DocumentRoot-Directory-.": 1,
                "pkg:oci/registry.access.redhat.com/ubi9/ubi-micro@sha256:71c7ec827876417693bd3feb615a5c70753b78667cb27c17cb3a5346a6955da5?arch=amd64&tag=9.5": 1,
                # vvv Identical between CycloneDX and SPDX
                "pkg:golang/github.com/release-engineering/retrodep@v2.1.0#v2": 1,
                "pkg:rpm/rhel/basesystem@11-13.el9?arch=noarch&distro=rhel-9.5&upstream=basesystem-11-13.el9.src.rpm": 1,
                "pkg:rpm/rhel/bash@5.1.8-9.el9?arch=x86_64&distro=rhel-9.5&upstream=bash-5.1.8-9.el9.src.rpm": 1,
                "pkg:rpm/rhel/coreutils-single@8.32-36.el9?arch=x86_64&distro=rhel-9.5&upstream=coreutils-8.32-36.el9.src.rpm": 1,
                "pkg:rpm/rhel/filesystem@3.16-5.el9?arch=x86_64&distro=rhel-9.5&upstream=filesystem-3.16-5.el9.src.rpm": 1,
                "pkg:rpm/rhel/glibc@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/glibc-common@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/glibc-minimal-langpack@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/gpg-pubkey@5a6340b3-6229229e?distro=rhel-9.5": 1,
                "pkg:rpm/rhel/gpg-pubkey@fd431d51-4ae0493b?distro=rhel-9.5": 1,
                "pkg:rpm/rhel/libacl@2.3.1-4.el9?arch=x86_64&distro=rhel-9.5&upstream=acl-2.3.1-4.el9.src.rpm": 1,
                "pkg:rpm/rhel/libattr@2.5.1-3.el9?arch=x86_64&distro=rhel-9.5&upstream=attr-2.5.1-3.el9.src.rpm": 1,
                "pkg:rpm/rhel/libcap@2.48-9.el9_2?arch=x86_64&distro=rhel-9.5&upstream=libcap-2.48-9.el9_2.src.rpm": 1,
                "pkg:rpm/rhel/libgcc@11.5.0-2.el9?arch=x86_64&distro=rhel-9.5&upstream=gcc-11.5.0-2.el9.src.rpm": 1,
                "pkg:rpm/rhel/libselinux@3.6-1.el9?arch=x86_64&distro=rhel-9.5&upstream=libselinux-3.6-1.el9.src.rpm": 1,
                "pkg:rpm/rhel/libsepol@3.6-1.el9?arch=x86_64&distro=rhel-9.5&upstream=libsepol-3.6-1.el9.src.rpm": 1,
                "pkg:rpm/rhel/ncurses-base@6.2-10.20210508.el9?arch=noarch&distro=rhel-9.5&upstream=ncurses-6.2-10.20210508.el9.src.rpm": 1,
                "pkg:rpm/rhel/ncurses-libs@6.2-10.20210508.el9?arch=x86_64&distro=rhel-9.5&upstream=ncurses-6.2-10.20210508.el9.src.rpm": 1,
                "pkg:rpm/rhel/pcre2@10.40-6.el9?arch=x86_64&distro=rhel-9.5&upstream=pcre2-10.40-6.el9.src.rpm": 1,
                "pkg:rpm/rhel/pcre2-syntax@10.40-6.el9?arch=noarch&distro=rhel-9.5&upstream=pcre2-10.40-6.el9.src.rpm": 1,
                "pkg:rpm/rhel/redhat-release@9.5-0.6.el9?arch=x86_64&distro=rhel-9.5&upstream=redhat-release-9.5-0.6.el9.src.rpm": 1,
                "pkg:rpm/rhel/setup@2.13.7-10.el9?arch=noarch&distro=rhel-9.5&upstream=setup-2.13.7-10.el9.src.rpm": 1,
                "pkg:rpm/rhel/tzdata@2024b-2.el9?arch=noarch&distro=rhel-9.5&upstream=tzdata-2024b-2.el9.src.rpm": 1,
            },
        ),
    ],
)
def test_merge_hermeto_and_syft_sbom(
    args: list[str],
    sbom_type: str,
    should_take_from_syft: dict[str, int],
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.chdir(data_dir / sbom_type)
    result, _ = run_main(args, monkeypatch, capsys)

    with open("merged.bom.json") as file:
        expected_sbom = json.load(file)

    assert json.loads(result) == expected_sbom

    with open("hermeto.bom.json") as f:
        hermeto_sbom = json.load(f)

    taken_from_syft = diff_counts(count_components(expected_sbom), count_components(hermeto_sbom))
    assert taken_from_syft == should_take_from_syft

    if sbom_type == "spdx":
        relationships_from_syft = diff_counts(count_relationships(expected_sbom), count_relationships(hermeto_sbom))
        assert relationships_from_syft == {
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Directory-.": 1,
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Image-registry.access.redhat.com-ubi9-ubi-micro": 1,
            # The one pkg:golang package
            "SPDXRef-DocumentRoot-Directory-. CONTAINS *": 1,
            # All the pkg:rpm packages
            "SPDXRef-DocumentRoot-Image-registry.access.redhat.com-ubi9-ubi-micro CONTAINS *": 22,
        }


@pytest.mark.parametrize(
    "args",
    [
        ["foo:x.json", "bar:y.json"],
        ["syft:x.json", "bar:y.json"],
        ["hermeto:x.json", "hermeto:y.json"],
        # invalid because left defaults to hermeto
        ["x.json", "hermeto:y.json"],
    ],
)
def test_invalid_flavours_combination(
    args: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    with pytest.raises(ValueError, match="Unsupported combination of SBOM flavours"):
        run_main(args, monkeypatch, capsys)


@pytest.mark.parametrize(
    "syft_tools_metadata, hermeto_tools_metadata, expected_result",
    [
        (
            [TOOLS_METADATA["syft-cyclonedx-1.4"]],
            [TOOLS_METADATA["hermeto-cyclonedx-1.4"]],
            [
                TOOLS_METADATA["syft-cyclonedx-1.4"],
                TOOLS_METADATA["hermeto-cyclonedx-1.4"],
            ],
        ),
        (
            [TOOLS_METADATA["syft-cyclonedx-1.4"]],
            {
                "components": [TOOLS_METADATA["hermeto-cyclonedx-1.5"]],
            },
            [
                TOOLS_METADATA["syft-cyclonedx-1.4"],
                TOOLS_METADATA["hermeto-cyclonedx-1.4"],
            ],
        ),
        (
            {
                "components": [TOOLS_METADATA["syft-cyclonedx-1.5"]],
            },
            {
                "components": [TOOLS_METADATA["hermeto-cyclonedx-1.5"]],
            },
            {
                "components": [
                    TOOLS_METADATA["syft-cyclonedx-1.5"],
                    TOOLS_METADATA["hermeto-cyclonedx-1.5"],
                ],
            },
        ),
        (
            {
                "components": [TOOLS_METADATA["syft-cyclonedx-1.5"]],
            },
            [TOOLS_METADATA["hermeto-cyclonedx-1.4"]],
            {
                "components": [
                    TOOLS_METADATA["syft-cyclonedx-1.5"],
                    TOOLS_METADATA["hermeto-cyclonedx-1.5"],
                ],
            },
        ),
    ],
)
def test_merging_tools_metadata(syft_tools_metadata: Any, hermeto_tools_metadata: Any, expected_result: Any) -> None:
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": syft_tools_metadata,
        },
        "components": [],
    }

    hermeto_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": hermeto_tools_metadata,
        },
        "components": [],
    }

    result = merge_cyclonedx_sboms(syft_sbom, hermeto_sbom, merge_by_apparent_sameness)

    assert result["metadata"]["tools"] == expected_result


def test_invalid_tools_format() -> None:
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": "invalid",
        },
        "components": [],
    }

    hermeto_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": [TOOLS_METADATA["hermeto-cyclonedx-1.4"]],
        },
        "components": [],
    }

    with pytest.raises(RuntimeError):
        merge_cyclonedx_sboms(syft_sbom, hermeto_sbom, merge_by_apparent_sameness)
