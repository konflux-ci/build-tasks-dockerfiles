import json
import sys
from pathlib import Path
from typing import Any

import pytest

from merge_cachi2_sboms import main, merge_by_apparent_sameness, merge_cyclonedx_sboms

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
    "cachi2-cyclonedx-1.4": {
        "name": "cachi2",
        "vendor": "red hat",
    },
    "cachi2-cyclonedx-1.5": {
        "type": "application",
        "author": "red hat",
        "name": "cachi2",
    },
}


@pytest.fixture
def data_dir() -> Path:
    """Path to the directory for storing unit test data."""
    return Path(__file__).parent / "test_data"


def get_purls(sbom: dict[str, Any]) -> set[str]:
    return {component["purl"] for component in sbom["components"]}


def run_main(args: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> tuple[str, str]:
    monkeypatch.setattr(sys, "argv", ["unused_script_name", *args])
    main()
    return capsys.readouterr()


@pytest.mark.parametrize(
    "args",
    [
        ["cachi2.bom.json", "syft.bom.json"],
        ["cachi2:cachi2.bom.json", "syft:syft.bom.json"],
        ["syft:syft.bom.json", "cachi2:cachi2.bom.json"],
    ],
)
def test_merge_cachi2_and_syft_sbom(
    args: list[str],
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.chdir(data_dir)
    result, _ = run_main(args, monkeypatch, capsys)

    with open("merged.bom.json") as file:
        expected_sbom = json.load(file)

    assert json.loads(result) == expected_sbom

    with open("cachi2.bom.json") as f:
        cachi2_sbom = json.load(f)

    purls_taken_from_syft_sbom = get_purls(expected_sbom) - get_purls(cachi2_sbom)
    assert purls_taken_from_syft_sbom == {
        "pkg:golang/github.com/release-engineering/retrodep@v2.1.0#v2",
        "pkg:rpm/rhel/basesystem@11-13.el9?arch=noarch&upstream=basesystem-11-13.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/bash@5.1.8-9.el9?arch=x86_64&upstream=bash-5.1.8-9.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/coreutils-single@8.32-36.el9?arch=x86_64&upstream=coreutils-8.32-36.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/filesystem@3.16-5.el9?arch=x86_64&upstream=filesystem-3.16-5.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/glibc-common@2.34-125.el9_5.1?arch=x86_64&upstream=glibc-2.34-125.el9_5.1.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/glibc-minimal-langpack@2.34-125.el9_5.1?arch=x86_64&upstream=glibc-2.34-125.el9_5.1.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/glibc@2.34-125.el9_5.1?arch=x86_64&upstream=glibc-2.34-125.el9_5.1.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/gpg-pubkey@5a6340b3-6229229e?distro=rhel-9.5",
        "pkg:rpm/rhel/gpg-pubkey@fd431d51-4ae0493b?distro=rhel-9.5",
        "pkg:rpm/rhel/libacl@2.3.1-4.el9?arch=x86_64&upstream=acl-2.3.1-4.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/libattr@2.5.1-3.el9?arch=x86_64&upstream=attr-2.5.1-3.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/libcap@2.48-9.el9_2?arch=x86_64&upstream=libcap-2.48-9.el9_2.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/libgcc@11.5.0-2.el9?arch=x86_64&upstream=gcc-11.5.0-2.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/libselinux@3.6-1.el9?arch=x86_64&upstream=libselinux-3.6-1.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/libsepol@3.6-1.el9?arch=x86_64&upstream=libsepol-3.6-1.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/ncurses-base@6.2-10.20210508.el9?arch=noarch&upstream=ncurses-6.2-10.20210508.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/ncurses-libs@6.2-10.20210508.el9?arch=x86_64&upstream=ncurses-6.2-10.20210508.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/pcre2-syntax@10.40-6.el9?arch=noarch&upstream=pcre2-10.40-6.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/pcre2@10.40-6.el9?arch=x86_64&upstream=pcre2-10.40-6.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/redhat-release@9.5-0.6.el9?arch=x86_64&upstream=redhat-release-9.5-0.6.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/setup@2.13.7-10.el9?arch=noarch&upstream=setup-2.13.7-10.el9.src.rpm&distro=rhel-9.5",
        "pkg:rpm/rhel/tzdata@2024b-2.el9?arch=noarch&upstream=tzdata-2024b-2.el9.src.rpm&distro=rhel-9.5",
    }


@pytest.mark.parametrize(
    "args",
    [
        ["foo:x.json", "bar:y.json"],
        ["syft:x.json", "bar:y.json"],
        ["cachi2:x.json", "cachi2:y.json"],
        # invalid because left defaults to cachi2
        ["x.json", "cachi2:y.json"],
    ],
)
def test_invalid_flavours_combination(
    args: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    with pytest.raises(ValueError, match="Unsupported combination of SBOM flavours"):
        run_main(args, monkeypatch, capsys)


@pytest.mark.parametrize(
    "syft_tools_metadata, cachi2_tools_metadata, expected_result",
    [
        (
            [TOOLS_METADATA["syft-cyclonedx-1.4"]],
            [TOOLS_METADATA["cachi2-cyclonedx-1.4"]],
            [
                TOOLS_METADATA["syft-cyclonedx-1.4"],
                TOOLS_METADATA["cachi2-cyclonedx-1.4"],
            ],
        ),
        (
            [TOOLS_METADATA["syft-cyclonedx-1.4"]],
            {
                "components": [TOOLS_METADATA["cachi2-cyclonedx-1.5"]],
            },
            [
                TOOLS_METADATA["syft-cyclonedx-1.4"],
                TOOLS_METADATA["cachi2-cyclonedx-1.4"],
            ],
        ),
        (
            {
                "components": [TOOLS_METADATA["syft-cyclonedx-1.5"]],
            },
            {
                "components": [TOOLS_METADATA["cachi2-cyclonedx-1.5"]],
            },
            {
                "components": [
                    TOOLS_METADATA["syft-cyclonedx-1.5"],
                    TOOLS_METADATA["cachi2-cyclonedx-1.5"],
                ],
            },
        ),
        (
            {
                "components": [TOOLS_METADATA["syft-cyclonedx-1.5"]],
            },
            [TOOLS_METADATA["cachi2-cyclonedx-1.4"]],
            {
                "components": [
                    TOOLS_METADATA["syft-cyclonedx-1.5"],
                    TOOLS_METADATA["cachi2-cyclonedx-1.5"],
                ],
            },
        ),
    ],
)
def test_merging_tools_metadata(syft_tools_metadata: Any, cachi2_tools_metadata: Any, expected_result: Any) -> None:
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": syft_tools_metadata,
        },
        "components": [],
    }

    cachi2_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": cachi2_tools_metadata,
        },
        "components": [],
    }

    result = merge_cyclonedx_sboms(syft_sbom, cachi2_sbom, merge_by_apparent_sameness)

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

    cachi2_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": [TOOLS_METADATA["cachi2-cyclonedx-1.4"]],
        },
        "components": [],
    }

    with pytest.raises(RuntimeError):
        merge_cyclonedx_sboms(syft_sbom, cachi2_sbom, merge_by_apparent_sameness)
