#!/usr/bin/env python3
import functools
import itertools
import json
from argparse import ArgumentParser
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol, Sequence
from urllib.parse import quote_plus

from packageurl import PackageURL


def try_parse_purl(s: str) -> PackageURL | None:
    try:
        return PackageURL.from_string(s)
    except ValueError:
        return None


class SBOMItem(Protocol):
    def name(self) -> str: ...
    def version(self) -> str: ...
    def purl(self) -> PackageURL | None: ...


@dataclass
class CDXComponent:
    data: dict[str, Any]

    def name(self) -> str:
        return self.data["name"]

    def version(self) -> str:
        return self.data.get("version") or ""

    def purl(self) -> PackageURL | None:
        if purl_str := self.data.get("purl"):
            return try_parse_purl(purl_str)
        return None


def wrap_as_cdx(items: Iterable[dict[str, Any]]) -> list[CDXComponent]:
    return list(map(CDXComponent, items))


def unwrap_from_cdx(items: list[CDXComponent]) -> list[dict[str, Any]]:
    return [c.data for c in items]


def _subpath_is_version(subpath: str) -> bool:
    # pkg:golang/github.com/cachito-testing/gomod-pandemonium@v0.0.0#terminaltor -> subpath is a subpath
    # pkg:golang/github.com/cachito-testing/retrodep@v2.1.1#v2 -> subpath is a version. Thanks, Syft.
    return subpath.startswith("v") and subpath.removeprefix("v").isdecimal()


def _is_syft_local_golang_component(component: SBOMItem) -> bool:
    """
    Check if a Syft Golang reported component is a local replacement.

    Local replacements are reported in a very different way by Cachi2, which is why the same
    reports by Syft should be removed.
    """
    purl = component.purl()
    if not purl or purl.type != "golang":
        return False
    if (subpath := purl.subpath) and not _subpath_is_version(subpath):
        return True
    return component.name().startswith(".") or component.version() == "(devel)"


def _is_cachi2_non_registry_dependency(component: SBOMItem) -> bool:
    """
    Check if Cachi2 component was fetched from a VCS or a direct file location.

    Cachi2 reports non-registry components in a different way from Syft, so the reports from
    Syft need to be removed.

    Unfortunately, there's no way to determine which components are non-registry by looking
    at the Syft report alone. This function is meant to create a list of non-registry components
    from Cachi2's SBOM, then remove the corresponding ones reported by Syft for the merged SBOM.

    Note that this function is only applicable for PyPI or NPM components.
    """
    purl = component.purl()
    if not purl:
        return False

    qualifiers = purl.qualifiers or {}
    return purl.type in ("pypi", "npm") and ("vcs_url" in qualifiers or "download_url" in qualifiers)


def _unique_key_cachi2(component: SBOMItem) -> str:
    """
    Create a unique key from Cachi2 reported components.

    This is done by taking a purl and removing any qualifiers and subpaths.

    See https://github.com/package-url/purl-spec/tree/master#purl for more info on purls.
    """
    purl = component.purl()
    if not purl:
        raise ValueError(f"cachi2 component with no purl? name={component.name()}, version={component.version()}")
    return purl._replace(qualifiers=None, subpath=None).to_string()


def _unique_key_syft(component: SBOMItem) -> str:
    """
    Create a unique key for Syft reported components.

    This is done by taking a lowercase namespace/name, and URL encoding the version.

    Syft does not set any qualifier for NPM, Pip or Golang, so there's no need to remove them
    as done in _unique_key_cachi2.

    If a Syft component lacks a purl (e.g. type OS), we'll use its name and version instead.
    """
    purl = component.purl()
    if not purl:
        return component.name() + "@" + component.version()

    name = purl.name
    version = purl.version
    subpath = purl.subpath

    if purl.type == "pypi":
        name = name.lower()

    if purl.type == "golang":
        if version:
            version = quote_plus(version)
        if subpath and _subpath_is_version(subpath):
            # put the module version where it belongs (in the module name)
            name = f"{name}/{subpath}"
            subpath = None

    return purl._replace(name=name, version=version, subpath=subpath).to_string()


def _get_syft_component_filter(cachi_sbom_components: Sequence[SBOMItem]) -> Callable[[SBOMItem], bool]:
    """
    Get a function that filters out Syft components for the merged SBOM.

    This function currently considers a Syft component as a duplicate/removable if:
    - it has the same key as a Cachi2 component
    - it is a local Golang replacement
    - is a non-registry component also reported by Cachi2

    Note that for the last bullet, we can only rely on the Pip dependency's name to find a
    duplicate. This is because Cachi2 does not report a non-PyPI Pip dependency's version.

    Even though multiple versions of a same dependency can be available in the same project,
    we are removing all Syft instances by name only because Cachi2 will report them correctly,
    given that it scans all the source code properly and the image is built hermetically.
    """
    cachi2_non_registry_components = [
        component.name() for component in cachi_sbom_components if _is_cachi2_non_registry_dependency(component)
    ]
    cachi2_local_paths = {
        Path(subpath) for component in cachi_sbom_components if (purl := component.purl()) and (subpath := purl.subpath)
    }

    cachi2_indexed_components = {_unique_key_cachi2(component): component for component in cachi_sbom_components}

    def is_duplicate_non_registry_component(component: SBOMItem) -> bool:
        return component.name() in cachi2_non_registry_components

    def is_duplicate_npm_localpath_component(component: SBOMItem) -> bool:
        purl = component.purl()
        if not purl or purl.type != "npm":
            return False
        # instead of reporting path dependencies as pkg:npm/name@version?...#subpath,
        # syft repots them as pkg:npm/subpath@version
        return Path(purl.namespace or "", purl.name) in cachi2_local_paths

    def component_is_duplicated(component: SBOMItem) -> bool:
        key = _unique_key_syft(component)

        return (
            _is_syft_local_golang_component(component)
            or is_duplicate_non_registry_component(component)
            or is_duplicate_npm_localpath_component(component)
            or key in cachi2_indexed_components.keys()
        )

    return component_is_duplicated


def _merge_tools_metadata(sbom_a: dict[Any, Any], sbom_b: dict[Any, Any]) -> None:
    """Merge the .metadata.tools of the right SBOM into the left SBOM.

    Handle both the 1.4 style and the 1.5 style of .metadata.tools.
    If the SBOMs don't use the same style, conform to the left SBOM.
    """
    # https://cyclonedx.org/docs/1.4/json/#metadata_tools
    # vs.
    # https://cyclonedx.org/docs/1.5/json/#metadata_tools
    shared_keys = ["name", "version", "hashes", "externalReferences"]

    def tool_to_component(tool: dict[str, Any]) -> dict[str, Any]:
        component = {key: tool[key] for key in shared_keys if key in tool}
        if vendor := tool.get("vendor"):
            component["author"] = vendor
        component["type"] = "application"
        return component

    def component_to_tool(component: dict[str, Any]) -> dict[str, Any]:
        tool = {key: component[key] for key in shared_keys if key in component}
        if author := component.get("author"):
            tool["vendor"] = author
        return tool

    tools_a = sbom_a["metadata"]["tools"]
    tools_b = sbom_b["metadata"]["tools"]

    if isinstance(tools_a, dict):
        components_a = tools_a["components"]
        if isinstance(tools_b, dict):
            components_b = tools_b["components"]
        else:
            components_b = map(tool_to_component, tools_b)

        merged_components = merge_by_apparent_sameness(wrap_as_cdx(components_a), wrap_as_cdx(components_b))
        sbom_a["metadata"]["tools"]["components"] = unwrap_from_cdx(merged_components)
    elif isinstance(tools_a, list):
        if isinstance(tools_b, dict):
            tools_b = map(component_to_tool, tools_b["components"])

        sbom_a["metadata"]["tools"] = _merge(tools_a, tools_b, lambda t: (t["name"], t.get("version")))
    else:
        raise RuntimeError(
            f"The .metadata.tools JSON key is in an unexpected format. Expected dict or list, got {type(tools_a)}."
        )


type MergeComponentsFunc[T: SBOMItem] = Callable[[Sequence[T], Sequence[T]], list[T]]


def merge_by_prefering_cachi2[T: SBOMItem](syft_components: Sequence[T], cachi2_components: Sequence[T]) -> list[T]:
    is_duplicate_component = _get_syft_component_filter(cachi2_components)
    merged = [c for c in syft_components if not is_duplicate_component(c)]
    merged += cachi2_components
    return merged


def merge_by_apparent_sameness[T: SBOMItem](components_a: Sequence[T], components_b: Sequence[T]) -> list[T]:
    def key(component: SBOMItem) -> str:
        purl = component.purl()
        if purl:
            return purl.to_string()
        return f"{component.name()}@{component.version()}"

    return _merge(components_a, components_b, key)


def _merge[T](items_a: Iterable[T], items_b: Iterable[T], by_key: Callable[[T], Any]) -> list[T]:
    return _dedupe(itertools.chain(items_a, items_b), by_key)


def _dedupe[T](items: Iterable[T], by_key: Callable[[T], Any]) -> list[T]:
    item_by_key: dict[Any, T] = {}
    for item in items:
        item_by_key.setdefault(by_key(item), item)

    return list(item_by_key.values())


def merge_cyclonedx_sboms(
    sbom_a: dict[str, Any],
    sbom_b: dict[str, Any],
    merge_components: MergeComponentsFunc[CDXComponent],
) -> dict[str, Any]:
    """Merge two CycloneDX SBOMs."""
    components_a = wrap_as_cdx(sbom_a.get("components", []))
    components_b = wrap_as_cdx(sbom_b.get("components", []))
    merged = merge_components(components_a, components_b)

    sbom_a["components"] = unwrap_from_cdx(merged)
    _merge_tools_metadata(sbom_a, sbom_b)

    return sbom_a


def merge_syft_and_cachi2_sboms(syft_sbom_paths: list[str], cachi2_sbom_path: str) -> dict[str, Any]:
    syft_sbom = merge_n_syft_sboms(syft_sbom_paths)

    with open(cachi2_sbom_path) as file:
        cachi2_sbom = json.load(file)

    return merge_cyclonedx_sboms(syft_sbom, cachi2_sbom, merge_by_prefering_cachi2)


def merge_n_syft_sboms(syft_sbom_paths: list[str]) -> dict[str, Any]:
    sboms = []
    for path in syft_sbom_paths:
        with open(path) as f:
            sboms.append(json.load(f))

    merge = functools.partial(merge_cyclonedx_sboms, merge_components=merge_by_apparent_sameness)
    merged_sbom = functools.reduce(merge, sboms)
    return merged_sbom


def parse_sbom_arg(arg: str, default_flavour: str) -> tuple[str, str]:
    before_colon, colon, after_colon = arg.partition(":")
    if colon:
        flavour = before_colon.lower()
        path = after_colon
    else:
        path = before_colon
        flavour = default_flavour

    return flavour, path


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("sbom_a")
    parser.add_argument("more_sboms", nargs="+")
    args = parser.parse_args()

    # For backwards compatiblity, if the flavour is unspecified,
    # the left SBOM defaults to cachi2 and the right one(s) to syft.
    sbom_a: tuple[str, str] = parse_sbom_arg(args.sbom_a, default_flavour="cachi2")
    more_sboms: list[tuple[str, str]] = [parse_sbom_arg(arg, default_flavour="syft") for arg in args.more_sboms]

    sboms = [sbom_a, *more_sboms]
    sbom_paths_by_flavour: dict[str, list[str]] = defaultdict(list)
    for flavour, path in sboms:
        sbom_paths_by_flavour[flavour].append(path)

    merged = None

    match sbom_paths_by_flavour:
        case {"cachi2": [cachi2_sbom_path], "syft": syft_sbom_paths, **extra} if not extra:
            merged = merge_syft_and_cachi2_sboms(syft_sbom_paths, cachi2_sbom_path)
        case {"syft": syft_sbom_paths, **extra} if not extra:
            merged = merge_n_syft_sboms(syft_sbom_paths)
        case _:
            flavours = " X ".join(flavour for flavour, _ in sboms)
            raise ValueError(
                f"Unsupported combination of SBOM flavours: {flavours}\n"
                "\n"
                "This script supports merging 0 or 1 cachi2 SBOM with >=1 syft SBOMs"
            )

    print(json.dumps(merged, indent=2))


if __name__ == "__main__":
    main()