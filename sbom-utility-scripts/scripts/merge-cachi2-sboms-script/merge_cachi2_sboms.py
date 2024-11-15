#!/usr/bin/env python3
import json
from argparse import ArgumentParser
from typing import Any, Callable
from urllib.parse import quote_plus, urlsplit
from packageurl import PackageURL


def _is_syft_local_golang_component(component: dict) -> bool:
    """
    Check if a Syft Golang reported component is a local replacement.

    Local replacements are reported in a very different way by Cachi2, which is why the same
    reports by Syft should be removed.
    """
    return component.get("purl", "").startswith("pkg:golang") and (
        component.get("name", "").startswith(".") or component.get("version", "") == "(devel)"
    )


def _is_syft_local_golang_package(package: dict) -> bool:
    """
    Check if a Syft Golang reported package is a local replacement.

    Local replacements are reported in a very different way by Cachi2, which is why the same
    reports by Syft should be removed.
    """
    for ref in package.get("externalRefs", []):
        if (
            ref["referenceType"] == "purl"
            and ref["referenceLocator"].startswith("pkg:golang")
            and (package.get("name", "").startswith(".") or package.get("versionInfo", "") == "(devel)")
        ):
            return True
    return False


def _is_cachi2_non_registry_dependency(component: dict) -> bool:
    """
    Check if Cachi2 component was fetched from a VCS or a direct file location.

    Cachi2 reports non-registry components in a different way from Syft, so the reports from
    Syft need to be removed.

    Unfortunately, there's no way to determine which components are non-registry by looking
    at the Syft report alone. This function is meant to create a list of non-registry components
    from Cachi2's SBOM, then remove the corresponding ones reported by Syft for the merged SBOM.

    Note that this function is only applicable for PyPI or NPM components.
    """
    purl = component.get("purl", "")

    return (purl.startswith("pkg:pypi") or purl.startswith("pkg:npm")) and (
        "vcs_url=" in purl or "download_url=" in purl
    )


def _is_cachi2_non_registry_dependency_spdx(package: dict) -> bool:
    """
    Check if Cachi2 component was fetched from a VCS or a direct file location.

    Cachi2 reports non-registry package in a different way from Syft, so the reports from
    Syft need to be removed.

    Unfortunately, there's no way to determine which components are non-registry by looking
    at the Syft report alone. This function is meant to create a list of non-registry components
    from Cachi2's SBOM, then remove the corresponding ones reported by Syft for the merged SBOM.

    Note that this function is only applicable for PyPI or NPM components.
    """
    for ref in package.get("externalRefs", []):
        if ref["referenceType"] == "purl":
            purl = ref["referenceLocator"]
            if (purl.startswith("pkg:pypi") or purl.startswith("pkg:npm")) and (
                "vcs_url=" in purl or "download_url=" in purl
            ):
                return True
    return False


def _unique_key_cachi2(component: dict) -> str:
    """
    Create a unique key from Cachi2 reported components.

    This is done by taking a purl and removing any qualifiers and subpaths.

    See https://github.com/package-url/purl-spec/tree/master#purl for more info on purls.
    """
    url = urlsplit(component["purl"])
    return url.scheme + ":" + url.path


def _unique_key_cachi2_spdx(package: dict) -> list[str]:
    """
    Create a unique key from Cachi2 reported packages.

    Cachi2 produce unique packages and combining purls togher to package with the same name and version
    """
    keys = []
    for ref in package.get("externalRefs", []):
        if ref["referenceType"] == "purl":
            parsed_purl = PackageURL.from_string(ref["referenceLocator"])
            name = parsed_purl.type + "/" + (parsed_purl.namespace or "") + "/" + parsed_purl.name
            version = parsed_purl.version or ""
            if parsed_purl.type == "pypi":
                name = name.lower()
            if parsed_purl.type == "golang":
                version = quote_plus(version)
            keys.append(name + "@" + version)
    return keys


def _unique_key_syft(component: dict) -> str:
    """
    Create a unique key for Syft reported components.

    This is done by taking a lowercase namespace/name, and URL encoding the version.

    Syft does not set any qualifier for NPM, Pip or Golang, so there's no need to remove them
    as done in _unique_key_cachi2.

    If a Syft component lacks a purl (e.g. type OS), we'll use its name and version instead.
    """
    if "purl" not in component:
        return component.get("name", "") + "@" + component.get("version", "")

    if "@" in component["purl"]:
        name, version = component["purl"].split("@")

        if name.startswith("pkg:pypi"):
            name = name.lower()

        if name.startswith("pkg:golang"):
            version = quote_plus(version)

        return f"{name}@{version}"
    else:
        return component["purl"]


def _unique_keys_syft_spdx(package: dict) -> str:
    """
    Create a unique keys for Syft reported components.

    This is done in following way:
    - If package doesn't have purl, return [<name>@<versionInfo>] as unique keys
    - If package has purl(s), take each purl and parse it and take type/namespace/name and version of it
    -- If package is pypy, convert type/namespace/name to loweracse
    -- If package is golang, encode version
    - Append this final key to list of unique keys

    Syft does not set any qualifier for NPM, Pip or Golang, so there's no need to remove them
    as done in _unique_key_cachi2.
    """
    for ref in package.get("externalRefs", []):
        if ref["referenceType"] == "purl":
            break
    else:
        return [package.get("name", "") + "@" + package.get("versionInfo", "")]

    keys = []

    for ref in package.get("externalRefs", []):
        if ref["referenceType"] == "purl":
            purl = ref["referenceLocator"]
            parsed_purl = PackageURL.from_string(purl)
            if parsed_purl.version:
                version = parsed_purl.version
                name = (parsed_purl.type + "/" + (parsed_purl.namespace or "") + "/" + parsed_purl.name).lower()

                if parsed_purl.type == "pypi":
                    name = name.lower()

                if parsed_purl.type == "golang":
                    version = quote_plus(version)
                keys.append(f"{name}@{version}")
            else:
                keys.append(purl)
    return keys


def _get_syft_component_filter(cachi_sbom_components: list[dict[str, Any]]) -> Callable:
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
        component["name"] for component in cachi_sbom_components if _is_cachi2_non_registry_dependency(component)
    ]

    cachi2_indexed_components = {_unique_key_cachi2(component): component for component in cachi_sbom_components}

    def is_duplicate_non_registry_component(component: dict[str, Any]) -> bool:
        return component["name"] in cachi2_non_registry_components

    def component_is_duplicated(component: dict[str, Any]) -> bool:
        key = _unique_key_syft(component)

        return (
            _is_syft_local_golang_component(component)
            or is_duplicate_non_registry_component(component)
            or key in cachi2_indexed_components.keys()
        )

    return component_is_duplicated


def _get_syft_package_filter(cachi_sbom_packages: list[dict[str, Any]]) -> Callable:
    """
    Get a function that filters out Syft packages for the merged SBOM.

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
    cachi2_non_registry_packages = [
        package["name"] for package in cachi_sbom_packages if _is_cachi2_non_registry_dependency_spdx(package)
    ]

    cachi2_indexed_packages = {}
    for package in cachi_sbom_packages:
        for key in _unique_key_cachi2_spdx(package):
            cachi2_indexed_packages[key] = package

    def is_duplicate_non_registry_package(package: dict[str, Any]) -> bool:
        return package["name"] in cachi2_non_registry_packages

    def package_is_duplicated(package: dict[str, Any]) -> bool:
        keys = _unique_keys_syft_spdx(package)

        return (
            _is_syft_local_golang_package(package)
            or is_duplicate_non_registry_package(package)
            or set(keys) & set(cachi2_indexed_packages.keys())
        )

    return package_is_duplicated


def _merge_tools_metadata(syft_sbom: dict[Any, Any], cachi2_sbom: dict[Any, Any]) -> None:
    """Merge the content of tools in the metadata section of the SBOM.

    With CycloneDX 1.5, a new format for specifying tools was introduced, and the format from 1.4
    was marked as deprecated.

    This function aims to support both formats in the Syft SBOM. We're assuming the Cachi2 SBOM
    was generated with the same version as this script, and it will be in the older format.
    """
    syft_tools = syft_sbom["metadata"]["tools"]
    cachi2_tools = cachi2_sbom["metadata"]["tools"]

    if isinstance(syft_tools, dict):
        components = []

        for t in cachi2_tools:
            components.append(
                {
                    "author": t["vendor"],
                    "name": t["name"],
                    "type": "application",
                }
            )

        syft_tools["components"].extend(components)
    elif isinstance(syft_tools, list):
        syft_tools.extend(cachi2_tools)
    else:
        raise RuntimeError(
            "The .metadata.tools JSON key is in an unexpected format. "
            f"Expected dict or list, got {type(syft_tools)}."
        )


def _merge_tools_metadata_spdx(syft_sbom: dict[Any, Any], cachi2_sbom: dict[Any, Any]) -> None:
    """Merge the creators in the metadata section of the SBOM."""
    cachi2_creators = cachi2_sbom["creationInfo"]["creators"]

    for creator in cachi2_creators:
        syft_sbom["creationInfo"]["creators"].append(creator)


def merge_components(syft_sbom: dict, cachi2_sbom: dict) -> dict:
    """Merge Cachi2 components into the Syft SBOM while removing duplicates."""
    is_duplicate_component = _get_syft_component_filter(cachi2_sbom["components"])
    filtered_syft_components = [c for c in syft_sbom.get("components", []) if not is_duplicate_component(c)]
    return filtered_syft_components + cachi2_sbom["components"]


def merge_external_refs(refs1, refs2):
    """Merge SPDX external references while removing duplicates."""
    ref_tuples = []
    unique_refs2 = []

    for _ref in refs1:
        ref = _ref.copy()
        if ref["referenceType"].lower() == "purl":
            parsed_purl = PackageURL.from_string(ref["referenceLocator"])
            purl_dict = parsed_purl.to_dict()
            purl_dict["qualifiers"] = {}
            parsed_purl = PackageURL(**purl_dict)
            ref["referenceLocator"] = parsed_purl.to_string()

        ref_tuples.append(
            (
                ref["referenceCategory"].lower(),
                ref["referenceType"].lower(),
                ref["referenceLocator"].lower(),
            )
        )

    for _ref in refs2:
        ref = _ref.copy()
        if ref["referenceType"].lower() == "purl":
            parsed_purl = PackageURL.from_string(ref["referenceLocator"])
            purl_dict = parsed_purl.to_dict()
            purl_dict["qualifiers"] = {}
            parsed_purl = PackageURL(**purl_dict)
            ref["referenceLocator"] = parsed_purl.to_string()
        if (
            ref["referenceCategory"].lower(),
            ref["referenceType"].lower(),
            ref["referenceLocator"].lower(),
        ) not in ref_tuples:
            unique_refs2.append(ref)
    return [ref for ref in refs1 + unique_refs2]


def merge_annotations(annotations1, annotations2):
    """Merge SPDX package annotations."""
    annotation_tuples = []
    for annotation in annotations1:
        annotation_tuples.append(
            (
                annotation["annotator"],
                annotation["comment"],
                annotation["annotationDate"],
                annotation["annotationType"],
            )
        )
    for annotation in annotations2:
        annotation_tuples.append(
            (
                annotation["annotator"],
                annotation["comment"],
                annotation["annotationDate"],
                annotation["annotationType"],
            )
        )
    annotations = set(annotation_tuples)
    return [
        {
            "annotator": annotation[0],
            "comment": annotation[1],
            "annotationDate": annotation[2],
            "annotationType": annotation[3],
        }
        for annotation in annotations
    ]


def merge_relationships(relationships1, relationships2, packages):
    """Merge SPDX relationships."""

    def map_relationships(relationships):
        """Map relationships of spdx element.
        Method returns triplet containing root element, map of relations and inverse map of relations.
        Root element is considered as element which is not listed as related document
        in any of the relationships. Relationship map is dict of {key: value} where key is spdx
        element and list of related elements is the value.
        Inverse map is dict of {key: value} where key is related spdx element in the relation ship
        and value is spdx element.
        """
        relations_map = {}
        relations_inverse_map = {}

        for relation in relationships:
            relations_map.setdefault(relation["spdxElementId"], []).append(relation["relatedSpdxElement"])
            relations_inverse_map[relation["relatedSpdxElement"]] = relation["spdxElementId"]

        for parent_element in relations_map.keys():
            if parent_element not in relations_inverse_map:
                break
        return parent_element, relations_map, relations_inverse_map

    def calculate_middle_element(root_element, map, inverse_map):
        """Calculate middle element of the relationship.
        Middle element is considered as element which is related to root element and is not root element.
        """
        middle_element = None
        for r, contains in map.items():
            if contains and inverse_map.get(r) == root_element:
                middle_element = r
        return middle_element

    relationships = []

    root_element1, map1, inverse_map1 = map_relationships(relationships1)
    root_element2, map2, inverse_map2 = map_relationships(relationships2)
    package_ids = [package["SPDXID"] for package in packages]

    middle_element1 = calculate_middle_element(root_element1, map1, inverse_map1)
    middle_element2 = calculate_middle_element(root_element2, map2, inverse_map2)

    for relation in relationships2:
        _relation = relation.copy()

        # If relations is Root decribes middle element, skip it
        if (
            _relation["relatedSpdxElement"] == middle_element2
            and _relation["spdxElementId"] == root_element2
            and _relation["relationshipType"] == "DESCRIBES"
        ):
            continue
        # if spdxElementId is root_element2, replace it with root_element1
        # if not and relatedSpdxElement is root_element2, replace it with root_element1
        if _relation["spdxElementId"] == root_element2:
            _relation["spdxElementId"] = root_element1
        elif relation["relatedSpdxElement"] == root_element2:
            _relation["relatedSpdxElement"] = root_element1
        if _relation["spdxElementId"] == middle_element2:
            _relation["spdxElementId"] = middle_element1
        if _relation["relatedSpdxElement"] == middle_element2:
            _relation["relatedSpdxElement"] = middle_element1

        # include only relations to packages which exists in merged packages.
        if _relation["relatedSpdxElement"] in package_ids:
            relationships.append(_relation)
        elif _relation["spdxElementId"] in package_ids:
            relationships.append(_relation)

    for relation in relationships1:
        _relation = relation.copy()
        if relation["relatedSpdxElement"] in package_ids:
            relationships.append(_relation)
    return relationships


def merge_packages(syft_sbom: dict, cachi2_sbom: dict) -> dict:
    """Merge Cachi2 packages into the Syft SBOM while removing duplicates."""

    def get_package_key(pkg):
        return json.dumps(sorted(set(_unique_keys_syft_spdx(pkg))), separators=(",", ":"))

    is_duplicate_package = _get_syft_package_filter(cachi2_sbom["packages"])
    cachi2_packages_map = {get_package_key(p): p for p in cachi2_sbom["packages"]}

    filtered_packages = []
    for p in syft_sbom.get("packages", []):
        if is_duplicate_package(p):
            if get_package_key(p) in cachi2_packages_map:
                cpackage = cachi2_packages_map[get_package_key(p)]
                cpackage["externalRefs"] = sorted(
                    merge_external_refs(cpackage.get("externalRefs", []), p.get("externalRefs", [])),
                    key=lambda x: (
                        x["referenceCategory"],
                        x["referenceType"],
                        x["referenceLocator"],
                    ),
                )
                cpackage["annotations"] = merge_annotations(cpackage.get("annotations", []), p.get("annotations", []))
        else:
            filtered_packages.append(p)
    return filtered_packages + cachi2_sbom["packages"]


def merge_sboms(cachi2_sbom_path: str, syft_sbom_path: str, format: str = "cyclonedx") -> str:
    """Merge Cachi2 components into the Syft SBOM while removing duplicates."""
    with open(cachi2_sbom_path) as file:
        cachi2_sbom = json.load(file)

    with open(syft_sbom_path) as file:
        syft_sbom = json.load(file)

    if format == "cyclonedx":
        syft_sbom["components"] = merge_components(syft_sbom, cachi2_sbom)
        _merge_tools_metadata(syft_sbom, cachi2_sbom)
    else:
        syft_sbom["packages"] = merge_packages(syft_sbom, cachi2_sbom)

        syft_sbom["relationships"] = merge_relationships(
            syft_sbom.get("relationships", []),
            cachi2_sbom.get("relationships", []),
            syft_sbom["packages"],
        )
        packages_in_relationships = []
        for relation in syft_sbom["relationships"]:
            packages_in_relationships.append(relation["spdxElementId"])
            packages_in_relationships.append(relation["relatedSpdxElement"])

        filtered_packages = []
        # Remove packages which don't have any relationships
        for package in syft_sbom["packages"]:
            if package["SPDXID"] in packages_in_relationships:
                filtered_packages.append(package)
        syft_sbom["packages"] = filtered_packages

        _merge_tools_metadata_spdx(syft_sbom, cachi2_sbom)

    return json.dumps(syft_sbom, indent=2)


if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument("cachi2_sbom_path")
    parser.add_argument("syft_sbom_path")
    parser.add_argument("--sbom-format", default="cyclonedx", choices=["cyclonedx", "spdx"])

    args = parser.parse_args()

    merged_sbom = merge_sboms(args.cachi2_sbom_path, args.syft_sbom_path, format=args.sbom_format)

    print(merged_sbom)
