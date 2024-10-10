import json

class _ANY:
    def __eq__(self, other):
        return True

    def __hash__(self):
        return hash("Any")


ANY = _ANY()


def merge_annotations(annotations1, annotations2):
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
    def map_relationships(relationships):
        relations_map = {}
        relations_inverse_map = {}

        for relation in relationships:
            relations_map.setdefault(relation["spdxElementId"], []).append(relation["relatedSpdxElement"])
            relations_inverse_map[relation["relatedSpdxElement"]] = relation["spdxElementId"]

        for parent_element in relations_map.keys():
            if parent_element not in relations_inverse_map:
                break
        return parent_element, relations_map, relations_inverse_map

    relationships = []

    root_element1, map1, inverse_map1 = map_relationships(relationships1)
    root_element2, map2, inverse_map2 = map_relationships(relationships2)
    package_ids = [package["SPDXID"] for package in packages]
    for r, contains in map2.items():
        if contains and inverse_map2.get(r) == root_element2:
            middle_element2 = r
    for r, contains in map1.items():
        if contains and inverse_map1.get(r) == root_element1:
            middle_element1 = r

    for relation in relationships2:
        _relation = {
            "spdxElementId": relation["spdxElementId"],
            "relatedSpdxElement": relation["relatedSpdxElement"],
            "relationshipType": relation["relationshipType"],
        }
        if _relation["spdxElementId"] == root_element2:
            _relation["spdxElementId"] = root_element1
        elif relation["relatedSpdxElement"] == root_element2:
            _relation["relatedSpdxElement"] = root_element1

        if _relation["relatedSpdxElement"] in package_ids:
            relationships.append(_relation)
        elif _relation["spdxElementId"] in package_ids:
            relationships.append(_relation)

    for relation in relationships1:
        _relation = {
            "spdxElementId": relation["spdxElementId"],
            "relatedSpdxElement": relation["relatedSpdxElement"],
            "relationshipType": relation["relationshipType"],
        }
        if _relation["relatedSpdxElement"] == middle_element1:
            continue
        if _relation["spdxElementId"] == middle_element1:
            _relation["spdxElementId"] = middle_element2
        if relation["relatedSpdxElement"] in package_ids:
            relationships.append(_relation)
    return relationships


def merge_packages(sbom1: dict, sbom2: dict) -> dict:
    """Merge SBOM packages from two SBOMs."""

    package_map1 = {(p["name"], p.get("versionInfo", ANY)): p for p in cachi2_sbom["packages"]}

    packages2 = []
    for p in sbom2.get("packages", []):
        if (p["name"], p.get("versionInfo", ANY)) in list(package_map1.keys()):
            try:
                package1 = package_map1[(p["name"], p.get("versionInfo"))]
            except KeyError:
                package1 = package_map1[(p["name"], ANY)]
            package1["externalRefs"] = sorted(
                merge_external_refs(package1.get("externalRefs", []), p.get("externalRefs", [])),
                key=lambda x: (
                    x["referenceCategory"],
                    x["referenceType"],
                    x["referenceLocator"],
                ),
            )
            package1["annotations"] = merge_annotations(package1.get("annotations", []), p.get("annotations", []))
    else:
        packages2.append(p)

    return packages2 + sbom1['packages']

def merge_metadata(sbom1: dict[Any, Any], sbom2: dict[Any, Any]) -> None:
    """Merge the content of tools in the metadata section of the SBOM.
    """
    creators = sbom2["creationInfo"]["creators"]

    for creator in creators:
        sbom1["creationInfo"]["creators"].append(creator)


# load SBOMs
with open("./sbom-image.json") as f:
    image_sbom = json.load(f)

with open("./sbom-source.json") as f:
    source_sbom = json.load(f)

packages = merge_packages(image_sbom, source_sbom)
relationships = merge_relationships(image_sbom.get("relationships", []),
                                    source_sbom.get("relationships", []),
                                    packages)

packages_in_relationships = []
for relation in relationships:
    packages_in_relationships.append(relation["spdxElementId"])
    packages_in_relationships.append(relation["relatedSpdxElement"])
filtered_packages = []

# Remove packages which don't have any relationships
for package in packages:
    if package["SPDXID"] in packages_in_relationships:
        filtered_packages.append(package)

merge_metadata(image_sbom, source_sbom)
image_sbom["packages"] = filtered_packages
image_sbom["relationships"] = relationships

# write the CycloneDX unified SBOM
with open("./sbom-spdx.json", "w") as f:
    json.dump(image_sbom, f, indent=4)
