import argparse
import json
import datetime
import uuid
from typing import IO, Any


def empty_cyclonedx_sbom() -> dict[str, Any]:

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {},
        "components": [],
    }


def empty_spdx_sbom() -> dict[str, Any]:

    # The only purpose of this package is to be the "root" of the relationships graph
    fake_root = {
        "SPDXID": "SPDXRef-DocumentRoot-Unknown",
        "downloadLocation": "NOASSERTION",
        "name": "",
    }

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": fake_root["SPDXID"],
        }
    ]
    packages = [fake_root]

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://konflux-ci.dev/spdxdocs/sbom-for-oci-copy-task/{uuid.uuid4()}",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": _datetime_utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: Konflux"],
        },
        "name": "sbom-for-oci-copy-task",
        "packages": packages,
        "relationships": relationships,
    }


def _datetime_utc_now() -> datetime.datetime:
    # a mockable datetime.datetime.now
    return datetime.datetime.now(datetime.UTC)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output-file", type=argparse.FileType(mode="w"), default="-")
    ap.add_argument("-t", "--sbom-type", choices=["cyclonedx", "spdx"], default="cyclonedx")
    args = ap.parse_args()

    output_file: IO[str] = args.output_file
    sbom_type: str = args.sbom_type

    if sbom_type == "cyclonedx":
        sbom = empty_cyclonedx_sbom()
    else:
        sbom = empty_spdx_sbom()

    json.dump(sbom, output_file, indent=2)
    output_file.write("\n")


if __name__ == "__main__":
    main()
