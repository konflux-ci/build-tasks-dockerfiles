#!/usr/bin/env python3
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass
from uuid import uuid4

from packageurl import PackageURL


@dataclass
class Image:
    repository: str
    name: str
    digest: str
    tag: str
    arch: Optional[str]

    @staticmethod
    def from_image_index_url_and_digest(
        image_url_and_tag: str,
        image_digest: str,
        arch: Optional[str] = None,
    ) -> "Image":

        repository, tag = image_url_and_tag.rsplit(":", 1)
        _, name = repository.rsplit("/", 1)
        return Image(
            repository=repository,
            name=name,
            digest=image_digest,
            tag=tag,
            arch=arch,
        )

    @property
    def digest_algo(self) -> str:
        algo, _ = self.digest.split(":")
        return algo.upper()

    @property
    def digest_hex_val(self) -> str:
        _, val = self.digest.split(":")
        return val

    def purls(self, index_digest: Optional[str] = None) -> list[str]:
        ans = []
        if index_digest and self.arch:
            ans.append(
                PackageURL(
                    type="oci",
                    name=self.name,
                    version=index_digest,
                    qualifiers={"arch": self.arch, "repository_url": self.repository},
                ).to_string()
            )
        ans.append(
            PackageURL(
                type="oci", name=self.name, version=self.digest, qualifiers={"repository_url": self.repository}
            ).to_string()
        )
        return ans

    def propose_spdx_id(self) -> str:
        purl_hex_digest = hashlib.sha256(self.purls()[0].encode()).hexdigest()
        return f"SPDXRef-Image-{self.name}-{purl_hex_digest}"


def create_package(image: Image, spdxid: Optional[str] = None, image_index_digest: Optional[str] = None) -> dict:
    return {
        "SPDXID": image.propose_spdx_id() if not spdxid else spdxid,
        "name": image.name if not image.arch else f"{image.name}_{image.arch}",
        "versionInfo": image.tag,
        "supplier": "Organization: Red Hat",
        "downloadLocation": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
            for purl in image.purls(image_index_digest)
        ],
        "checksums": [
            {
                "algorithm": image.digest_algo,
                "checksumValue": image.digest_hex_val,
            }
        ],
    }


def get_relationship(spdxid: str, related_spdxid: str):
    return {
        "spdxElementId": spdxid,
        "relationshipType": "VARIANT_OF",
        "relatedSpdxElement": related_spdxid,
    }


def create_sbom(
    image_index_url: str,
    image_index_digest: str,
    inspect_input: dict[str, Any],
) -> dict:
    if inspect_input["mediaType"] != "application/vnd.oci.image.index.v1+json":
        raise ValueError("Invalid input file detected, requires `buildah manifest inspect` json.")

    image_index_obj = Image.from_image_index_url_and_digest(image_index_url, image_index_digest)
    sbom_name = f"{image_index_obj.name}-{image_index_obj.tag}"

    packages = [create_package(image_index_obj, "SPDXRef-image-index")]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-image-index",
        }
    ]

    for manifest in inspect_input["manifests"]:
        if manifest["mediaType"] != "application/vnd.oci.image.manifest.v1+json":
            continue

        arch_image = Image(
            arch=manifest.get("platform", {}).get("architecture"),
            name=image_index_obj.name,
            digest=manifest.get("digest"),
            tag=image_index_obj.tag,
            repository=image_index_obj.repository,
        )
        packages.append(create_package(arch_image, image_index_digest=image_index_obj.digest))
        relationships.append(get_relationship(arch_image.propose_spdx_id(), "SPDXRef-image-index"))

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://redhat.com/spdxdocs/{sbom_name}-{uuid4()}",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "creators": ["Tool: Konflux"],
            "licenseListVersion": "3.25",
        },
        "name": sbom_name,
        "packages": packages,
        "relationships": relationships,
    }
    return sbom


def main():
    parser = argparse.ArgumentParser(description="Create an image index SBOM.")
    parser.add_argument(
        "--image-index-url",
        "-u",
        type=str,
        help="Image index URL in the format 'repository/image:tag'.",
        required=True,
    )
    parser.add_argument(
        "--image-index-digest",
        "-d",
        type=str,
        help="Image index digest in the format 'algorithm:digest'.",
        required=True,
    )
    parser.add_argument(
        "--inspect-input-file",
        "-i",
        type=Path,
        help="Inspect json file produced by image index inspection.",
        required=True,
    )
    parser.add_argument(
        "--output-path",
        "-o",
        type=str,
        help="Path to save the output SBOM in JSON format.",
    )
    args = parser.parse_args()
    with open(args.inspect_input_file, "r") as inp_file:
        inspect_input = json.load(inp_file)

    sbom = create_sbom(args.image_index_url, args.image_index_digest, inspect_input)
    if args.output_path:
        with open(args.output_path, "w") as fp:
            json.dump(sbom, fp, indent=4)
    else:
        print(json.dumps(sbom, indent=4))


if __name__ == "__main__":
    main()
