#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field
from uuid import uuid4

from packageurl import PackageURL


SUPPORTED_ARCHITECTURES = ["amd64", "arm64", "s390x", "ppc64le"]


@dataclass
class Image:
    repository: str
    name: str
    digest: str
    tag: str
    arch: Optional[str]
    alternate_purl_names: list[str] = field(default_factory=list)

    @staticmethod
    def from_image_index_url_and_digest(
        image_url_and_tag: str,
        image_digest: str,
        alternate_purl_names: Optional[list[str]] = None,
    ) -> "Image":
        alternate_purl_names = alternate_purl_names or []

        repository, tag = image_url_and_tag.rsplit(":", 1)
        _, name = repository.rsplit("/", 1)
        return Image(
            repository=repository,
            name=name,
            digest=image_digest,
            tag=tag,
            alternate_purl_names=alternate_purl_names,
            arch=None,
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
        names = {self.name}
        if self.alternate_purl_names:
            names.update(self.alternate_purl_names)
        ans = []
        names = sorted(names)
        for name in names:
            if index_digest:
                ans.append(
                    PackageURL(
                        type="oci",
                        name=name,
                        version=index_digest,
                        qualifiers={"arch": self.arch, "repository_url": self.repository},
                    ).to_string()
                )
            ans.append(
                PackageURL(
                    type="oci", name=name, version=self.digest, qualifiers={"repository_url": self.repository}
                ).to_string()
            )
        return ans

    def propose_spdx_id(self) -> str:
        return f"SPDXRef-{self.digest_hex_val}"


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
    arch_digests: dict[str, str],
    alternative_names: Optional[list[str]] = None,
) -> dict:
    alternative_names = alternative_names or []
    image_index_obj = Image.from_image_index_url_and_digest(image_index_url, image_index_digest, alternative_names)
    sbom_name = f"{image_index_obj.name}-{image_index_obj.tag}"

    packages = [create_package(image_index_obj, "SPDXRef-image-index")]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-image-index",
        }
    ]

    for arch, digest in arch_digests.items():
        arch_image = Image(
            image_index_obj.repository,
            image_index_obj.name,
            digest,
            image_index_obj.tag,
            arch,
            alternative_names,
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
    for arch in SUPPORTED_ARCHITECTURES:
        parser.add_argument(
            f"--{arch}-digest",
            f"-{arch}",
            type=str,
            help=f"Digest of the {arch} image.",
        )
    parser.add_argument(
        "--alt-name",
        "-a",
        type=str,
        help="Alternative name of the image, used in PURLs. "
        "Include only the image name, not the whole URL. "
        "Can be specified multiple times",
        action="append",
    )
    parser.add_argument(
        "--output-path",
        "-o",
        type=str,
        help="Path to save the output SBOM in JSON format.",
    )
    args = parser.parse_args()
    arch_digests = {arch: getattr(args, f"{arch}_digest") for arch in SUPPORTED_ARCHITECTURES}
    arch_digests = {key: value for key, value in arch_digests.items() if value}

    sbom = create_sbom(args.image_index_url, args.image_index_digest, arch_digests, args.alt_name)
    if args.output_path:
        with open(args.output_path, "w") as fp:
            json.dump(sbom, fp)
    else:
        print(json.dumps(sbom, indent=4))


if __name__ == "__main__":
    main()
