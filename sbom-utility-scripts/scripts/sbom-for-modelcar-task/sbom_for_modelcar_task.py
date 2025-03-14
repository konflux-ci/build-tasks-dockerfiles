"""



The script requires 2 references, the Model OCI artifact where the model files will be extracted from, and the Base Image for the ModelCar image.

The SBOM report has the following structure:

- There are 3 components reported in the SBOM, the Modelcar image, and the Base and Model images
- The Modelcar component is a DESCENDANT OF both the Model and the Base images

usage: sbom_for_modelcar_task.py [-h] --modelcar-image MODELCAR_IMAGE --base-image BASE_IMAGE --model-image MODEL_IMAGE [-o OUTPUT_FILE] [--sbom-type {cyclonedx,spdx}]

options:
  -h, --help            show this help message and exit
  --modelcar-image MODELCAR_IMAGE    Modelcar OCI artifact reference resolved to digest (e.g., quay.io/foo/modelcar_image@sha256:abcdef1234567890...
  --base-image BASE_IMAGE            Base image OCI artifact reference resolved to digest (e.g., quay.io/foo/base_image@sha256:abcdef1234567890...
  --model-image MODEL_IMAGE          Model OCI artifact reference resolved to digest (e.g., quay.io/foo/model_image@sha256:abcdef1234567890...
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
  --sbom-type {cyclonedx,spdx}
"""

import argparse
import datetime
import json
import re
import uuid
from typing import IO, Any, Literal


from packageurl import PackageURL

from dataclasses import dataclass


@dataclass
class OCIArtifact:
    repository: str
    domain: str
    name: str
    digest: str
    digest_alg: str
    digest_hash: str
    tag: str

    # Regular expression to validate OCI image references with digest (credit to https://regex101.com/r/nmSDPA/1)
    ARTIFACT_PATTERN = r"""
    ^
    (?P<repository>
      (?:(?P<domain>(?:(?:[\w-]+(?:\.[\w-]+)+)(?::\d+)?)|[\w]+:\d+)/)
      (?P<name>[a-z0-9_.-]+(?:/[a-z0-9_.-]+)*)
    )
    (?::(?P<tag>[\w][\w.-]{0,127}))?
    (?:@(?P<digest>
      (?P<digest_alg>[A-Za-z][A-Za-z0-9]*)(?:[+.-_][A-Za-z][A-Za-z0-9]*)*:
      (?P<digest_hash>[0-9a-fA-F]{32,})))
    $
    """

    @staticmethod
    def from_oci_artifact_reference(
        oci_reference: str,
    ) -> "OCIArtifact":
        """
        Create an instance of the Image class from the image URL and digest.

        Args:
            oci_reference (str): The OCI artifact reference.

        Returns:
            OCI_Artifact: An instance of the Image class representing the artifact reference
        """

        pattern = re.compile(OCIArtifact.ARTIFACT_PATTERN, re.VERBOSE | re.MULTILINE)
        match = pattern.match(oci_reference)
        if not match:
            raise ValueError(f"Invalid OCI artifact reference format: {oci_reference}")

        return OCIArtifact(
            repository=match.group("repository"),
            name=match.group("name"),
            domain=match.group("domain"),
            digest=match.group("digest"),
            tag=match.group("tag"),
            digest_alg=match.group("digest_alg"),
            digest_hash=match.group("digest_hash"),
        )

    def purl(self) -> str:
        """
        Get the Package URL (PURL) for the image.

        Returns:
            str: A string representing the PURL for the image.
        """
        return PackageURL(
            type="oci",
            name=self.name,
            version=self.digest_hash,
            qualifiers={"repository_url": self.repository},
        ).to_string()

    def digest_alg_formatted(self, format: Literal["spdx", "cyclonedx"]) -> str:
        if format == "cyclonedx":
            return self._digest_alg_cyclonedx()
        elif format == "spdx":
            return self._digest_alg_spdx()

    def _digest_alg_cyclonedx(self) -> str:
        algorithm_mapping = {"sha256": "SHA-256", "sha512": "SHA-512"}
        return algorithm_mapping.get(self.digest_alg, self.digest_alg.upper())

    def _digest_alg_spdx(self) -> str:
        return self.digest_alg.upper()


def get_cyclonedx_component_from_ociartifact(artifact: OCIArtifact) -> dict[str, Any]:

    return {
        "type": "container",
        "name": artifact.name,
        "purl": artifact.purl(),
        "version": artifact.tag,
        "hashes": [{"alg": artifact.digest_alg_formatted("cyclonedx"), "content": artifact.digest_hash}],
    }


def get_spdx_package_from_ociartifact(artifact: OCIArtifact) -> dict[str, Any]:

    return {
        "SPDXID": f"SPDXRef-image-{artifact.repository}-{artifact.digest_hash}",
        "name": artifact.name,
        "versionInfo": artifact.tag,
        "downloadLocation": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "supplier": "NOASSERTION",
        "externalRefs": [
            {
                "referenceLocator": artifact.purl(),
                "referenceType": "purl",
                "referenceCategory": "PACKAGE-MANAGER",
            }
        ],
        "checksums": [{"algorithm": artifact.digest_alg_formatted("spdx"), "checksumValue": artifact.digest_hash}],
    }


def _to_cyclonedx_sbom(modelcar: OCIArtifact, base: OCIArtifact, model: OCIArtifact) -> dict[str, Any]:

    modelcar_component = get_cyclonedx_component_from_ociartifact(modelcar)
    modelcar_component["components"] = list(map(get_cyclonedx_component_from_ociartifact, [base, model]))
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": get_cyclonedx_component_from_ociartifact(modelcar)},
        "components": [modelcar_component],
    }


def _datetime_utc_now() -> datetime.datetime:
    # a mockable datetime.datetime.now
    return datetime.datetime.now(datetime.UTC)


def _to_spdx_sbom(
    modelcar_artifact: OCIArtifact, base_artifact: OCIArtifact, model_artifact: OCIArtifact
) -> dict[str, Any]:

    def get_descendant_relationship(spdxid: str, related_spdxid: str) -> dict[str, Any]:
        return {
            "spdxElementId": spdxid,
            "relationshipType": "DESCENDANT_OF",
            "relatedSpdxElement": related_spdxid,
        }

    modelcar_package = get_spdx_package_from_ociartifact(modelcar_artifact)
    base_package = get_spdx_package_from_ociartifact(base_artifact)
    model_package = get_spdx_package_from_ociartifact(model_artifact)

    packages = [modelcar_package, base_package, model_package]

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": modelcar_package["SPDXID"],
        },
        get_descendant_relationship(modelcar_package["SPDXID"], base_package["SPDXID"]),
        get_descendant_relationship(modelcar_package["SPDXID"], model_package["SPDXID"]),
    ]

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://konflux-ci.dev/spdxdocs/sbom-for-oci-copy-task/{uuid.uuid4()}",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": _datetime_utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: Konflux"],
        },
        "name": "sbom-for-modelcar-task",
        "packages": packages,
        "relationships": relationships,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.description = "This script provides a helper function to generate an SBOM reports for ModelCar images."
    ap.epilog = """
        A ModelCar is a containerized approach to deploying machine learning models. It involves packaging
        model artifacts within a container image, enabling efficient and standardized deployment in
        Kubernetes environments, used as Sidecar containers (secondary containers that run alongside the
        main application container within the same Pod)
    """
    ap.add_argument(
        "--modelcar-image",
        type=str,
        help="Modelcar OCI artifact reference resolved to digest (e.g., quay.io/foo/modelcar_image@sha256:abcdef1234567890...",
        required=True,
    )
    ap.add_argument(
        "--base-image",
        type=str,
        help="Base image OCI artifact reference resolved to digest (e.g., quay.io/foo/base_image@sha256:abcdef1234567890...",
        required=True,
    )
    ap.add_argument(
        "--model-image",
        type=str,
        help="Model OCI artifact reference resolved to digest (e.g., quay.io/foo/model_image@sha256:abcdef1234567890...",
        required=True,
    )
    ap.add_argument("-o", "--output-file", type=argparse.FileType(mode="w"), default="-")
    ap.add_argument("--sbom-type", choices=["cyclonedx", "spdx"], default="cyclonedx")
    args = ap.parse_args()

    try:
        modelcar = OCIArtifact.from_oci_artifact_reference(args.modelcar_image)
        base: OCIArtifact = OCIArtifact.from_oci_artifact_reference(args.base_image)
        model: OCIArtifact = OCIArtifact.from_oci_artifact_reference(args.model_image)
    except ValueError as e:
        print(f"Error validating OCI artifact reference: {e}")
        raise

    output_file: IO[str] = args.output_file
    sbom_type: str = args.sbom_type

    sbom = to_sbom(base, model, modelcar, sbom_type)

    json.dump(sbom, output_file, indent=2)
    output_file.write("\n")


def to_sbom(base, model, modelcar, sbom_type):
    if sbom_type == "cyclonedx":
        sbom = _to_cyclonedx_sbom(modelcar, base, model)
    else:
        sbom = _to_spdx_sbom(modelcar, base, model)
    return sbom


if __name__ == "__main__":
    main()
