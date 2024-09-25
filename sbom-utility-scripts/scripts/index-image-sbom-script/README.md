# SBOM for Image Index

This script builds SPDX2.3 SBOM for image index.

## Usage

**List of arguments:**

- `--image-index-url` / `-u`
  - Must be in the format `repository/image:tag`
  - Example value `quay.io/mkosiarc_rhtap/single-container-app:f2566ab`
- `--image-index-digest` / `-d`
  - Must be in the format `algorithm:hexvalue`
  - Example value `sha256:8f99627e843e931846855c5d899901bf093f5093e613a92745696a26b5420941`
- `--amd64-digest` / `-amd64`
  - Must be in the format `algorithm:hexvalue`
- `--arm64-digest` / `-arm64`
- `--s390x-digest` / `-s390x`
- `--ppc64le-digest` / `-ppc64le`
- `--alt-name` / `-a`
  - Only alternate image names, not the whole url
  - Can be specified multiple times
  - Example usage: `-u registry.redhat.io/ubi-micro:9.4-6.1716471860 -a ubi9-micro -a ubi-m`
  - This data is used for additional PURL creation
- `--output-path` / `-o`
  - Path where the SBOM should be written
  - If omitted, SBOM is returned to STDOUT

## Behavior

This script creates an SBOM with externalRefs using both
PURLs from image index digest with `arch` qualifier
and with child digests. These PURLs are created for the
image digest name and for all its aliases.

## Example

To closely replicate the [example image index](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/container_image/build/ubi9-micro-container-9.4-6.1716471860.spdx.json),
you can use the following command:

```bash
python3 index_image_sbom_script.py \
 -u registry.redhat.io/ubi-micro:9.4-6.1716471860 \
 -d sha256:1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d \
 -a ubi9-micro -ppc64le sha256:f08722139c4da653b870272a192fac700960a3315baa1f79f83a4712a436d4 \
 -s390x sha256:c9e70f4174747c6b53d253e879177c52731cc4bdc5fe9c6a2555412d849a952 \
 -arm64 sha256:c72c705fe4e9de2e065a817be2fbf1b6406010610532243727fdc3042227c71b \
 -amd64 sha256:13fd2a0116a76eaa274fee20c86eef4dfba9f311784e8fb7d7f5fc38b32f3ef
```