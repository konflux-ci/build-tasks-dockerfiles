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
- `--inspect-input-file` / `-i`
  - Path to a file containing a json output of `buildah manifest inspect` command
  - File contents MUST be a valid JSON
  - See example in `sample_data/inspect.json`
- `--output-path` / `-o`
  - Path where the SBOM should be written
  - If omitted, SBOM is returned to STDOUT

## Behavior

This script creates an SBOM with externalRefs using both
PURLs from child digest and from index digest with `arch` qualifier.

## Example

To closely replicate the [example image index](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/container_image/build/ubi9-micro-container-9.4-6.1716471860.spdx.json),
you can use the following command:

```bash
python3 index_image_sbom_script.py \
 -u registry.redhat.io/ubi-micro:9.4-6.1716471860 \
 -d sha256:1c8483e0fda0e990175eb9855a5f15e0910d2038dd397d9e2b357630f0321e6d \
 -i sample_data/inspect.json
 ```

To generate a different output, create a json document using `buildah manifest inspect <manifest_pullspec>`
and supply this file as the `-i` argument.
