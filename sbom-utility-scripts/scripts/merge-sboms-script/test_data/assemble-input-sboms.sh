#!/bin/bash
set -o errexit -o nounset -o pipefail -o xtrace

# This script was used to generate the input SBOMs in this directory:
# - cyclonedx/**
# - spdx/**
#
# Hopefully you won't need to run this script again, but if you do, you need:
# - hermeto (https://github.com/containerbuildsystem/hermeto/blob/main/CONTRIBUTING.md#virtual-environment)
# - syft (https://github.com/anchore/syft/releases)
#   - preferably at the version used by the tasks in https://github.com/konflux-ci/build-definitions
#
# It will generate hermeto and syft SBOMs for a few sample repositories (and one
# container image, for syft) and assemble them into a merged hermeto SBOM and a
# merged syft SBOM. You can then test the merge_sboms.py script by merging
# the hermeto SBOM with the syft SBOM.

sbom_type=${1:-cyclonedx}

case $sbom_type in
    cyclonedx)
        syft_sbom_type=cyclonedx-json@1.5
        ;;
    spdx)
        syft_sbom_type=spdx-json@2.3
        ;;
    *)
        echo "unknown SBOM type: $sbom_type" >&2
        exit 1
        ;;
esac

testdata_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

# This can't actually be in /tmp! Until v1.6.0, syft had a bug where directory scanning
# didn't work at all if the directory was in /tmp
temp_workdir=$PWD/assemble-sboms-$sbom_type
mkdir -p "$temp_workdir"
trap 'rm -rf "$temp_workdir"' EXIT

cd "$temp_workdir"
mkdir hermeto-sboms
mkdir syft-sboms

git clone https://github.com/cachito-testing/gomod-pandemonium
(
    cd gomod-pandemonium

    syft dir:. -o "$syft_sbom_type" > "$temp_workdir/syft-sboms/gomod-pandemonium.bom.json"

    hermeto fetch-deps --sbom-output-type "$sbom_type" '[
        {"type": "gomod"},
        {"type": "gomod", "path": "terminaltor"},
        {"type": "gomod", "path": "weird"}
    ]'
    cp hermeto-output/bom.json "../hermeto-sboms/gomod-pandemonium.bom.json"
)

git clone https://github.com/cachito-testing/pip-e2e-test
(
    cd pip-e2e-test

    syft dir:. -o "$syft_sbom_type" > "$temp_workdir/syft-sboms/pip-e2e-test.bom.json"

    hermeto fetch-deps --sbom-output-type "$sbom_type" pip
    cp hermeto-output/bom.json "$temp_workdir/hermeto-sboms/pip-e2e-test.bom.json"
)

git clone https://github.com/cachito-testing/npm-cachi2-smoketest --branch lockfile-v3
(
    cd npm-cachi2-smoketest

    syft dir:. -o "$syft_sbom_type" > "$temp_workdir/syft-sboms/npm-cachi2-smoketest.bom.json"

    hermeto fetch-deps --sbom-output-type "$sbom_type" npm
    cp hermeto-output/bom.json "$temp_workdir/hermeto-sboms/npm-cachi2-smoketest.bom.json"
)

ubi_micro=registry.access.redhat.com/ubi9/ubi-micro:9.5@sha256:a22fffe0256af00176c8b4f22eec5d8ecb1cb1684d811c33b1f2832fd573260f
syft image:"$ubi_micro" -o "$syft_sbom_type" > "$temp_workdir/syft-sboms/ubi-micro.bom.json"

# postprocess_*: Some attributes change every time, e.g. timestamps or UUIDs.
# Set them to hardcoded values to avoid unnecessary changes when re-running this script.

postprocess_hermeto_cyclonedx() {
    jq --sort-keys
}

postprocess_hermeto_spdx() {
    jq --sort-keys '
        .creationInfo.created = "2024-12-18T11:27:10Z" |
        .packages[].annotations[].annotationDate = "2024-12-18T11:27:10Z" |
        (.relationships |= sort)
    '
    # TODO remove the relationships sorting if hermeto fixes the random order
}

postprocess_syft_cyclonedx() {
    jq --sort-keys '
        .metadata.timestamp = "2024-12-18T11:08:00+01:00" |
        .serialNumber = "urn:uuid:1d823647-6b64-41b3-a29b-1d09cfb3ba8a"
    '
}

postprocess_syft_spdx() {
    jq --sort-keys '
        .creationInfo.created = "2024-12-18T11:28:00Z" |
        .documentNamespace = "https://anchore.com/syft/dir/syft-sboms-b66779b6-6e20-4128-9fad-da28250a1b82"
    '
}

mkdir -p "$testdata_dir/$sbom_type"

hermeto merge-sboms --sbom-output-type "$sbom_type" "$temp_workdir/hermeto-sboms"/* |
    postprocess_hermeto_"$sbom_type" > "$testdata_dir/$sbom_type/hermeto.bom.json"

mkdir -p "$testdata_dir/$sbom_type/syft-sboms"
for syft_sbom in ./syft-sboms/*; do
    name=$(basename "$syft_sbom")
    postprocess_syft_"$sbom_type" < "$syft_sbom" > "$testdata_dir/$sbom_type/syft-sboms/$name"
done

syft ./syft-sboms --select-catalogers=+sbom-cataloger -o "$syft_sbom_type" |
    postprocess_syft_"$sbom_type" > "$testdata_dir/$sbom_type/syft.merged-by-syft.bom.json"

printf "syft:%s\n" "$testdata_dir/$sbom_type/syft-sboms"/* |
    xargs python "$testdata_dir/../merge_sboms.py" > "$testdata_dir/$sbom_type/syft.merged-by-us.bom.json"
