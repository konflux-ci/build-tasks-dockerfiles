#!/bin/bash
set -o errexit -o nounset -o pipefail -o xtrace

# This script was used to generate the input SBOMs in this directory:
# - cachi2.bom.json
# - syft.bom.json
#
# Hopefully you won't need to run this script again, but if you do, you need:
# - cachi2 (https://github.com/containerbuildsystem/cachi2/blob/main/CONTRIBUTING.md#virtual-environment)
# - syft (https://github.com/anchore/syft/releases)
#   - preferably at the version used by the tasks in https://github.com/konflux-ci/build-definitions
#
# It will generate cachi2 and syft SBOMs for a few sample repositories (and one
# container image, for syft) and assemble them into a merged cachi2 SBOM and a
# merged syft SBOM. You can then test the merge_sboms.py script by merging
# the cachi2 SBOM with the syft SBOM.

testdata_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

# This can't actually be in /tmp! Until v1.6.0, syft had a bug where directory scanning
# didn't work at all if the directory was in /tmp
temp_workdir=$(realpath ./assemble-sboms)
mkdir -p "$temp_workdir"
trap 'rm -rf "$temp_workdir"' EXIT

cd "$temp_workdir"
mkdir cachi2-sboms
mkdir syft-sboms

git clone https://github.com/cachito-testing/gomod-pandemonium
(
    cd gomod-pandemonium

    syft dir:. -o cyclonedx-json@1.5 > "$temp_workdir/syft-sboms/gomod-pandemonium.bom.json"

    cachi2 fetch-deps '[
        {"type": "gomod"},
        {"type": "gomod", "path": "terminaltor"},
        {"type": "gomod", "path": "weird"}
    ]'
    cp cachi2-output/bom.json "../cachi2-sboms/gomod-pandemonium.bom.json"
)

git clone https://github.com/cachito-testing/pip-e2e-test
(
    cd pip-e2e-test

    syft dir:. -o cyclonedx-json@1.5 > "$temp_workdir/syft-sboms/pip-e2e-test.bom.json"

    cachi2 fetch-deps pip
    cp cachi2-output/bom.json "$temp_workdir/cachi2-sboms/pip-e2e-test.bom.json"
)

git clone https://github.com/cachito-testing/npm-cachi2-smoketest --branch lockfile-v3
(
    cd npm-cachi2-smoketest

    syft dir:. -o cyclonedx-json@1.5 > "$temp_workdir/syft-sboms/npm-cachi2-smoketest.bom.json"

    cachi2 fetch-deps npm
    cp cachi2-output/bom.json "$temp_workdir/cachi2-sboms/npm-cachi2-smoketest.bom.json"
)

ubi_micro=registry.access.redhat.com/ubi9/ubi-micro:9.5@sha256:a22fffe0256af00176c8b4f22eec5d8ecb1cb1684d811c33b1f2832fd573260f
syft image:"$ubi_micro" -o cyclonedx-json@1.5 > "$temp_workdir/syft-sboms/ubi-micro.bom.json"

postprocess_cachi2_cyclonedx() {
    jq --sort-keys
}

postprocess_syft_cyclonedx() {
    # These change every time. Set them to a hardcoded value to avoid unnecessary changes
    # when re-running this script.
    jq --sort-keys '
        .metadata.timestamp = "2024-12-18T11:08:00+01:00" |
        .serialNumber = "urn:uuid:1d823647-6b64-41b3-a29b-1d09cfb3ba8a"
    '
}

cachi2 merge-sboms "$temp_workdir/cachi2-sboms"/* |
    postprocess_cachi2_cyclonedx > "$testdata_dir/cachi2.bom.json"

mkdir -p "$testdata_dir/syft-sboms"
for syft_sbom in ./syft-sboms/*; do
    name=$(basename "$syft_sbom")
    postprocess_syft_cyclonedx < "$syft_sbom" > "$testdata_dir/syft-sboms/$name"
done

syft ./syft-sboms --select-catalogers=+sbom-cataloger -o cyclonedx-json@1.5 |
    postprocess_syft_cyclonedx > "$testdata_dir/syft.merged-by-syft.bom.json"

printf "syft:%s\n" "$testdata_dir/syft-sboms"/* |
    xargs python "$testdata_dir/../merge_sboms.py" > "$testdata_dir/syft.merged-by-us.bom.json"
