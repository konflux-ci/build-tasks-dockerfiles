#!/bin/bash
set -o errexit -o nounset -o pipefail

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

: "${TEST_SBOM_FORMAT?must set variable; valid values: cyclonedx, spdx}"
: "${TEST_IMAGE=icm-inject-test:latest}"

banner() {
    echo "--------------------------------------------------------------------------------"
    echo "$1"
    echo "--------------------------------------------------------------------------------"
}

cleanup() {
    rm -r "$WORKDIR" || true
    buildah rm "$test_container" >/dev/null || true
    buildah rmi "$TEST_IMAGE" >/dev/null || true
}
trap cleanup EXIT

WORKDIR=$(mktemp -d --suffix=-icm-inject-test)

banner "Creating test image: $TEST_IMAGE"
test_container=$(buildah from registry.fedoraproject.org/fedora-minimal:41)
buildah commit "$test_container" "$TEST_IMAGE"

cd "$WORKDIR"

banner "Running inject-icm.sh with a $TEST_SBOM_FORMAT SBOM"
cp "$SCRIPTDIR/test-data/sbom-cachi2-$TEST_SBOM_FORMAT.json" ./sbom-cachi2.json
bash "$SCRIPTDIR/inject-icm.sh" "$TEST_IMAGE"

expect_icm=$(jq -n '{
  "metadata": {
    "icm_version": 1,
    "icm_spec": "https://raw.githubusercontent.com/containerbuildsystem/atomic-reactor/master/atomic_reactor/schemas/content_manifest.json",
    "image_layer_index": 0
  },
  "from_dnf_hint": true,
  "content_sets": [
    "releases",
    "ubi-8-appstream-rpms",
    "ubi-8-appstream-source"
  ]
}')

banner "Checking the content of /usr/share/buildinfo/content-sets.json in $TEST_IMAGE"

got_icm=$(podman run --rm "$TEST_IMAGE" cat /usr/share/buildinfo/content-sets.json | jq)

if [[ "$expect_icm" != "$got_icm" ]]; then
    printf "%s\n" \
        "❌ Mismatched ICM files!" \
        "------------------------" \
        "Expected:" \
        "$expect_icm" \
        "------------------------" \
        "Got:" \
        "$got_icm"
    exit 1
else
    echo "✅ Success!"
fi
