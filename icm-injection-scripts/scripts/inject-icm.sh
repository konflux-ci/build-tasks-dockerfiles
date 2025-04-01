#!/bin/bash
# Inject an ICM (image content manifest) file with content sets for backwards compatibility
#
# https://github.com/containerbuildsystem/atomic-reactor/blob/master/atomic_reactor/schemas/content_manifest.json
#
# This is not a file we want to inject always into the future, but older Red
# Hat build systems injected a file like this and some third-party scanners
# depend on it in order to map rpms found in each layer to CPE ids, to match
# them with vulnerability data. In the future, those scanners should port to
# using the dnf db and/or SBOMs to make that same match. Consider this
# deprecated.
#
# This is only possible for images built hermetically with prefetch

set -euo pipefail

IMAGE="${1}"
MOUNT_PATH="${2}"
SQUASH="${SQUASH:-false}"

icm_filename="content-sets.json"
# Note this used to be /root/buildinfo/content_manifests but is now /usr/share/buildinfo for compatibility
# with bootc/ostree systems. Ref https://issues.redhat.com/browse/KONFLUX-6844
location="/usr/share/buildinfo/${icm_filename}"

if [ ! -f "./sbom-cachi2.json" ]; then
  echo "Could not find sbom-cachi2.json. No content_sets found for ICM"
  exit 0
fi

echo "Extracting annotations to copy to the modified image"
base_image_name=$(buildah inspect --format '{{ index .ImageAnnotations "org.opencontainers.image.base.name"}}' "$IMAGE" | cut -f1 -d'@')
base_image_digest=$(buildah inspect --format '{{ index .ImageAnnotations "org.opencontainers.image.base.digest"}}' "$IMAGE")

echo "Creating container from $IMAGE"
CONTAINER=$(buildah from --pull-never $IMAGE)
trap 'buildah rm "$CONTAINER"' EXIT

echo "Preparing construction of $location for container $CONTAINER to be committed back as $IMAGE (squash: $SQUASH)"
cat >content-sets.json <<EOF
{
    "metadata": {
	"icm_version": 1,
	"icm_spec": "https://raw.githubusercontent.com/containerbuildsystem/atomic-reactor/master/atomic_reactor/schemas/content_manifest.json",
	"image_layer_index": 0
    },
    "from_dnf_hint": true,
    "content_sets": []
}

EOF

while IFS='' read -r content_set;
do
  if [ "${content_set}" != "" ]; then
    jq --arg content_set "$content_set" '.content_sets += [$content_set]' content-sets.json > content-sets.json.tmp
    mv content-sets.json.tmp content-sets.json
  fi
done <<< "$(
    jq -r '
        if .bomFormat == "CycloneDX" then
            .components[].purl
        else
            .packages[].externalRefs[]? | select(.referenceType == "purl") | .referenceLocator
        end' sbom-cachi2.json |
    grep -o -P '(?<=repository_id=).*(?=(&|$))' |
    sort -u
)"

echo "Constructed the following:"
cat content-sets.json

echo "Checking to see if the content-sets.json file exists in ${location}"
status=0
diff -EZbB "${MOUNT_PATH}/${location}" content-sets.json || status=$?
if [ "$status" -eq 0 ]; then
  echo "content-sets.json already exists in container and it matches. Skipping injection."
  exit 0
fi

echo "No matching content-sets.json found at $location. Adding file into the image."
buildah copy "$CONTAINER" content-sets.json /usr/share/buildinfo/
buildah config -a "org.opencontainers.image.base.name=${base_image_name}" -a "org.opencontainers.image.base.digest=${base_image_digest}" "$CONTAINER"

BUILDAH_ARGS=()
if [ "${SQUASH}" == "true" ]; then
  BUILDAH_ARGS+=("--squash")
fi

echo "Committing that back to $IMAGE"
buildah commit "${BUILDAH_ARGS[@]}" "$CONTAINER" "$IMAGE"
