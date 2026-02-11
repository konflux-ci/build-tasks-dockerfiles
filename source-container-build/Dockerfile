FROM quay.io/konflux-ci/task-runner:1.3.0

ARG BSI_VERSION=0.2.0
ARG bsi_source=https://github.com/containers/BuildSourceImage/archive/refs/tags/v${BSI_VERSION}.tar.gz
ARG patch0=0001-cleanup-directory-with-all-rpms-which-isn-t-used-any.patch
ARG patch1=0001-Increase-counter-as-numeric-rather-than-string.patch
ARG patch2=0001-Use-extra-src-archive-checksum-in-filename.patch
ARG patch3=0001-Set-mediaType-on-image-manifest.patch

USER 0

# We still need to install 'file' and 'dnf' packages, becasue the BSI script expects them.
# These packages are specific for the source-container-build, so we don't want to include them in the base image.
# After the BSI is implemented in Go, we won't need the source-container-build.
# hadolint ignore=DL3041
RUN microdnf update -y && microdnf install -y file dnf && microdnf clean all

# Create the directories as root, then give ownership to user 1000.
# We use group 0 because the base image uses 'useradd -g 0 ...'
RUN mkdir -p /opt/BuildSourceImage /opt/source_build && \
    chown -R 1000:0 /opt/BuildSourceImage /opt/source_build && \
    chmod -R g+rwX /opt/BuildSourceImage /opt/source_build

USER 1000
WORKDIR /opt/BuildSourceImage

COPY --chown=1000:0 $patch0 $patch1 $patch2 $patch3 ./
RUN cp /cachi2/output/deps/generic/BuildSourceImage-${BSI_VERSION}.tar.gz . && \
    tar --extract -f BuildSourceImage-${BSI_VERSION}.tar.gz -z --strip-components=1 BuildSourceImage-${BSI_VERSION}/BuildSourceImage.sh && \
    git apply --allow-empty BuildSourceImage.sh $patch0 $patch1 $patch2 $patch3 && \
    rm -r $patch0 $patch1 $patch2 $patch3 && \
    mv BuildSourceImage.sh bsi

WORKDIR /opt/source_build/
COPY --chown=1000:0 app/source_build.py app/requirements.txt ./
RUN python3.12 -m venv appenv && \
    ./appenv/bin/python3 -m pip install --no-cache-dir -r ./requirements.txt
