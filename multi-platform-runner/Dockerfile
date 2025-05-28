FROM quay.io/konflux-ci/buildah-task:latest AS buildah-task-image
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6-1747218906
ENV HOME=/root
RUN microdnf install -y rsync openssh-clients buildah podman

RUN curl -LO https://dl.k8s.io/release/v1.27.4/bin/linux/amd64/kubectl && \
    echo "4685bfcf732260f72fce58379e812e091557ef1dfc1bc8084226c7891dd6028f  kubectl" | sha256sum --check && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin

COPY --from=buildah-task-image /usr/bin/retry /usr/bin/
