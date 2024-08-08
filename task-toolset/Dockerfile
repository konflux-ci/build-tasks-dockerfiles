# https://catalog.redhat.com/software/containers/ubi9/ubi-minimal/615bd9b4075b022acc111bf5
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4-1194
RUN microdnf install -y git jq && \
    microdnf clean all && rm -rf /var/cache/dnf/*
