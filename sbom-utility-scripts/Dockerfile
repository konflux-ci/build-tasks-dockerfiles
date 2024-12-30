FROM registry.access.redhat.com/ubi9/python-312:9.5-1734610689@sha256:1d8846b7c6558a50b434f1ea76131f200dcdd92cfaf16b81996003b14657b491

WORKDIR /scripts

COPY scripts/merge_syft_sboms.py /scripts
COPY scripts/merge-cachi2-sboms-script/merge_cachi2_sboms.py /scripts
COPY scripts/merge-cachi2-sboms-script/requirements.txt /scripts/merge-cachi2-sboms-script-requirements.txt
COPY scripts/base-images-sbom-script/app/base_images_sbom_script.py /scripts
COPY scripts/base-images-sbom-script/app/requirements.txt /scripts/base-images-sbom-script-requirements.txt
COPY scripts/index-image-sbom-script/requirements.txt /scripts/index-image-sbom-script-requirements.txt
COPY scripts/index-image-sbom-script/index_image_sbom_script.py /scripts

COPY scripts/add-image-reference-script/add_image_reference.py /scripts
COPY scripts/add-image-reference-script/requirements.txt /scripts/add-image-reference-requirements.txt

RUN pip3 install --no-cache-dir \
    -r merge-cachi2-sboms-script-requirements.txt \
    -r base-images-sbom-script-requirements.txt \
    -r index-image-sbom-script-requirements.txt \
    -r add-image-reference-requirements.txt
