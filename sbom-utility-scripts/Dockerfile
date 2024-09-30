FROM registry.access.redhat.com/ubi9/python-39:1-197.1725907694@sha256:278ae38e8f28ccba3cb7cd542f684d739a84f771e418fc8018d07a522205b05c

WORKDIR /scripts

COPY scripts/merge_syft_sboms.py /scripts
COPY scripts/merge_syft_sboms_spdx.py /scripts
COPY scripts/merge-cachi2-sboms-script/merge_cachi2_sboms.py /scripts
COPY scripts/base-images-sbom-script/app/base_images_sbom_script.py /scripts
COPY scripts/base-images-sbom-script/app/requirements.txt /scripts/base-images-sbom-script-requirements.txt
COPY scripts/index-image-sbom-script/requirements.txt /scripts/index-image-sbom-script-requirements.txt
COPY scripts/index-image-sbom-script/index_image_sbom_script.py /scripts

COPY scripts/add-image-reference-script/add_image_reference.py /scripts
COPY scripts/add-image-reference-script/requirements.txt /scripts/add-image-reference-requirements.txt

RUN pip3 install --no-cache-dir \
    -r base-images-sbom-script-requirements.txt \
    -r index-image-sbom-script-requirements.txt \
    -r add-image-reference-requirements.txt
