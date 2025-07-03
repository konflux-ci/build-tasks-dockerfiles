FROM registry.access.redhat.com/ubi9/python-312:9.6-1751459812@sha256:81ecc946acac7523ab3c7fe10ca4cf7db29bb462c2ab5c6c57c7b57d39f38b19

WORKDIR /scripts

COPY scripts/merge_syft_sboms.py /scripts
COPY scripts/merge-sboms-script/merge_sboms.py /scripts
# for backwards compatibility, also ship the script at the original location
COPY scripts/merge-sboms-script/merge_sboms.py /scripts/merge_cachi2_sboms.py
COPY scripts/merge-sboms-script/requirements.txt /scripts/merge-sboms-script-requirements.txt
COPY scripts/base-images-sbom-script/app/base_images_sbom_script.py /scripts
COPY scripts/base-images-sbom-script/app/requirements.txt /scripts/base-images-sbom-script-requirements.txt
COPY scripts/index-image-sbom-script/requirements.txt /scripts/index-image-sbom-script-requirements.txt
COPY scripts/index-image-sbom-script/index_image_sbom_script.py /scripts

COPY scripts/add-image-reference-script/add_image_reference.py /scripts
COPY scripts/add-image-reference-script/requirements.txt /scripts/add-image-reference-requirements.txt

COPY scripts/sbom-for-oci-copy-task/sbom_for_oci_copy_task.py /scripts
COPY scripts/sbom-for-oci-copy-task/requirements.txt /scripts/sbom-for-oci-copy-task-requirements.txt

COPY scripts/sbom-for-modelcar-task/sbom_for_modelcar_task.py /scripts
COPY scripts/sbom-for-modelcar-task/requirements.txt /scripts/sbom-for-modelcar-task-requirements.txt


RUN pip3 install --no-cache-dir \
    -r merge-sboms-script-requirements.txt \
    -r base-images-sbom-script-requirements.txt \
    -r index-image-sbom-script-requirements.txt \
    -r add-image-reference-requirements.txt \
    -r sbom-for-oci-copy-task-requirements.txt \
    -r sbom-for-modelcar-task-requirements.txt \
