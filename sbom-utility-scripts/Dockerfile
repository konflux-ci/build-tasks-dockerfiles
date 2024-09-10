FROM registry.access.redhat.com/ubi9/python-39:1-197.1725907694@sha256:278ae38e8f28ccba3cb7cd542f684d739a84f771e418fc8018d07a522205b05c

WORKDIR /scripts

COPY scripts/merge_syft_sboms.py /scripts
COPY scripts/merge-cachi2-sboms-script/merge_cachi2_sboms.py /scripts
COPY scripts/create_purl_sbom.py /scripts
COPY scripts/base-images-sbom-script/app/base_images_sbom_script.py /scripts
COPY scripts/base-images-sbom-script/app/requirements.txt /scripts

RUN pip3 install -r requirements.txt
