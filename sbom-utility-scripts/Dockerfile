FROM registry.access.redhat.com/ubi9/python-39:1-192.1722518946@sha256:0176b477075984d5a502253f951d2502f0763c551275f9585ac515b9f241d73d

WORKDIR /scripts

COPY scripts/merge_syft_sboms.py /scripts
COPY scripts/merge-cachi2-sboms-script/merge_cachi2_sboms.py /scripts
COPY scripts/create_purl_sbom.py /scripts
COPY scripts/base-images-sbom-script/app/base_images_sbom_script.py /scripts
COPY scripts/base-images-sbom-script/app/requirements.txt /scripts
COPY scripts/index-image-sbom-script/index_image_sbom_script.py /scripts

# Same requirements for base-images-sbom-script and index-image-sbom-script
RUN pip3 install -r requirements.txt
