FROM registry.access.redhat.com/ubi9/python-39:1-192.1722518946@sha256:0176b477075984d5a502253f951d2502f0763c551275f9585ac515b9f241d73d

WORKDIR /app
COPY app/requirements.txt  /app
COPY app/base_images_sbom_script.py /app

RUN pip3 install -r requirements.txt
