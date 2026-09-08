FROM ghcr.io/security-onion-solutions/ubi9:9.7

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="Patched UBI9 base image shared by Security Onion containers"

RUN dnf update -y && \
    dnf install -y --nodocs ca-certificates && \
    dnf clean all
