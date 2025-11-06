# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

ARG MSITOOLS_VERSION=v0.103

FROM ghcr.io/security-onion-solutions/alpine:3.22.1 AS msibuilder

# Re-declare ARG to make it available in this stage
ARG MSITOOLS_VERSION

# Install build dependencies
RUN apk add --no-cache \
    git build-base autoconf automake libtool pkgconfig \
    glib-dev libgsf-dev util-linux-dev libxml2-dev \
    gobject-introspection-dev meson ninja vala bison \
    libgcab-dev g++ \
    && rm -rf /var/cache/apk/*

# Clone and build msitools
RUN git clone https://github.com/GNOME/msitools.git /build/msitools \
    && cd /build/msitools \
    && git checkout ${MSITOOLS_VERSION} \
    && git submodule update --init \
    && meson setup builddir \
    && ninja -C builddir install

# Final stage with Go
FROM ghcr.io/security-onion-solutions/golang:1.25.1-alpine

# Install runtime dependencies for wixl
RUN apk add --no-cache \
    glib libgsf libxml2 util-linux \
    gobject-introspection libgcab make

# Copy msitools files from builder
COPY --from=msibuilder /usr/local/bin/wixl* /usr/local/bin/
COPY --from=msibuilder /usr/local/lib/libmsi* /usr/local/lib/
COPY --from=msibuilder /usr/local/share/wixl-0.103 /usr/local/share/wixl-0.103

# Set up workspace:
# source is go code
# msi is config & lib for wixl
RUN mkdir /workspace
ADD source /workspace
ADD msi /workspace
WORKDIR /workspace
RUN go get .