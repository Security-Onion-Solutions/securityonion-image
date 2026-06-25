# syntax=docker/dockerfile:1.7
#
# Source is fetched from a public git repo at build time.

ARG PY_BASE=ghcr.io/security-onion-solutions/ubi9:9.7
ARG STRELKA_REPO=https://github.com/defensivedepth/strelka
ARG STRELKA_REF=python-3.14
ARG YARA_VERSION=4.5.4
ARG EXIFTOOL_VERSION=12.60
ARG SEVENZ_VERSION=26.00
ARG SEVENZ_ARCHIVE=7z2600-linux-x64.tar.xz
ARG JTR_REV=b5c10480f56ff1b5d76c6cbdaf9c817582ee2228
ARG USERNAME=strelka
ARG USER_UID=1001
ARG USER_GID=1001

# ---- builder ---------------------------------------------------------------
FROM ghcr.io/security-onion-solutions/oraclelinux:9 AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG STRELKA_REPO
ARG STRELKA_REF
ARG YARA_VERSION
ARG EXIFTOOL_VERSION
ARG SEVENZ_VERSION
ARG SEVENZ_ARCHIVE
ARG JTR_REV

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_INSTALLER_MAX_WORKERS=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CXX=g++

# libxcb1/libzbar0 are imported at test time by pyzbar even though they're
# not direct build deps.
RUN --mount=type=cache,target=/var/cache/dnf,sharing=locked \
    dnf -y install dnf-plugins-core && \
    dnf config-manager --enable ol9_codeready_builder && \
    dnf -y install epel-release && \
    dnf install -y --nodocs \
      automake gcc gcc-c++ ca-certificates cmake curl git libtool make \
      perl perl-Compress-Raw-Lzma pkgconfig swig yasm \
      libarchive-devel bzip2-devel libxcrypt-devel ssdeep-devel gmp-devel \
      jansson-devel xz xz-devel file-devel libpcap-devel openssl-devel zlib-devel \
      libxcb-devel zbar-devel \
      tesseract tesseract-devel unzip upx \
      python3.14 python3.14-devel python3.14-pip && \
    dnf clean all && rm -rf /var/cache/dnf/* && \
    ln -s /usr/bin/python3.14 /usr/local/bin/python3 && \
    ln -s /usr/bin/python3.14 /usr/local/bin/python

RUN --mount=type=cache,target=/root/.cache/pip \
    python3.14 -m pip install --upgrade pip && \
    pip3.14 install setuptools wheel poetry

# antiword, exiftool, 7zz, YARA, yara-python (linked dynamically against libyara).
RUN set -eu; \
    cd /tmp; \
    curl -fsSL -o "antiword-0.37.tar.gz" "http://deb.debian.org/debian/pool/main/a/antiword/antiword_0.37.orig.tar.gz"; \
    tar -zxf "antiword-0.37.tar.gz"; \
    (cd "antiword-0.37" && make -f Makefile.Linux && make -f Makefile.Linux global_install); \
    curl -fsSLO "https://github.com/exiftool/exiftool/archive/refs/tags/${EXIFTOOL_VERSION}.tar.gz"; \
    tar -zxf "${EXIFTOOL_VERSION}.tar.gz"; \
    (cd "exiftool-${EXIFTOOL_VERSION}" && perl Makefile.PL && make -s -j2 && make -s install); \
    curl -fsSLO "https://github.com/ip7z/7zip/releases/download/${SEVENZ_VERSION}/${SEVENZ_ARCHIVE}"; \
    tar -xf "${SEVENZ_ARCHIVE}" 7zz; \
    mv 7zz /usr/local/bin/; \
    curl -fsSLO "https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz"; \
    tar -zxf "v${YARA_VERSION}.tar.gz"; \
    (cd "yara-${YARA_VERSION}" \
        && ./bootstrap.sh \
        && ./configure --with-crypto --enable-magic --enable-cuckoo \
        && make -s -j2 && make -s install && OPENSSL_ENABLE_SHA1_SIGNATURES=yes make -s check); \
    curl -fsSLO "https://github.com/VirusTotal/yara-python/archive/v${YARA_VERSION}.tar.gz"; \
    tar -zxf "v${YARA_VERSION}.tar.gz"; \
    (cd "yara-python-${YARA_VERSION}" \
        && python3.14 setup.py build --dynamic-linking \
        && python3.14 setup.py install); \
    rm -rf /tmp/*

# JTR — pinned to a commit because upstream doesn't tag releases.
RUN set -eu; \
    mkdir /jtr && cd /jtr; \
    git init && \
    git remote add origin https://github.com/openwall/john.git && \
    git fetch --depth 1 origin "${JTR_REV}" && \
    git reset --hard FETCH_HEAD && \
    rm -rf /jtr/.git; \
    cd /jtr/src && ./configure && make -s clean && make -sj2 && make install; \
    cp -Tr /jtr/run/ /jtr && rm -rf /jtr/run; \
    chmod -R 755 /jtr

RUN git clone --depth 1 -b "${STRELKA_REF}" "${STRELKA_REPO}" /tmp/strelka-source

WORKDIR /strelka/
RUN cp /tmp/strelka-source/pyproject.toml /tmp/strelka-source/poetry.lock /strelka/

# ssdeep 3.4 (last release) won't build under setuptools>81. Installed
# out-of-band — pyproject.toml in the fork omits it from poetry deps.
RUN --mount=type=cache,target=/root/.cache/pip \
    echo "setuptools==81.0.0" > constraints.txt && \
    pip3.14 wheel --build-constraint constraints.txt "ssdeep==3.4" && \
    pip3.14 install ssdeep==3.4 && \
    poetry config virtualenvs.create false && \
    mkdir -p /root/.cache/pypoetry/virtualenvs && \
    poetry env use python3.14

# Source-build opencv-python-headless without FFmpeg to avoid the vendored
# libcrypto-1.1.1k that aborts on import under STIG/FIPS. Build deps are
# pre-installed system-wide and --no-build-isolation is passed so opencv's
# CMake (which shells out to python3.14 to find numpy headers) sees them.
# numpy is pinned to opencv 4.12.0.88's required <2.3; poetry install will
# later upgrade it to ^2.4 — safe because numpy 2.x has a stable C ABI.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3.14 install "numpy<2.3" scikit-build ninja && \
    CMAKE_ARGS="-DWITH_FFMPEG=OFF -DWITH_GSTREAMER=OFF -DWITH_1394=OFF -DWITH_OPENCL=OFF" \
    ENABLE_HEADLESS=1 \
    pip3.14 install --no-build-isolation --no-binary=opencv-python-headless \
        "opencv-python-headless==4.12.0.88"

RUN --mount=type=cache,target=/root/.cache/pip \
    poetry install --only main --no-root

RUN cp -r /tmp/strelka-source/src/python/. /strelka/ && \
    python3.14 setup.py -q build && \
    python3.14 setup.py -q install && \
    python3.14 setup.py -q clean --all

# Build gate — pcap/clamav tests need deps out of scope for this image.
RUN cp -r /tmp/strelka-source/configs/python/backend/. /etc/strelka/ && \
    ldconfig && \
    cd /strelka/strelka/ && \
    python3.14 -m pytest -p no:cacheprovider --tb=short --no-header -rN \
        --ignore=tests/test_scan_pcap.py \
        --ignore=tests/test_scan_clamav.py \
        tests/

# Trim before final COPY.
RUN find /usr/local -name '__pycache__' -type d -prune -exec rm -rf {} + && \
    find /usr/local -name '*.pyc' -delete && \
    rm -rf /usr/local/include /usr/local/share/doc /usr/local/share/man \
           /usr/local/lib*/python3.14/site-packages/poetry* \
           /usr/local/lib*/python3.14/site-packages/poetry_core* \
           /usr/local/src/*/.git /usr/local/src/*/samples

# ---- runtime ---------------------------------------------------------------
FROM ${PY_BASE} AS runtime

LABEL maintainer="Security Onion Solutions, LLC"

ARG DEBIAN_FRONTEND=noninteractive
ARG USERNAME
ARG USER_UID
ARG USER_GID

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    MAGIC=/usr/share/file/magic.mgc

RUN dnf update -y && \
    dnf install -y --nodocs ca-certificates && \
    dnf clean all

RUN --mount=type=cache,target=/var/cache/dnf,sharing=locked \
    dnf install -y --repofrompath=rocky-baseos,https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/ \
        --repofrompath=rocky-appstream,https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/ \
        --setopt=rocky-baseos.gpgcheck=0 \
        --setopt=rocky-appstream.gpgcheck=0 \
        https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && \
    dnf install -y --nodocs \
        --repofrompath=rocky-baseos,https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/ \
        --repofrompath=rocky-appstream,https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/ \
        --setopt=rocky-baseos.gpgcheck=0 \
        --setopt=rocky-appstream.gpgcheck=0 \
        libarchive ssdeep-libs libgomp jansson file-libs zbar perl-interpreter perl-Compress-Raw-Lzma tesseract unzip upx \
        python3.14 python3.14-pip && \
    dnf -y remove epel-release && \
    dnf clean all && rm -rf /var/cache/dnf/* && \
    mkdir -p /usr/share/file /usr/lib/file && \
    ln -sf /usr/share/misc/magic.mgc /usr/share/file/magic.mgc && \
    ln -sf /usr/share/misc/magic.mgc /usr/lib/file/magic.mgc

RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME && \
    mkdir -p /var/log/strelka && \
    chown -R $USER_UID:$USER_GID /var/log/strelka

COPY --from=builder /usr/local /usr/local
COPY --from=builder --chown=${USER_UID}:${USER_GID} /jtr /jtr

RUN ldconfig

USER $USERNAME
