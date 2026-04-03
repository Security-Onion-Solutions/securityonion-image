FROM ghcr.io/security-onion-solutions/ubuntu:22.04
LABEL maintainer="Security Onion Solutions, LLC"

ARG DEBIAN_FRONTEND=noninteractive

# Test configuration
ARG CONFIG_TESTS=false

ARG YARA_VERSION=4.3.1
ARG CAPA_VERSION=9.2.1
ARG EXIFTOOL_VERSION=12.60

# Environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PYTHONUNBUFFERED 1

# User configuration
ARG USERNAME=strelka
ARG USER_UID=1001
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME

# SO - Pin to release tag, download from GitHub, and prepare container dirs
ARG STRELKA_RELEASE_VERSION=1.0.1

RUN mkdir /strelka && \
    mkdir /etc/strelka && \
    mkdir /tmp/strelka && \
    mkdir /var/log/strelka && \
    apt -y update && \
    apt -y upgrade && \
    apt install git -y && \
    git clone -b $STRELKA_RELEASE_VERSION https://github.com/target/strelka /tmp/strelka && \
    cp -fr /tmp/strelka/pyproject.toml /strelka/ && \
    cp -fr /tmp/strelka/poetry.lock /strelka/ && \
    cp -fr /tmp/strelka/src/python/* /strelka/ && \
    cp -fr /tmp/strelka/configs/python/backend/* /etc/strelka/ && \
    rm -fr /tmp/strelka && \
    chown -R ${USER_UID}:${USER_GID} /var/log/strelka/ && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/apt/archives/*.deb

# Install build packages
RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
    automake \
    build-essential \
    cmake \
    curl \
    gcc \
    git \
    dirmngr \
    gnupg \
    gpg \
    libglu1-mesa \
    libtool \
    make \
    swig \
    python3-dev \
    python3-pip \
    python3-wheel \
    python-is-python3 \
    pkg-config \
    supervisor \
    ncat && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/apt/archives/*.deb

# Install runtime packages
RUN apt-get -q update && apt-get install -q -y --no-install-recommends \
    antiword \
    binwalk \
    libarchive-dev \
    libfuzzy-dev \
    libjansson-dev \
    libmagic-dev \
    libssl-dev \
    libzbar0 \
    libgl1 \
    python3-setuptools \
    redis-server \
    tesseract-ocr \
    unrar \
    unzip \
    upx \
    jq && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/apt/archives/*.deb
# Download and compile exiftool
RUN cd /tmp/ && \
    curl -OL https://github.com/exiftool/exiftool/archive/refs/tags/$EXIFTOOL_VERSION.tar.gz && \
    tar -zxvf $EXIFTOOL_VERSION.tar.gz && \
    cd exiftool-$EXIFTOOL_VERSION/ && \
    perl Makefile.PL && \
    make -s -j && \
    make -s install && \
# Download and move binary for 7z 24.09
    cd /tmp/ && \
    curl -OL https://github.com/ip7z/7zip/releases/download/26.00/7z2600-linux-x64.tar.xz && \
    tar -xf 7z2600-linux-x64.tar.xz &&\
    cp 7zz /usr/local/bin && \
# Install FireEye CAPA rules and signatures
    mkdir -p /etc/capa/rules/ && \
    curl -OL https://github.com/mandiant/capa-rules/archive/refs/tags/v$CAPA_VERSION.zip && \
    unzip v$CAPA_VERSION.zip -d /etc/capa/rules/ && \
    rm -rf v$CAPA_VERSION.zip && \
    mkdir -p /etc/capa/signatures/ && \
    cd /etc/capa/signatures/ && \
    curl -OL https://github.com/mandiant/capa/raw/master/sigs/1_flare_msvc_rtf_32_64.sig && \
    curl -OL https://github.com/mandiant/capa/raw/master/sigs/2_flare_msvc_atlmfc_32_64.sig && \
    curl -OL https://github.com/mandiant/capa/raw/master/sigs/3_flare_common_libs.sig && \
# Install FireEye FLOSS
#   - Binary installation, not supported as Python 3 plugin
#   - Requires binary to be executable
    cd /tmp/ && \
    curl -OL https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss && \
    chmod +x /tmp/floss && \
    mv /tmp/floss /bin/floss && \
# Install YARA
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz && \
    tar -zxvf v$YARA_VERSION.tar.gz && \
    cd yara-$YARA_VERSION/ && \
    ./bootstrap.sh && \
    ./configure --with-crypto --enable-magic --enable-cuckoo && \
    make -s -j && make -s install && make -s check && \
# Install yara-python
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara-python/archive/v$YARA_VERSION.tar.gz && \
    tar -zxvf v$YARA_VERSION.tar.gz && \
    cd yara-python-$YARA_VERSION/ && \
    python3 setup.py build --dynamic-linking && \
    python3 setup.py install

# Install JTR
RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends \
    ca-certificates \
    zlib1g-dev \
    yasm \
    libgmp-dev \
    liblzma-dev \
    libpcap-dev \
    libbz2-dev \
    libgomp1 && \
    cpan -i Compress::Raw::Lzma && \
# The maintainer isn't big on releases or tags so grab an arbitrary, but consistent, commit.
# Additionally jump through some extra hoops to get the single commit to save some download time.
    mkdir jtr && cd jtr && git init && git remote add origin https://github.com/openwall/john.git && \
    git fetch --depth 1 origin b5c10480f56ff1b5d76c6cbdaf9c817582ee2228 && \
    git reset --hard FETCH_HEAD && \
    rm -rf /jtr/.git && \
    cd /jtr/src && \
    ./configure && \
    make -s clean && \
    make -sj && \
    make install && \
    cp -Tr /jtr/run/ /jtr && rm -rf /jtr/run && \
    chmod -R 777 /jtr && \
    chown -R $USER_UID:$USER_UID /jtr && \
# Install Poetry globally and copy project files
    python3 -m pip install -U pip setuptools && \
    python3 -m pip install poetry && \
    rm -rf /root/.cache/pip && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/apt/archives/*.deb

# Set the working directory
WORKDIR /strelka/

# This next block is a workaround due to ssdeep not being compatible with setuptools>81
# There's a PR in the ssdeep repo but we'd also need Target to update their ssdeep version pin.
RUN echo "setuptools==81.0.0" > constraints.txt && \
    pip -v wheel --build-constraint constraints.txt "ssdeep (==3.4)" && \
    pip install ssdeep==3.4 && \
    poetry config virtualenvs.create false && \
    poetry remove ssdeep --lock

# Use Poetry to install the project dependencies globally
# This step is after the COPY step because it is more likely to change,
# and therefore should not be included in earlier layers that can be cached.
RUN poetry config virtualenvs.create false && \
    poetry install --only main && \
    rm -rf /root/.cache/pypoetry && \
# Install Strelka
    cd /strelka/ && \
    python3 setup.py -q build && \
    python3 setup.py -q install && \
# Remove build packages
    python3 setup.py -q clean --all && \
    rm -rf dist/ strelka.egg-info && \
    apt-get -q update && \
    apt-get purge -y \
    automake \
    build-essential \
    cmake \
    curl \
    gcc \
    git \
    gpg \
    libtool \
    make \
    python3-dev \
    python3-pip \
    python3-wheel && \
    apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/* /tmp/yara* && \
# Assign permissions to Strelka scan result logging directory
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/ && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/apt/archives/*.deb

RUN sed -i 's/24\.09/26\.00/' /strelka/strelka/tests/test_*

# Run tests as non-root user
USER $USERNAME

# Run build checks
ARG SCANNER_TEST=""
RUN echo '[+] Run build checks' && \
    cd /strelka/strelka/ && \
    if $SCANNER_TESTS; then python3 -m pytest -p no:cacheprovider -s --ignore=tests/test_scan_pcap.py --ignore=tests/test_scan_clamav.py tests/$SCANNER_TEST; fi && \
    if $CONFIG_TESTS; then python3 -m pytest -s --ignore=tests/test_scan_pcap.py tests_configuration/; fi && \
    echo '[+] Done'

USER root

# Remove build directories and unused files
# Remove config directory (will bind mount once built)
RUN cd /strelka/ && \
    rm -rf /strelka/ && \
    rm -rf /root/.cache && \
    rm -rf /tmp/* && \
    rm -rf /etc/strelka/

USER $USERNAME
