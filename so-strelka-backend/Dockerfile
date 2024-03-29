FROM ghcr.io/security-onion-solutions/ubuntu:23.04
LABEL maintainer "Security Onion Solutions, LLC"

ARG DEBIAN_FRONTEND=noninteractive

ARG CONFIG_TESTS=false

ARG USERNAME=strelka
ARG USER_UID=1001
ARG USER_GID=$USER_UID

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV PIP_BREAK_SYSTEM_PACKAGES 1

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME

ARG YARA_VERSION=4.3.0
ARG YARA_PYTHON_VERSION=4.3.0
ARG CAPA_VERSION=5.0.0
ARG EXIFTOOL_VERSION=12.52

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# SO - Pin to release tag, download from GitHub, and prepare container dirs
ARG STRELKA_RELEASE_VERSION=0.23.09.12
RUN mkdir /strelka && \
    mkdir /etc/strelka && \
    mkdir /tmp/strelka && \
    mkdir /var/log/strelka && \
    apt -y update && \ 
    apt install git -y && \
    git clone -b $STRELKA_RELEASE_VERSION https://github.com/target/strelka /tmp/strelka && \
    cp -fr /tmp/strelka/src/python/* /strelka/ && \
    cp -fr /tmp/strelka/configs/python/backend/* /etc/strelka/ && \
    cp -fr /tmp/strelka/build/python/backend/pin.pref /etc/apt/preferences.d/ && \
    cp -fr /tmp/strelka/build/python/backend/lunar.list /etc/apt/sources.list.d/ && \
    rm -fr /tmp/strelka && \
    chown -R ${USER_UID}:${USER_GID} /var/log/strelka/

# Update packages
RUN apt-get -q update && \
# Install build packages
    apt-get install -q -y --no-install-recommends \
    automake \
    build-essential \
    cmake \
    curl \
    gcc \
    git \
    gpg \
    libglu1-mesa \
    libtool \
    make \
    swig \
    python3-dev \
    python3-pip \
    python3-wheel \
    python-is-python3 \
    pkg-config

# Install runtime packages
RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
    7zip \
    antiword \
    binwalk \
    libarchive-dev \
    # 7z2john.pl
    libcompress-raw-lzma-perl \
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
# Download and compile Archive library, needed for exiftool to work best
    cd /tmp/ && \
    curl -OL https://cpan.metacpan.org/authors/id/P/PH/PHRED/Archive-Zip-1.68.tar.gz && \
    tar -xzf Archive-Zip-1.68.tar.gz && \
    cd Archive-Zip-1.68/ && \
    perl Makefile.PL && \
    make && \
    make install && \
# Download and compile exiftool
    cd /tmp/ && \
    curl -OL https://github.com/exiftool/exiftool/archive/refs/tags/$EXIFTOOL_VERSION.tar.gz && \
    tar -zxvf $EXIFTOOL_VERSION.tar.gz && \
    cd exiftool-$EXIFTOOL_VERSION/ && \
    perl Makefile.PL && \
    make && \
    make install && \
# Install FireEye CAPA rules and signatures
    mkdir -p /etc/capa/rules/ && \
    curl -OL https://github.com/mandiant/capa-rules/archive/refs/tags/v$CAPA_VERSION.zip && \
    unzip v$CAPA_VERSION.zip -d /etc/capa/rules/ && \
    rm v$CAPA_VERSION.zip && \
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
# Install YARA
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz && \
    tar -zxvf v$YARA_VERSION.tar.gz && \
    cd yara-$YARA_VERSION/ && \
    ./bootstrap.sh && \
    ./configure --with-crypto --enable-magic --enable-cuckoo && \
    make && make install && make check && \
# Install yara-python
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara-python/archive/v$YARA_PYTHON_VERSION.tar.gz && \
    tar -zxvf v$YARA_PYTHON_VERSION.tar.gz && \
    cd yara-python-$YARA_PYTHON_VERSION/ && \
    python3 setup.py build --dynamic-linking && \
    python3 setup.py install

# Install JTR
RUN apt-get -q update \
  && apt-get install -q -y --no-install-recommends \
    ca-certificates \
    libssl-dev \
    zlib1g-dev \
    yasm \
    libgmp-dev \
    libpcap-dev \
    libbz2-dev \
    libgomp1
# The maintainer isn't big on releases or tags so grab an arbitrary, but consistent, commit.
# Additionally jump through some extra hoops to get the single commit to save some download time.
RUN mkdir jtr && cd jtr && git init && git remote add origin https://github.com/openwall/john.git && git fetch --depth 1 origin b5c10480f56ff1b5d76c6cbdaf9c817582ee2228 && git reset --hard FETCH_HEAD \
  && rm -rf /jtr/.git \
  && cd /jtr/src \
  && ./configure \
  && make -s clean \
  && make -sj4 \
  && make install \
  && cp -Tr /jtr/run/ /jtr && rm -rf /jtr/run \
  && chmod -R 777 /jtr \
  && chown -R 1001:1001 /jtr

# Install Python packages
RUN pip3 install --no-cache-dir -r /strelka/requirements.txt && \
    pip3 install --index-url https://lief-project.github.io/packages --trusted-host lief.quarkslab.com lief

# Install Strelka
RUN cd /strelka/ && \
    python3 setup.py -q build && \
    python3 setup.py -q install && \
# Remove build packages
    python3 setup.py -q clean --all && \
    rm -rf dist/ strelka.egg-info && \
    pip3 uninstall -y grpcio-tools && \
    apt-get remove -y --purge \
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
    rm -rf /var/lib/apt/lists/* /tmp/yara*

# Run tests as non-root user
USER $USERNAME

# Run build checks
RUN echo '[+] Run build checks' && \
    cd /strelka/strelka/ && \
    python3 -m pytest -p no:cacheprovider -s tests/ --ignore-glob='*pcap*.py' --ignore-glob='*test_scan_transcode.py' --ignore-glob='*test_scan_nf.py' && \
    if $CONFIG_TESTS; then python3 -m pytest -s tests_configuration/; fi && \
    echo '[+] Done'

USER root

# Remove python build directory
RUN cd /strelka/ && \
    rm -rf /strelka/

# Remove config directory (will bind mount once built)
RUN rm -rf /etc/strelka/

USER $USERNAME
