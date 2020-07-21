FROM ubuntu:18.04

# Common Ubuntu layer
RUN apt-get update && \
    apt-get --no-install-recommends --no-install-suggests -y install \
        curl \
        ca-certificates \
        build-essential

RUN apt-get install -y --no-install-recommends \
    gcab \
    msitools \
    ruby \
    ruby-dev \ 
    rubygems \ 
    cpio \
    binutils \
    cpio \
    cabextract \
    rpm

RUN gem install --no-ri --no-rdoc fpm && \
    apt-get -f -y --auto-remove remove build-essential autoconf libtool && \    
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/launcher-1.2.2/launcher.tar.gz -o /tmp/launcher.tgz
RUN tar xf /tmp/launcher.tgz -C /var && \
    cp -fr /var/launcher/src/tools/* /usr/local/bin/

WORKDIR /var/launcher

ENTRYPOINT ["/var/launcher/generate-packages.sh"]
