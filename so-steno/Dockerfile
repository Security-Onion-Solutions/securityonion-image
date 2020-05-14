FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Google Stenographer running in a docker for use with Security Onion."

RUN yum update -y && \
    yum clean all

# Install epel
RUN yum -y install epel-release bash libpcap iproute tcpdump && yum clean all
RUN yum -y install https://centos7.iuscommunity.org/ius-release.rpm
RUN yum -y install snappy leveldb jq libaio libseccomp golang which openssl python36u python36u-pip
RUN /usr/bin/pip3.6 install
RUN yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum

# Install the steno package
RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/stenographer_20180316/stenographer-0-1.20180316git57b88aa.el7.centos.x86_64.rpm
RUN mkdir -p /opt/sensoroni 

RUN curl -L https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/Sensoroni-1.3.0/sensoroni -o /opt/sensoroni/sensoroni
RUN chmod +x /opt/sensoroni/sensoroni

# setcap
RUN setcap 'CAP_NET_RAW+ep CAP_NET_ADMIN+ep CAP_IPC_LOCK+ep CAP_SETGID+ep' /usr/bin/stenotype

# Fix those perms.. big worm
RUN mkdir -p /nsm/pcap/files \
    && mkdir -p /nsm/pcap/index \
    && chown -R 941:941 /nsm/pcap \
    && chown -R 941:941 /opt/sensoroni \
    && mkdir -p /etc/stenographer/certs \
    && mkdir -p /var/log/stenographer \
    && usermod -s /bin/bash stenographer


# Copy over the entry script.
COPY files/so-steno.sh /usr/local/sbin/so-steno.sh
RUN chmod +x /usr/local/sbin/so-steno.sh

ENTRYPOINT ["/usr/local/sbin/so-steno.sh"]
