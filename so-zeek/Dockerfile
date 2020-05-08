FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Zeek running in a docker with AF_Packet 1.4 for use with Security Onion."

RUN yum update -y && \
    yum clean all

# Install epel
RUN yum -y install epel-release bash libpcap iproute && yum clean all
RUN yum -y install jemalloc numactl libnl3 libdnet gdb GeoIP python-ipaddress python3 && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum

# Install the Zeek package
RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/securityonion-zeek-3.0.6.0/securityonion-zeek-3.0.6.0.rpm

VOLUME ["/nsm/zeek/logs", "/nsm/zeek/spool", "/opt/zeek/share/bro", "/opt/zeek/etc/"]

# Create Bro User.
RUN groupadd --gid 937 zeek  && \
    adduser --uid 937 --gid 937 \
    --home-dir /opt/zeek --no-create-home zeek

# Fix those perms.. big worm
RUN chown -R 937:937 /opt/zeek && \
    chown -R 937:937 /nsm/zeek

# Copy over the entry script.
COPY files/zeek.sh /usr/local/sbin/zeek.sh
RUN chmod +x /usr/local/sbin/zeek.sh

ENTRYPOINT ["/usr/local/sbin/zeek.sh"]
