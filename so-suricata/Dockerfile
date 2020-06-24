FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Suricata 5.0.3 running in a docker for use with Security Onion."

RUN yum update -y && \
    yum clean all

# Install epel
RUN yum -y install epel-release bash libpcap iproute

RUN yum -y install GeoIP luajit libnet jansson libyaml cargo rustc && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum

# Install the Suricata package
RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/securityonion-suricata-5.0.3-0/securityonion-suricata-5.0.3.0.rpm
# Create Suricata User.
RUN groupadd --gid 940 suricata && \
    adduser --uid 940 --gid 940 \
    --home-dir /etc/suricata --no-create-home suricata

# Fix those perms.. big worm
RUN chown -R 940:940 /etc/suricata && \
    chown -R 940:940 /var/log/suricata

# Copy over the entry script.
ADD files/so-suricata.sh /usr/local/sbin/so-suricata.sh

RUN chmod +x /usr/local/sbin/so-suricata.sh && chown 940:940 /var/run/suricata

ENTRYPOINT ["/usr/local/sbin/so-suricata.sh"]
