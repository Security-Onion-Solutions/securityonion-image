# Copyright Security Onion Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

FROM ghcr.io/security-onion-solutions/oraclelinux:9

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="Google Stenographer running in a docker for use with Security Onion."

# Common Oracle layer
RUN dnf update -y && dnf -y install epel-release bash libpcap iproute
    dnf clean all && rm -rf /var/cache/dnf/* 

# Packages Specific to this Container
RUN dnf -y install snappy leveldb tcpdump jq libaio libseccomp golang which openssl && \ 
    dnf -y erase epel-release && dnf clean all && rm -rf /var/cache/dnf/* 

# User configuration
RUN groupadd -g 941 stenographer && \
    useradd stenographer -u 941 -g 941 && \
    rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/stenographer-v101/securityonion-stenographer-v1.0.1.0.rpm && \
    chmod 755 /usr/bin/steno* && \
    setcap 'CAP_NET_RAW+ep CAP_NET_ADMIN+ep CAP_IPC_LOCK+ep CAP_SETGID+ep' /usr/bin/stenotype && \
    mkdir -p /nsm/pcap/files && \
    mkdir -p /nsm/pcap/index && \
    chown -R 941:941 /nsm/pcap && \
    mkdir -p /etc/stenographer/certs && \
    mkdir -p /var/log/stenographer && \
    usermod -s /bin/bash stenographer


# Copy over the entry script.
COPY files/so-steno.sh /usr/local/sbin/so-steno.sh
RUN chmod +x /usr/local/sbin/so-steno.sh

ENTRYPOINT ["/usr/local/sbin/so-steno.sh"]
