# Copyright 2014-2020 Security Onion Solutions, LLC

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

FROM ghcr.io/security-onion-solutions/centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Google Stenographer running in a docker for use with Security Onion."

# Common CentOS layer
RUN yum -y install epel-release bash libpcap iproute && \
    yum -y install https://repo.ius.io/ius-release-el7.rpm && \
    yum -y install snappy leveldb tcpdump jq libaio libseccomp golang which openssl python36u python36u-pip && \
    /usr/bin/pip3.6 install && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum && \
    rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/Stenoupgrade/stenographer-0-1.20200922gite8db1ee.el7.x86_64.rpm && \
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
