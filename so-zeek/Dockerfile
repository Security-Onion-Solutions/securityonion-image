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
LABEL description="Zeek running in a docker with AF_Packet 1.4 for use with Security Onion."

# Common CentOS layer
RUN yum update -y && \
    yum -y install epel-release bash libpcap iproute && \
    yum clean all

RUN yum -y install jemalloc numactl libnl3 libdnet gdb GeoIP python-ipaddress python3 && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum

# Install the Zeek package
RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/securityonion-zeek-3.0.13.0/securityonion-zeek-3.0.13.0.rpm

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
