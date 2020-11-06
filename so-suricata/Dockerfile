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
LABEL description="Suricata 5.0.4 running in a docker for use with Security Onion."

# Common CentOS layer
RUN yum update -y && \
    yum -y install epel-release bash libpcap iproute && \
    yum clean all

RUN yum -y install GeoIP luajit libnet jansson libyaml cargo rustc && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum

# Install the Suricata package
RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/securityonion-suricata-5.0.4-0/securityonion-suricata-5.0.4.0.rpm
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
