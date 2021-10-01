# Copyright 2014-2021 Security Onion Solutions, LLC

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

FROM ghcr.io/security-onion-solutions/centos:7 as builder

RUN yum -y install epel-release
RUN yum -y install jansson-devel libpcap-devel python3 libpcap-devel openssl-devel zlib-devel jemalloc-devel python3-devel kernel-devel kernel-headers libjansson libgeoip liblua5.1 wget make gcc pkg-config libhiredis libevent pcre-devel libpcre libmagic zlib libyaml rustc cargo libyaml-devel libcap-ng-devel file-devel nss-devel nspr-devel python3-yaml luajit-devel luajit

ENV SURIVERSION=6.0.3
RUN mkdir /suricata

WORKDIR /suricata

RUN wget https://www.openinfosecfoundation.org/download/suricata-$SURIVERSION.tar.gz && tar zxvf suricata-$SURIVERSION.tar.gz && \
    cd suricata-$SURIVERSION && ./configure --enable-rust --enable-luajit --prefix=/opt/suricata --sysconfdir=/etc --disable-gccmarch-native --localstatedir=/var && make
RUN mkdir suriinstall && cd suricata-$SURIVERSION && make install DESTDIR=/suricata/suriinstall && make install-conf DESTDIR=/suricata/suriinstall && rm -rf /suricata/suriinstall/var/run

FROM ghcr.io/security-onion-solutions/centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Suricata running in a docker with AF_Packet for use with Security Onion."

COPY --from=builder /suricata/suriinstall/ /

RUN yum -y install epel-release bash libpcap iproute && \
    yum -y install GeoIP luajit libnet jansson libyaml cargo rustc && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum && \
    groupadd --gid 940 suricata && \
    adduser --uid 940 --gid 940 --home-dir /etc/suricata --no-create-home suricata && \
    chown -R 940:940 /etc/suricata && \
    chown -R 940:940 /var/log/suricata

# Copy over the entry script.
ADD files/so-suricata.sh /usr/local/sbin/so-suricata.sh

RUN chmod +x /usr/local/sbin/so-suricata.sh

ENTRYPOINT ["/usr/local/sbin/so-suricata.sh"]
