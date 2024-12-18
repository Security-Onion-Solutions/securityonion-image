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

FROM ghcr.io/security-onion-solutions/oraclelinux:9 as builder

RUN dnf update -y && \
    dnf -y install epel-release && \
    dnf config-manager --enable ol9_codeready_builder
RUN dnf -y install oraclelinux-developer-release-el9 
RUN dnf repolist
RUN dnf -y install autoconf automake diffutils file-devel gcc gcc-c++ git \
               jansson-devel jq libcap-ng-devel libevent-devel \
               libmaxminddb-devel libmaxminddb libnet-devel libnetfilter_queue-devel \
               libnfnetlink-devel libpcap-devel libtool libyaml-devel \
               lua-devel lz4-devel make nss-devel pcre-devel pcre2-devel pkgconfig \
               python3-devel python3-sphinx python3-yaml sudo which cargo \
               zlib-devel luajit-devel cargo && cargo install --force cbindgen
ENV SURIVERSION=7.0.8
RUN mkdir /suricata

WORKDIR /suricata

RUN curl -vO https://www.openinfosecfoundation.org/download/suricata-$SURIVERSION.tar.gz && tar zxvf suricata-$SURIVERSION.tar.gz && \
    cd suricata-$SURIVERSION && ./configure --enable-rust --enable-luajit --prefix=/opt/suricata --sysconfdir=/etc --disable-gccmarch-native --localstatedir=/var --enable-geoip && make -j4
RUN mkdir suriinstall && cd suricata-$SURIVERSION && make install DESTDIR=/suricata/suriinstall && make install-conf DESTDIR=/suricata/suriinstall && rm -rf /suricata/suriinstall/var/run

FROM ghcr.io/security-onion-solutions/oraclelinux:9

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Suricata running in a docker with AF_Packet for use with Security Onion."

# Common Oracle layer
RUN dnf update -y && dnf -y install epel-release bash libpcap iproute && \
    dnf clean all && rm -rf /var/cache/dnf/* 

# Packages Specific to this Container
RUN dnf -y install luajit libnet jansson libyaml cargo rustc nss nss-devel libmaxminddb && \ 
    dnf -y erase epel-release && dnf clean all && rm -rf /var/cache/dnf/* 

COPY --from=builder /suricata/suriinstall/ /

# User configuration
RUN groupadd --gid 940 suricata && \
    adduser --uid 940 --gid 940 --home-dir /etc/suricata --no-create-home suricata && \
    chown -R 940:940 /etc/suricata && \
    chown -R 940:940 /var/log/suricata

# Copy over the entry script.
ADD files/so-suricata.sh /usr/local/sbin/so-suricata.sh

RUN chmod +x /usr/local/sbin/so-suricata.sh && rpm -i https://github.com/axellioinc/fx-libpcap/releases/download/px3_1.9.1-3/fx-libpcap-1.9.1-3.el9.x86_64.rpm

ENTRYPOINT ["/usr/local/sbin/so-suricata.sh"]
