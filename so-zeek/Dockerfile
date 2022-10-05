# Copyright 2014-2022 Security Onion Solutions, LLC

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

FROM ghcr.io/security-onion-solutions/rockylinux:8 as builder 
RUN dnf -y install dnf-plugins-core && dnf config-manager --set-enabled powertools && dnf update -y && \
    dnf -y install epel-release bash libpcap iproute wget cmake swig && \
    dnf -y install jemalloc numactl libnl3 libdnet gdb GeoIP && \
    dnf -y install libpcap-devel openssl-devel zlib-devel jemalloc-devel python3-devel kernel-devel kernel-headers &&\
    dnf group install -y "Development Tools" && \
    pip3 install GitPython semantic-version && \
    dnf -y erase epel-release && dnf clean all && rm -rf /var/cache/dnf

ENV ZEEKVER=5.0.2
ARG BUILD_TYPE=Release

RUN mkdir /zeekbuild

WORKDIR /zeekbuild

RUN wget https://download.zeek.org/zeek-$ZEEKVER.tar.gz && tar zxvf zeek-$ZEEKVER.tar.gz
RUN cd zeek-$ZEEKVER && \
    ./configure --prefix=/opt/zeek --spooldir=/nsm/zeek/spool --logdir=/nsm/zeek/logs --enable-jemalloc --build-type=$BUILD_TYPE && \
    make -j4 && make install 
RUN yum install -y glibc-common
RUN /opt/zeek/bin/zkg install --force ja3 && \
    /opt/zeek/bin/zkg install --force hassh && \
    /opt/zeek/bin/zkg install --force https://github.com/TOoSmOotH/zeek-af_packet-plugin --version=master && \
    /opt/zeek/bin/zkg install --force zeek-community-id && \
    /opt/zeek/bin/zkg install --force bzar && \
    /opt/zeek/bin/zkg install --force icsnpp-bacnet && \
    /opt/zeek/bin/zkg install --force icsnpp-bsap && \
    /opt/zeek/bin/zkg install --force icsnpp-ethercat && \
    /opt/zeek/bin/zkg install --force icsnpp-enip && \
    /opt/zeek/bin/zkg install --force icsnpp-opcua-binary && \
    /opt/zeek/bin/zkg install --force icsnpp-dnp3 && \
    /opt/zeek/bin/zkg install --force icsnpp-modbus && \
    /opt/zeek/bin/zkg install --force zeek-spicy-wireguard && \ 
    /opt/zeek/bin/zkg install --force zeek-spicy-stun

FROM ghcr.io/security-onion-solutions/rockylinux:8 

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Zeek running in a docker with AF_Packet 3.2.0 for use with Security Onion."

COPY --from=builder /nsm/zeek /nsm/zeek
COPY --from=builder /opt/zeek /opt/zeek
# Common CentOS layer
RUN dnf update -y && \
    dnf -y install epel-release bash libpcap iproute && \
    dnf -y install jemalloc numactl libnl3 libdnet gdb GeoIP python3 && \
    dnf -y erase epel-release && dnf clean all && rm -rf /var/cache/dnf && \
    groupadd --gid 937 zeek  && \
    adduser --uid 937 --gid 937 --home-dir /opt/zeek --no-create-home zeek && \
    chown -R 937:937 /opt/zeek && \
    chown -R 937:937 /nsm/zeek

VOLUME ["/nsm/zeek/logs", "/nsm/zeek/spool", "/opt/zeek/share/bro", "/opt/zeek/etc/"]

# Copy over the entry script.
COPY files/zeek.sh /usr/local/sbin/zeek.sh
RUN chmod +x /usr/local/sbin/zeek.sh
RUN rpm -i https://github.com/axellioinc/fx-libpcap/releases/download/fxlibpcap-1.9.1/fx-libpcap-1.9.1-1.el7.x86_64.rpm

HEALTHCHECK --interval=10m --timeout=2m CMD /opt/zeek/bin/zeekctl status || (kill -s 15 -1 && (sleep 30; kill -s 9 -1))

ENTRYPOINT ["/usr/local/sbin/zeek.sh"]
