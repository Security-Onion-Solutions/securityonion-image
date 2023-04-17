# Copyright 2014-2023 Security Onion Solutions, LLC

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

FROM ghcr.io/security-onion-solutions/rockylinux:9 as builder 
RUN dnf -y install dnf-plugins-core && \
    dnf config-manager --set-enabled crb && \
    dnf update -y && \ 
    dnf -y install epel-release bash libpcap iproute wget cmake swig && \
    dnf -y install numactl libnl3 libdnet gdb git && \
    dnf -y install libpcap-devel openssl-devel zlib-devel python3-devel kernel-devel kernel-headers && \
    dnf group install -y "Development Tools" && \
    dnf -y install libunwind-devel && \
    pip3 install GitPython semantic-version requests && \
    dnf -y erase epel-release && dnf clean all && rm -rf /var/cache/dnf

RUN rpm -i https://repo.securityonion.net/file/so-repo/2.4/securityonion-jemalloc-5.3.0_1.rpm

ENV ZEEKVER=5.0.8
ARG BUILD_TYPE=Release

RUN mkdir /zeekbuild

WORKDIR /zeekbuild

RUN wget https://download.zeek.org/zeek-$ZEEKVER.tar.gz && tar zxvf zeek-$ZEEKVER.tar.gz
RUN cd zeek-$ZEEKVER && \
    ./configure --prefix=/opt/zeek --spooldir=/nsm/zeek/spool --logdir=/nsm/zeek/logs --enable-jemalloc --build-type=$BUILD_TYPE && \
    make -j4 && make install 
RUN yum install -y glibc-common
RUN /opt/zeek/bin/zkg install --force ja3 && \
    /opt/zeek/bin/zkg install --force https://github.com/JustinAzoff/zeek-jemalloc-profiling && \
    /opt/zeek/bin/zkg install --force hassh && \
    /opt/zeek/bin/zkg install --force https://github.com/TOoSmOotH/zeek-af_packet-plugin --version=master && \
    /opt/zeek/bin/zkg install --force zeek-community-id && \
    #/opt/zeek/bin/zkg install --force bzar && \
    /opt/zeek/bin/zkg install --force --skiptests https://github.com/mmguero-dev/bzar --version=master && \
    /opt/zeek/bin/zkg install --force --skiptests icsnpp-bacnet && \
    /opt/zeek/bin/zkg install --force --skiptests icsnpp-bsap && \
    /opt/zeek/bin/zkg install --force --skiptests icsnpp-ethercat && \
    /opt/zeek/bin/zkg install --force --skiptests icsnpp-enip && \
    /opt/zeek/bin/zkg install --force --skiptests icsnpp-opcua-binary && \
    sed -i 's|-|_|g' /opt/zeek/share/zeek/site/icsnpp-opcua-binary/main.zeek && \
    /opt/zeek/bin/zkg install --force --skiptests icsnpp-dnp3 && \
    /opt/zeek/bin/zkg install --force --skiptests icsnpp-modbus && \
    git clone https://github.com/cisagov/icsnpp-s7comm && \
    /opt/zeek/bin/zkg install --force --skiptests icsnpp-s7comm && \
    git clone https://github.com/amzn/zeek-plugin-profinet && \
    /opt/zeek/bin/zkg install --force --skiptests zeek-plugin-profinet && \
    git clone https://github.com/amzn/zeek-plugin-tds && \
    /opt/zeek/bin/zkg install --force --skiptests zeek-plugin-tds && \
    /opt/zeek/bin/zkg install --force --skiptests zeek-spicy-wireguard && \ 
    /opt/zeek/bin/zkg install --force --skiptests zeek-spicy-stun && \
    /opt/zeek/bin/zkg install --force --skiptests https://github.com/iamckn/oui-logging && \
    /bin/python3 /opt/zeek/share/zeek/site/oui-logging/oui.py /opt/zeek/share/zeek/site/oui-logging/oui.dat && \
    rm -rf /opt/zeek/var/lib/zkg/testing && \
    rm -rf /opt/zeek/var/lib/zkg/scratch
RUN groupadd --gid 937 zeek  && \
    adduser --uid 937 --gid 937 --home-dir /opt/zeek --no-create-home zeek && \
    chown -R 937:937 /opt/zeek && \
    chown -R 937:937 /nsm/zeek
    
FROM ghcr.io/security-onion-solutions/rockylinux:9

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Zeek running in a docker with AF_Packet 3.2.0 for use with Security Onion."

# Common CentOS layer
RUN dnf update -y && \
    dnf -y install epel-release bash findutils libpcap iproute && \
    dnf -y install numactl libnl3 libdnet gdb python3 && \
    dnf -y erase epel-release && dnf clean all && rm -rf /var/cache/dnf && \
    dnf -y install libunwind-devel && \
    groupadd --gid 937 zeek  && \
    adduser --uid 937 --gid 937 --home-dir /opt/zeek --no-create-home zeek

RUN rpm -i https://repo.securityonion.net/file/so-repo/2.4/securityonion-jemalloc-5.3.0_1.rpm

COPY --from=builder /nsm/zeek /nsm/zeek
COPY --from=builder /opt/zeek /opt/zeek

# Copy over the entry script.
COPY files/zeek.sh /usr/local/sbin/zeek.sh
RUN chmod +x /usr/local/sbin/zeek.sh
RUN rpm -i https://github.com/axellioinc/fx-libpcap/releases/download/fxlibpcap-1.9.1/fx-libpcap-1.9.1-1.el7.x86_64.rpm

HEALTHCHECK --interval=10m --timeout=2m CMD /opt/zeek/bin/zeekctl status || (kill -s 15 -1 && (sleep 30; kill -s 9 -1))

ENTRYPOINT ["/usr/local/sbin/zeek.sh"]
