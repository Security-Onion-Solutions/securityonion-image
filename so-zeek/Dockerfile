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

RUN dnf -y install dnf-plugins-core && \
    dnf config-manager --enable ol9_codeready_builder && \
    dnf update -y && \
    dnf -y install epel-release bash libpcap iproute wget cmake swig && \
    dnf -y install jemalloc numactl libnl3 libdnet gdb git && \
    dnf -y install libpcap-devel openssl-devel zlib-devel jemalloc-devel python3-devel kernel-devel kernel-headers && \
    dnf group install -y "Development Tools" && \
    yum install -y glibc-common && \
    pip3 install GitPython semantic-version requests && \
    dnf -y erase epel-release && dnf clean all && rm -rf /var/cache/dnf

RUN mkdir /opensslbuild
WORKDIR /opensslbuild
RUN wget https://www.openssl.org/source/old/3.0/openssl-3.0.1.tar.gz && tar zxvf openssl-3.0.1.tar.gz

WORKDIR /opensslbuild/openssl-3.0.1
RUN dnf -y install perl && \
    echo 'yes' | cpan && \
    cpan Test::More && \
    ./Configure --prefix=/usr/local/ssl --openssldir=/usr/local/ssl enable-fips && \
    time make -j4 && \
    time make install && \
    /usr/local/ssl/bin/openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf -module /usr/local/ssl/lib64/ossl-modules/fips.so

WORKDIR /

ENV ZEEKVER=6.0.1
ARG BUILD_TYPE=Release

RUN mkdir /zeekbuild

WORKDIR /zeekbuild

RUN wget https://download.zeek.org/zeek-$ZEEKVER.tar.gz && tar zxvf zeek-$ZEEKVER.tar.gz
RUN cd zeek-$ZEEKVER && \
    ./configure --prefix=/opt/zeek --spooldir=/nsm/zeek/spool --logdir=/nsm/zeek/logs --enable-jemalloc --build-type=$BUILD_TYPE --with-openssl=/usr/local/ssl && \
    time make -j4 && time make install
RUN /opt/zeek/bin/zkg install --force ja3 && \
    /opt/zeek/bin/zkg install --force hassh && \
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
    #git clone https://github.com/amzn/zeek-plugin-profinet && \
    #/opt/zeek/bin/zkg install --force --skiptests zeek-plugin-profinet && \
    #git clone https://github.com/amzn/zeek-plugin-tds && \
    #/opt/zeek/bin/zkg install --force --skiptests zeek-plugin-tds && \
    /opt/zeek/bin/zkg install --force --skiptests zeek-spicy-wireguard && \
    /opt/zeek/bin/zkg install --force --skiptests zeek-spicy-stun && \
    /opt/zeek/bin/zkg install --force --skiptests https://github.com/iamckn/oui-logging && \
    /bin/python3 /opt/zeek/share/zeek/site/oui-logging/oui.py /opt/zeek/share/zeek/site/oui-logging/oui.dat && \
    rm -rf /opt/zeek/var/lib/zkg/testing && \
    rm -rf /opt/zeek/var/lib/zkg/scratch && \
    rm -rf /zeekbuild
RUN groupadd --gid 937 zeek  && \
    adduser --uid 937 --gid 937 --home-dir /opt/zeek --no-create-home zeek && \
    chown -R 937:937 /opt/zeek && \
    chown -R 937:937 /nsm/zeek && \
    chown -R 937:937 /usr/local/ssl

FROM ghcr.io/security-onion-solutions/oraclelinux:9

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Zeek running in docker for use with Security Onion"

# Common CentOS layer
RUN dnf update -y && \
    dnf -y install epel-release bash findutils libpcap iproute && \
    dnf -y install jemalloc numactl libnl3 libdnet gdb python3 && \
    dnf -y install libunwind-devel && \
    dnf -y erase epel-release && dnf clean all && rm -rf /var/cache/dnf && \
    groupadd --gid 937 zeek  && \
    adduser --uid 937 --gid 937 --home-dir /opt/zeek --no-create-home zeek

COPY --from=builder /nsm/zeek /nsm/zeek
COPY --from=builder /opt/zeek /opt/zeek
COPY --from=builder /usr/local/ssl/ /usr/local/ssl

# Copy over the entry script.
COPY files/zeek.sh /usr/local/sbin/zeek.sh
RUN chmod +x /usr/local/sbin/zeek.sh
RUN rpm -Uvh https://github.com/axellioinc/fx-libpcap/releases/download/px3_1.9.1-3/fx-libpcap-1.9.1-3.el7_9.x86_64.rpm

HEALTHCHECK --interval=10m --timeout=2m CMD /opt/zeek/bin/zeekctl status || (kill -s 15 -1 && (sleep 30; kill -s 9 -1))

ENTRYPOINT ["/usr/local/sbin/zeek.sh"]
