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

FROM ghcr.io/security-onion-solutions/centos:7 as builder

RUN yum update -y && \
    yum -y install epel-release bash libpcap iproute && \
    yum -y install jemalloc numactl libnl3 libdnet gdb GeoIP python-ipaddress python3 && \
    yum -y install libpcap-devel openssl-devel zlib-devel jemalloc-devel python3-devel kernel-devel kernel-headers &&\
    yum group install -y "Development Tools" && \
    pip3 install GitPython semantic-version && \
    yum -y install centos-release-scl && \
    yum -y install devtoolset-7-gcc-c++ cmake3 wget && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum

ENV ZEEKVER=4.0.3
ARG BUILD_TYPE=Release

RUN mkdir /zeekbuild

WORKDIR /zeekbuild

RUN wget https://download.zeek.org/zeek-$ZEEKVER.tar.gz && tar zxvf zeek-$ZEEKVER.tar.gz
RUN source scl_source enable devtoolset-7 && cd zeek-$ZEEKVER && \
    ./configure --prefix=/opt/zeek --spooldir=/nsm/zeek/spool --logdir=/nsm/zeek/logs --enable-jemalloc --build-type=$BUILD_TYPE && \
    make -j8 && make install 
RUN yes | /opt/zeek/bin/zkg install ja3
RUN yes | /opt/zeek/bin/zkg install hassh
RUN source scl_source enable devtoolset-7 && yes | /opt/zeek/bin/zkg install https://github.com/TOoSmOotH/zeek-af_packet-plugin --version=master
RUN source scl_source enable devtoolset-7 && yes | /opt/zeek/bin/zkg install zeek-community-id

FROM ghcr.io/security-onion-solutions/centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Zeek running in a docker with AF_Packet 1.4 for use with Security Onion."

COPY --from=builder /nsm/zeek /nsm/zeek
COPY --from=builder /opt/zeek /opt/zeek
# Common CentOS layer
RUN yum update -y && \
    yum -y install epel-release bash libpcap iproute && \
    yum -y install jemalloc numactl libnl3 libdnet gdb GeoIP python-ipaddress python3 && \
    yum -y erase epel-release && yum clean all && rm -rf /var/cache/yum && \
    groupadd --gid 937 zeek  && \
    adduser --uid 937 --gid 937 --home-dir /opt/zeek --no-create-home zeek && \
    chown -R 937:937 /opt/zeek && \
    chown -R 937:937 /nsm/zeek

VOLUME ["/nsm/zeek/logs", "/nsm/zeek/spool", "/opt/zeek/share/bro", "/opt/zeek/etc/"]

# Copy over the entry script.
COPY files/zeek.sh /usr/local/sbin/zeek.sh
RUN chmod +x /usr/local/sbin/zeek.sh

HEALTHCHECK --interval=10m --timeout=2m CMD /opt/zeek/bin/zeekctl status || (kill -s 15 -1 && (sleep 30; kill -s 9 -1))

ENTRYPOINT ["/usr/local/sbin/zeek.sh"]
