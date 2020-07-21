# Copyright 2014,2015,2016,2017,2018 Security Onion Solutions, LLC

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

FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="IDSTools for downloading rules"

ARG GID=939
ARG UID=939
ARG USERNAME=socore
ARG VERSION=0.6.3

# Install epel
RUN yum -y install epel-release bash && yum clean all
RUN yum update -y && yum -y install python-idstools \
    && yum clean all && rm -rf /var/cache/yum

RUN apk add --no-cache bash

RUN mkdir -p /opt/so/idstools/bin && mkdir /opt/so/idstools/etc
COPY entrypoint.sh /opt/so/idstools/bin
RUN chmod +x /opt/so/idstools/bin/entrypoint.sh && chown -R ${UID}:${GID} /opt/so/idstools

RUN chmod +x /opt/so/idstools/bin/so-idstools.sh

RUN pip install idstools==${VERSION}

RUN apk del .build-deps

ENTRYPOINT ["/opt/so/idstools/bin/so-idstools.sh"]
