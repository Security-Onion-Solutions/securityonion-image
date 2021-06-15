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

FROM ghcr.io/security-onion-solutions/python:3-alpine

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="IDSTools for downloading rules"

ARG GID=939
ARG UID=939
ARG USERNAME=socore
ARG VERSION=0.6.3

RUN apk add --no-cache --virtual .build-deps\
    shadow

RUN apk add --no-cache bash

RUN mkdir -p /opt/so/idstools/bin && mkdir /opt/so/idstools/etc
COPY entrypoint.sh /opt/so/idstools/bin
RUN chmod +x /opt/so/idstools/bin/entrypoint.sh && chown -R ${UID}:${GID} /opt/so/idstools

RUN groupadd --gid ${GID} ${USERNAME} && \
    useradd --uid ${UID} --gid ${GID} \
    --home-dir /opt/so --no-create-home ${USERNAME}

RUN pip install https://github.com/jasonish/py-idstools/archive/master.zip

RUN apk del .build-deps

USER ${USERNAME}
WORKDIR /opt/so/idstools/bin
ENTRYPOINT ["./entrypoint.sh"]
