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

FROM alpine:3

LABEL maintainer "Security Onion Solutions, LLC"

ARG GID=934
ARG UID=934
ARG USERNAME=curator

ENV LC_ALL=en_US.UTF-8

USER root

RUN apk --no-cache add python3 py-setuptools py-pip gcc libffi py-cffi python3-dev libffi-dev py-openssl musl-dev linux-headers openssl-dev && \
    pip install elasticsearch-curator && \
    apk del gcc python3-dev libffi-dev musl-dev linux-headers openssl-dev

RUN addgroup -g ${GID} ${USERNAME} && \
    adduser -u ${UID} -G ${USERNAME} -D -H ${USERNAME}

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER curator

ENTRYPOINT [ "/entrypoint.sh" ]
