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

FROM python:3-alpine

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Domainstats running in Docker container for use with Security Onion"

ARG GID=936
ARG UID=936
ARG USERNAME=domainstats

RUN apk add --no-cache --virtual .build-deps\
    shadow \
    git

RUN apk add --no-cache bash

RUN groupadd --gid ${GID} ${USERNAME} && \
    useradd --uid ${UID} --gid ${GID} --no-create-home ${USERNAME}

RUN cd /opt && \
	git clone -b domain_stats_1 https://github.com/MarkBaggett/domain_stats.git && \
	mkdir /var/log/domain_stats && \
	ln -sf /dev/stderr /var/log/domain_stats/domain_stats.log && \
	chown -R ${UID}:${GID} /opt/domain_stats

RUN pip install --no-cache-dir six python-whois
RUN apk del .build-deps

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 20000
STOPSIGNAL SIGTERM

USER ${USERNAME}

ENTRYPOINT [ "/entrypoint.sh" ]
