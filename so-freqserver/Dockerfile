FROM python:3-alpine

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Freqserver running in Docker container for use with Security Onion"

ARG GID=935
ARG UID=935
ARG USERNAME=freqserver

RUN apk add --no-cache --virtual .build-deps\
    shadow \
    git 

RUN apk add --no-cache bash

RUN groupadd --gid ${GID} ${USERNAME} && \
    useradd --uid ${UID} --gid ${GID} --no-create-home ${USERNAME}

RUN mkdir -p /opt/freq_server && \
	cd /opt/freq_server && \
	git clone https://github.com/MarkBaggett/freq.git && \
	chown -R ${UID}:${GID} /opt/freq_server && \
	mkdir /var/log/freq_server && \
	ln -sf /dev/stderr /var/log/freq_server/freq_server.log

RUN pip install --no-cache-dir six
RUN apk del .build-deps

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 10004
STOPSIGNAL SIGTERM

USER ${USERNAME}

ENTRYPOINT [ "/entrypoint.sh"]