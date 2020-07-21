FROM centos:7

# Originally developed by Justin Henderson justin@hasecuritysolutions.com
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
	chown -R domainstats: /opt/domain_stats

USER domainstats

EXPOSE 20000

STOPSIGNAL SIGTERM

CMD /usr/bin/python3 /opt/domain_stats/domain_stats.py -ip 0.0.0.0 20000 -a /opt/domain_stats/top-1m.csv --preload 0
