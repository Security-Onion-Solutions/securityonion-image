# This Dockerfile was based on the official Elasticsearch Docker image:
# https://github.com/elastic/elasticsearch-docker

# Copyright 2014,2015,2016,2017,2019,2020 Security Onion Solutions, LLC

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
ARG FLAVOR
ARG VERSION

FROM docker.elastic.co/elasticsearch/$FLAVOR:$VERSION

RUN groupmod -g 930 elasticsearch && \
    usermod -u 930 -g 930 elasticsearch

WORKDIR /usr/share/elasticsearch

RUN set -ex && for esdirs in config data logs; do \
        mkdir -p "$esdirs"; \
        chown -R elasticsearch:elasticsearch "$esdirs"; \
    done

COPY elasticsearch.yml log4j2.properties config/
COPY bin/es-docker bin/es-docker
#COPY plugins/ingest-community-id  /usr/share/elasticsearch/plugins

RUN chown elasticsearch:elasticsearch config/elasticsearch.yml config/log4j2.properties bin/es-docker && \
    chmod 0750 bin/es-docker

USER elasticsearch
CMD ["/bin/bash", "bin/es-docker"]
