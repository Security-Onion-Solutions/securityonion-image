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


FROM docker.elastic.co/elasticsearch/elasticsearch:7.11.1

LABEL maintainer "Security Onion Solutions, LLC"

ENV PATH /usr/share/elasticsearch/bin:$PATH

WORKDIR /usr/share/elasticsearch

RUN groupadd -g 939 socore && adduser -u 939 -g 939 -d /usr/share/elasticsearch socore
RUN set -ex && for esdirs in config data logs; do \
        mkdir -p "$esdirs"; \
    done; \
    chown -R socore:socore /usr/share/elasticsearch

USER socore

COPY elasticsearch.yml config/
COPY log4j2.properties config/
COPY bin/es-docker bin/es-docker

USER root

RUN chown socore:socore config/elasticsearch.yml config/log4j2.properties bin/es-docker && \
    chmod 0750 bin/es-docker

USER socore
CMD ["/bin/bash", "bin/es-docker"]
