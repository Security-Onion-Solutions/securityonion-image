#    Copyright Security Onion Solutions, LLC

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

FROM ghcr.io/security-onion-solutions/oraclelinux:9

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Kafka running in a docker container for use with Security Onion"

ARG KAFKA_DOWNLOAD=https://downloads.apache.org/kafka/3.7.0/
ARG KAFKA_TARNAME=kafka_2.13-3.7.0

RUN dnf update -y && \
    dnf install -y java-11-openjdk java-11-openjdk-devel curl && \
    dnf clean all

WORKDIR /

RUN groupadd --gid 960 kafka && \
    adduser --uid 960 --gid 960 kafka

RUN curl -O ${KAFKA_DOWNLOAD}${KAFKA_TARNAME}.tgz && \
    tar -xzf ${KAFKA_TARNAME}.tgz

RUN rm -f ${KAFKA_TARNAME}.tgz && \
    mv ${KAFKA_TARNAME} kafka && \
    chown -R 960:960 kafka

ENTRYPOINT ["/kafka/bin/kafka-server-start.sh", "/kafka/config/kraft/server.properties"]
