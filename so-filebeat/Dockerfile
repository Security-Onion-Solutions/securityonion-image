# This Dockerfile was based on the official Filebeat Docker image:
# https://hub.docker.com/r/elastic/filebeat/

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

FROM docker.elastic.co/beats/$FLAVOR:$VERSION
USER root
# Add entrypoint wrapper script
ADD files/docker-entrypoint /usr/local/bin
RUN chmod 755 /usr/local/bin/docker-entrypoint

# Provide a non-root user.
RUN groupadd --gid 939 socore && \
    useradd -M --uid 939 --gid 939 --home /usr/share/filebeat socore && \
    groupadd -g 945 ossec && \
    usermod -a -G ossec socore

WORKDIR /usr/share/filebeat
RUN chown -R root:socore . && \
    find /usr/share/filebeat -type d -exec chmod 0750 {} \; && \
    find /usr/share/filebeat -type f -exec chmod 0640 {} \; && \
    chmod 0750 filebeat && \
    chmod 0770 modules.d && \
    chmod 0770 data logs
USER socore
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["-c", "/usr/share/filebeat/filebeat.yml"]
