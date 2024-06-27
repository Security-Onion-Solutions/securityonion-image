# This Dockerfile was based on the official Elastic Agent Docker image:
# https://hub.docker.com/r/elastic/elastic-agent
# Copyright Security Onion Solutions, LLC
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
ARG VERSION
FROM docker.elastic.co/beats/elastic-agent:$VERSION
ARG GID=947
ARG UID=947
ARG USERNAME=elastic-agent
USER root 
RUN groupmod -g ${GID} ${USERNAME} && \
     usermod -u ${UID} -g ${GID} ${USERNAME}

RUN chown ${USERNAME}:${USERNAME} /usr/share/elastic-agent/data/elastic-agent-*/components/filebeat* /usr/share/elastic-agent/data/elastic-agent-*/components/metricbeat*
