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

FROM ghcr.io/security-onion-solutions/ubuntu:18.04

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="TheHive Docker container for use with Security Onion"

# Common Ubuntu layer
RUN apt-get update && \
    apt-get --no-install-recommends --no-install-suggests -y install \
      curl \
      wget \
      ca-certificates \
      build-essential

RUN apt-get --no-install-recommends --no-install-suggests -y install \
  gpg gpg-agent dirmngr \
  apt-transport-https
  
RUN echo 'deb https://deb.thehive-project.org release main' | tee -a /etc/apt/sources.list.d/thehive-project.list && \
    curl -s https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | apt-key add - > /dev/null 2>&1

RUN apt-get update \
  && apt-get -y install openjdk-8-jre \
  && apt-get -y install thehive

RUN groupmod -g 939 thehive \
  && usermod -u 939 -g 939 thehive \
  && ls -la /opt \
  && ls -la /opt/thehive
RUN mkdir -p /opt/thehive/conf
RUN chown -R thehive /opt/thehive \
    /var/log/thehive
RUN echo "play.http.secret.key=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 49)" >> /opt/thehive/conf/application.conf \
  && echo -e 'search.host = ["elasticsearch:9300"]\n\
    play.http.secret.key = ${?PLAY_SECRET}' >> /opt/thehive/conf/application.conf
COPY bin/so-thehive.sh /opt/thehive/bin/so-thehive.sh
RUN chmod +x /opt/thehive/bin/so-thehive.sh

USER thehive

EXPOSE 9000

ENTRYPOINT ["/opt/thehive/bin/so-thehive.sh"]
