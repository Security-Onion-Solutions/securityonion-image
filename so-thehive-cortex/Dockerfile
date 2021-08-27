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
LABEL description="Cortex Docker container for use with Security Onion"

# Common Ubuntu layer
RUN apt-get update && \
    apt-get --no-install-recommends --no-install-suggests -y install \
        curl \
        ca-certificates \
        build-essential

RUN apt-get --no-install-recommends --no-install-suggests -y install \
    libffi-dev \
    python3 \
    python3-dev \
    python3-pip \
    libfuzzy-dev \
    git \
    gpg gpg-agent \
    exiftool \
    locales \
    libmagic1 \
    netbase \
    whois

RUN locale-gen en_US.UTF-8

ENV LC_ALL=en_US.UTF-8
ENV LANG=en_US.UTF-8

RUN echo 'deb https://deb.thehive-project.org release main' | tee -a /etc/apt/sources.list.d/thehive-project.list && \
    curl -s https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | apt-key add - > /dev/null 2>&1

RUN apt-get update && apt-get --no-install-recommends --no-install-suggests -y install cortex

RUN groupmod -g 939 cortex \
  && usermod -u 939 -g 939 cortex \
  && ls -la /opt \
  && ls -la /opt/cortex
RUN mkdir -p /opt/cortex/conf
RUN chown -R cortex /opt/cortex \
     /var/log/cortex
     
RUN git clone https://github.com/TheHive-Project/Cortex-Analyzers

RUN pip3 install setuptools wheel && \
    python3 -m pip install -U pip
RUN for i in $(find Cortex-Analyzers -not -path  "Cortex-Analyzers/analyzers/MalwareClustering/*" -name 'requirements.txt'); do pip3 install -r $i || exit 1 ; done     
USER cortex

ENTRYPOINT ["/opt/cortex/bin/cortex"]
