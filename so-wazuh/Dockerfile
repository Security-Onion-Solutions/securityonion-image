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

FROM ubuntu:18.04

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Wazuh Manager and API running in Docker container for use with Security Onion"

ENV WAZUH_VERSION="3.10.2-1"

# Common Ubuntu layer
RUN apt-get update && \
    apt-get --no-install-recommends --no-install-suggests -y install \
        curl \
        ca-certificates \
        build-essential

RUN groupadd -g 945 ossec && \
    useradd -u 943 -g 945 -d /var/ossec -s /sbin/nologin ossecm && \
    useradd -u 944 -g 945 -d /var/ossec -s /sbin/nologin ossecr && \
    useradd -u 945 -g 945 -d /var/ossec -s /sbin/nologin ossec

RUN apt-get --no-install-recommends --no-install-suggests -y install \
    gpg gpg-agent \
    apt-transport-https \
    lsb-release 

RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
RUN echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends --no-install-suggests -y install openssl postfix bsd-mailx python3-boto python3-pip  \
    apt-transport-https vim expect nodejs python3-cryptography mailutils libsasl2-modules wazuh-manager=${WAZUH_VERSION} \
    wazuh-api=${WAZUH_VERSION} && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -f \
    /var/ossec/logs/alerts/*/*/*.log && rm -f /var/ossec/logs/alerts/*/*/*.json && rm -f \
    /var/ossec/logs/archives/*/*/*.log && rm -f /var/ossec/logs/archives/*/*/*.json && rm -f \
    /var/ossec/logs/firewall/*/*/*.log && rm -f /var/ossec/logs/firewall/*/*/*.json

# Add OSSEC config
COPY config/securityonion_rules.xml /var/ossec/ruleset/rules/securityonion_rules.xml
COPY config/ossec.conf /var/ossec/etc/ossec.conf

# Adding first run script.
COPY config/data_dirs.env /data_dirs.env
COPY config/init.bash /init.bash

RUN chmod 755 /init.bash && \
    sync && /init.bash && \
    sync && rm /init.bash

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
