# Based off of https://github.com/wazuh/wazuh-docker
FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Wazuh Manager and API running in Docker container for use with Security Onion"

ENV WAZUH_VERSION="3.10.2-1"

RUN yum update -y

# Install pre-reqs
RUN yum install -y initscripts expect logrotate openssl

# Creating ossec users
RUN groupadd -g 945 ossec && \
    useradd -u 943 -g 945 -d /var/ossec -s /sbin/nologin ossecm && \
    useradd -u 944 -g 945 -d /var/ossec -s /sbin/nologin ossecr && \
    useradd -u 945 -g 945 -d /var/ossec -s /sbin/nologin ossec

# Add Wazuh repo
ADD config/repos.bash /repos.bash
RUN chmod +x /repos.bash
RUN /repos.bash

# Download wazuh-manager pkg
#RUN rpm -i https://packages.wazuh.com/yum/el/7/x86_64/wazuh-manager-2.0.1-1.el7.x86_64.rpm

# Install wazuh-manager
RUN yum install -y wazuh-manager-$WAZUH_VERSION

# Install nodejs and wazuh-api
RUN curl -sL https://rpm.nodesource.com/setup_8.x | bash -
RUN yum install -y nodejs

#RUN rpm -i https://packages.wazuh.com/yum/el/7/x86_64/wazuh-api-2.0.1-1.el7.x86_64.rpm
RUN yum install -y wazuh-api-$WAZUH_VERSION

RUN mkdir -p /var/ossec/logs/firewall && \
    mkdir -p /var/ossec/logs/ossec && \
    mkdir -p /var/ossec/queue && \
    mkdir -p /var/ossec/stats && \
    chown -R ossec:ossec /var/ossec

# Add OSSEC config
ADD config/securityonion_rules.xml /var/ossec/ruleset/rules/securityonion_rules.xml
ADD config/ossec.conf /var/ossec/etc/ossec.conf

# Adding first run script.
ADD config/data_dirs.env /data_dirs.env
ADD config/init.bash /init.bash

# Sync calls are due to https://github.com/docker/docker/issues/9547
RUN chmod 755 /init.bash &&\
    sync && /init.bash &&\
    sync && rm /init.bash

# Adding entrypoint
ADD config/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

RUN yum clean all
    
USER ossec

ENTRYPOINT ["/entrypoint.sh"]
