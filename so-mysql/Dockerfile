# Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
FROM ghcr.io/security-onion-solutions/oraclelinux:7-slim

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="MySQL Server running in Docker container for use with Security Onion"

ARG GID=939
ARG UID=939
ARG USERNAME=socore

# Latest versions found here: https://repo.mysql.com/yum/mysql-5.7-community/el/7/x86_64/
ARG MYSQL_CE_VERSION=5.7.41-1
ARG MYSQL_SHELL_VERSION=8.0.32-1

# Install server
RUN yum install -y libpwquality \
  https://repo.mysql.com/yum/mysql-5.7-community/el/7/x86_64/mysql-community-common-${MYSQL_CE_VERSION}.el7.x86_64.rpm \
  https://repo.mysql.com/yum/mysql-5.7-community/el/7/x86_64/mysql-community-libs-${MYSQL_CE_VERSION}.el7.x86_64.rpm \
  https://repo.mysql.com/yum/mysql-5.7-community/el/7/x86_64/mysql-community-client-${MYSQL_CE_VERSION}.el7.x86_64.rpm \
  https://repo.mysql.com/yum/mysql-5.7-community/el/7/x86_64/mysql-community-server-${MYSQL_CE_VERSION}.el7.x86_64.rpm \
  https://repo.mysql.com/yum/mysql-tools-community/el/7/x86_64/mysql-shell-${MYSQL_SHELL_VERSION}.el7.x86_64.rpm \
  && yum clean all \
  && mkdir /docker-entrypoint-initdb.d

# Create socore user.
RUN groupadd --gid ${GID} ${USERNAME} && \
    useradd --uid ${UID} --gid ${GID} \
    --home-dir /opt/so --no-create-home ${USERNAME}

COPY docker-entrypoint.sh /entrypoint.sh
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh && chmod +x /healthcheck.sh
RUN chown -R 939:939 /var/lib/mysql && chown 939:939 -R /var/run/mysqld && chown -R 939:939 /var/lib/mysql-files
ENTRYPOINT ["/entrypoint.sh"]
HEALTHCHECK CMD /healthcheck.sh
EXPOSE 3306 33060
CMD ["mysqld"]
