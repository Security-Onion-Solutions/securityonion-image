# Copyright 2014,2015,2016,2017,2018 Security Onion Solutions, LLC

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

# Navigator build stage
FROM ghcr.io/security-onion-solutions/node:14-alpine as navigator-builder

ARG NAVIGATOR_VERSION=3.1

RUN apk add git && \
    git config --global advice.detachedHead false && \
    git clone -b "v${NAVIGATOR_VERSION}" https://github.com/mitre-attack/attack-navigator.git

WORKDIR /attack-navigator/nav-app/

RUN npm ci && npx ng build

# Delete base href line from index html to fix url path issues
RUN sed -i '/<base href="\/">/d' ./dist/index.html

###################################

FROM ghcr.io/security-onion-solutions/nginx:1.17-alpine

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Security Onion Core Functions Docker"

ARG CYBERCHEF_VERSION=9.27.2

RUN mkdir -p /opt/socore/html/navigator
COPY --from=navigator-builder /attack-navigator/nav-app/dist /opt/socore/html/navigator

RUN mkdir -p /opt/socore/html/cyberchef && \
    wget -O /tmp/CyberChef.zip https://github.com/gchq/CyberChef/releases/download/v${CYBERCHEF_VERSION}/CyberChef_v${CYBERCHEF_VERSION}.zip  && \
    unzip -o /tmp/CyberChef.zip -d /opt/socore/html/cyberchef && \
    mv /opt/socore/html/cyberchef/CyberChef_v${CYBERCHEF_VERSION}.html /opt/socore/html/cyberchef/index.html && \
    rm -f /tmp/CyberChef.zip

EXPOSE 80
EXPOSE 443
