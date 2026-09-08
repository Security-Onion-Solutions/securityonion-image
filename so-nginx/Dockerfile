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

# Navigator build stage
FROM  ghcr.io/security-onion-solutions/node:26.3.1-alpine AS navigator-builder

# Navigator v5.3.0
ARG NAVIGATOR_COMMIT=f40b225282c9c349bbe4a56f7ada142d79b705a3
ARG ATTACK_VERSION=16.1

RUN apk add git wget

# Clone Navigator and pin to commit hash
RUN git clone https://github.com/mitre-attack/attack-navigator.git && \
    git -C attack-navigator -c advice.detachedHead=false checkout ${NAVIGATOR_COMMIT}

# Download a pinned version of Enterprise ATT&CK compatible with Navigator version
RUN wget -O /tmp/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-${ATTACK_VERSION}.json

WORKDIR /attack-navigator/nav-app/

RUN npm ci && npx ng build

# Delete base href line from index html to fix url path issues
RUN sed -i '/<base href="\/"\/>/d' ./dist/browser/index.html

###################################

FROM  ghcr.io/security-onion-solutions/nginx:1.31.2-alpine
HEALTHCHECK --interval=5m --timeout=3s CMD curl --fail http://localhost/ || exit 1
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description "Security Onion Core Functions Docker"

ARG CYBERCHEF_VERSION=11.3.0
ARG CYBERCHEF_HASH=d24ba1afce2e3a080308b5df7db033332fe94a1a
ARG CYBERCHEF_VERIFY=98ba94991dc3ed5f58a42f2c5d3a61d11e741c74bd438cca9f7e4be3fdbd9e56

RUN mkdir -p /opt/socore/html/navigator
COPY --from=navigator-builder /attack-navigator/nav-app/dist/browser /opt/socore/html/navigator
COPY --from=navigator-builder /tmp/enterprise-attack.json /opt/socore/html/navigator/assets/mitre/enterprise-attack.json

RUN mkdir -p /opt/socore/html/cyberchef && \
    wget -O /tmp/CyberChef.zip https://github.com/gchq/CyberChef/releases/download/v${CYBERCHEF_VERSION}/CyberChef_${CYBERCHEF_HASH}.zip && \
    sha256sum /tmp/CyberChef.zip | grep ${CYBERCHEF_VERIFY} && \
    unzip -o /tmp/CyberChef.zip -d /opt/socore/html/cyberchef && \
    mv /opt/socore/html/cyberchef/CyberChef_v${CYBERCHEF_VERSION}.html /opt/socore/html/cyberchef/index.html && \
    rm -f /tmp/CyberChef.zip

EXPOSE 80
EXPOSE 443
