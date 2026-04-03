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
ARG GID=948
ARG UID=948
ARG USERNAME=elastic-agent-pr

FROM docker.elastic.co/package-registry/distribution:$VERSION AS original_image

ARG GID
ARG UID
ARG USERNAME

USER root
# Add bash because it is not included in the new default base image of wolfi-base (default sh shell)
RUN apk add --no-cache bash shadow

# add elastic-agent-pr user / group with no login shell or created home dir
RUN groupadd -g ${GID} ${USERNAME} && \
    useradd -u ${UID} -g ${GID} ${USERNAME} -M -s /sbin/nologin

# Remove unsupported packages
COPY scripts /scripts
COPY versions /versions
# Keep copy of integrations listed in ./versions/$VERSION. Helps avoid issues during the ES upgrade process.
# in the future this will also allow for downgrading integration versions.
RUN bash /scripts/maintained-versions.sh && bash /scripts/unsupported-integrations.sh && rm -rf /scripts

# Cleanup unneeded packages, keeping the most recent verson of each one
# Except for endpoint packages, keep all versions
RUN cd /packages/package-storage/ \
&& rm -rf suricata-* zeek-* dga-* endpoint*dev* endpoint*next* *preview* *beta* \
&& cd /packages/package-storage/ && LIST=$(ls | grep -v "^endpoint-" | awk -F'[-]' '{print $1}' | sort | uniq ) \
&& for item in $LIST; do ls $item-*.zip | cut -d '-' -f 2 | tr - \~ | sort -V | tr \~ - | head -n-1 | xargs -I {} echo "$item-"{} |  xargs -r rm -fr; done \
&& for item in $LIST; do ls $item-*.zip.sig | cut -d '-' -f 2 | tr - \~ | sort -V | tr \~ - | head -n-1 | xargs -I {} echo "Removing signature file: $item-"{} |  xargs -r rm -fr; done \
&& mv /packages/saved-packages/* /packages/package-storage/

FROM scratch

ARG UID
ARG GID

USER ${UID}:${GID}

COPY --from=original_image / /
WORKDIR /package-registry

EXPOSE 8080
ENTRYPOINT ["./package-registry"]

ENV EPR_ADDRESS=0.0.0.0:8080

HEALTHCHECK --interval=1m --retries=30 CMD curl --silent --fail localhost:8080/health || exit 1
