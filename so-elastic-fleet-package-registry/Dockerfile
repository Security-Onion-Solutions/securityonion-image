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

FROM docker.elastic.co/package-registry/distribution:8.17.3 AS original_image

# Add bash because it is not included in the new default base image of wolfi-base (default sh shell)
RUN apk add --no-cache bash coreutils

# Remove unsupported packages
COPY scripts /scripts
COPY versions /versions
RUN bash /scripts/maintained-versions.sh && bash /scripts/unsupported-integrations.sh && rm -rf /scripts

# Cleanup unneeded packages, keeping the two most recent versons of each one
# Except for endpoint packages, keep all versions
RUN cd /packages/package-storage/ \
&& rm -rf suricata-* zeek-* dga-* endpoint*dev* endpoint*next* *preview* *beta* \
&& cd /packages/package-storage/ && LIST=$(ls --ignore="endpoint-*" | awk -F'[-]' '{print $1}' | sort | uniq ) \
&& for item in $LIST; do ls $item-*.zip | cut -d '-' -f 2 | tr - \~ | sort -V | tr \~ - | head -n-1 | xargs -I {} echo "$item-"{} |  xargs -r rm -fr; done \
&& for item in $LIST; do ls $item-*.zip.sig | cut -d '-' -f 2 | tr - \~ | sort -V | tr \~ - | head -n-1 | xargs -I {} echo "Removing signature file: $item-"{} |  xargs -r rm -fr; done \
&& mv /packages/saved-packages/* /packages/package-storage/

FROM scratch

COPY --from=original_image / /
WORKDIR /package-registry

EXPOSE 8080
ENTRYPOINT ["./package-registry"]

ENV EPR_ADDRESS=0.0.0.0:8080

HEALTHCHECK --interval=1m --retries=30 CMD curl --silent --fail localhost:8080/health || exit 1
