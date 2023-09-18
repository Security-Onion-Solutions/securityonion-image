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

FROM docker.elastic.co/package-registry/distribution:$VERSION as original_image

# Cleanup unneeded packages, keeping the two most recent versons of each one
RUN cd /packages/package-storage/ \
&& rm -rf suricata-* zeek-* snort-* dga-* endpoint*preview* endpoint*dev* endpoint*next* \
&& cd /packages/package-storage/ && LIST=$(ls | awk -F'[-]' '{print $1}' | sort | uniq ) \
&& for item in $LIST; do ls $item-*.zip | cut -d '-' -f 2 | tr - \~ | sort -V | tr \~ - | head -n-2 | xargs -I {} echo "$item-"{} |  xargs rm -r; done

FROM scratch

COPY --from=original_image / /
WORKDIR /package-registry

EXPOSE 8080
ENTRYPOINT ["./package-registry"]

ENV EPR_ADDRESS=0.0.0.0:8080

HEALTHCHECK --interval=1m --retries=30 CMD curl --silent --fail localhost:8080/health || exit 1
