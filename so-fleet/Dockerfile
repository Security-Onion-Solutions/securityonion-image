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

FROM ghcr.io/security-onion-solutions/alpine:3.12.1
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Fleet running in Docker container for use with Security Onion"

RUN apk --update add ca-certificates unzip curl bash
RUN mkdir -p /tmp/fleet && cd /tmp/fleet \
&& curl -OL  https://github.com/fleetdm/fleet/releases/download/3.9.0/fleet.zip \
&& unzip fleet.zip 'linux/*' \
&& cp linux/fleet /usr/bin/fleet \
&& cp linux/fleetctl /usr/bin/fleetctl \
&& cd /tmp && rm -rf /tmp/fleet

COPY startfleet.sh /startfleet.sh
RUN chmod +x /startfleet.sh

ENTRYPOINT ["/startfleet.sh"]
