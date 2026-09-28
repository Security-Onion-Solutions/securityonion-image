# This Dockerfile was based on the official Elastic Agent Docker image:
# https://hub.docker.com/r/elastic/elastic-agent

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
# Pin to package.hash / .elastic-agent.active.commit in the official images
# These sources are used to verify the agent commit, from both slim and full image
# - /usr/share/elastic-agent/.elastic-agent.active.commit
# - package.hash in /usr/share/elastic-agent/manifest.yaml
ARG AGENT_COMMIT=7a92f7b9479cbfbcb88c94c398660e981dee3d14

FROM docker.elastic.co/elastic-agent/elastic-agent:$VERSION AS servers
USER root
RUN mkdir -p /fleet-export /so-meta && \
cp -a /usr/share/elastic-agent/data/elastic-agent-*/components/fleet-server \
/usr/share/elastic-agent/data/elastic-agent-*/components/fleet-server.spec.yml \
/fleet-export/ && \
cp -a /usr/share/elastic-agent/.elastic-agent.active.commit \
/usr/share/elastic-agent/manifest.yaml \
/so-meta/ && \
test -x /fleet-export/fleet-server && \
test -f /fleet-export/fleet-server.spec.yml

FROM docker.elastic.co/elastic-agent/elastic-agent-slim:$VERSION AS slim

# Kept: elastic-agent, elastic-otel-collector, fleet-server.
# Removed: pf-host-agent, osquery, defend, cloudbeat (not used for heavy/fleet node)
ARG AGENT_COMMIT
USER root
COPY scripts /tmp/so-elastic-agent/scripts
COPY --from=servers --chown=elastic-agent:elastic-agent /fleet-export/ /tmp/fleet-export/
COPY --from=servers /so-meta/ /tmp/servers-meta/
RUN microdnf install -y python3 && \
    python3 -m unittest discover -s /tmp/so-elastic-agent/scripts -v && \
    python3 /tmp/so-elastic-agent/scripts/assemble.py \
      --agent-home /usr/share/elastic-agent \
      --agent-commit "$AGENT_COMMIT" \
      --fleet-export /tmp/fleet-export \
      --also-verify /tmp/servers-meta && \
    microdnf remove -y python3 python3-libs python-unversioned-command python3-pip-wheel expat gdbm-libs mpdecimal && \
    microdnf clean all && \
    rm -rf /tmp/so-elastic-agent /tmp/fleet-export /tmp/servers-meta /root/.cache /var/cache/dnf

USER elastic-agent
