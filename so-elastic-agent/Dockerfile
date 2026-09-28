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
COPY --from=servers --chown=elastic-agent:elastic-agent /fleet-export/ /tmp/fleet-export/
COPY --from=servers /so-meta/ /tmp/servers-meta/
RUN set -euo pipefail; \
    check_commit() { \
      role="$1"; dir="$2"; \
      active="$(cat "$dir/.elastic-agent.active.commit")"; \
      hash="$(awk '/^[[:space:]]+hash:[[:space:]]+/ {print $2; exit}' "$dir/manifest.yaml")"; \
      for got in "$active" "$hash"; do \
        case "$got" in "$AGENT_COMMIT"*) continue ;; esac; \
        case "$AGENT_COMMIT" in "$got"*) continue ;; esac; \
        echo "$role commit mismatch: expected $AGENT_COMMIT got $got" >&2; \
        exit 1; \
      done; \
      echo "$role commit ok: $active"; \
    }; \
    check_commit slim /usr/share/elastic-agent; \
    check_commit servers /tmp/servers-meta; \
    components="$(echo /usr/share/elastic-agent/data/elastic-agent-*/components)"; \
    test -d "$components"; \
    cp -a /tmp/fleet-export/fleet-server /tmp/fleet-export/fleet-server.spec.yml "$components/"; \
    chmod 0755 "$components/fleet-server"; \
    chmod 0644 "$components/fleet-server.spec.yml"; \
    chown elastic-agent:elastic-agent "$components/fleet-server" "$components/fleet-server.spec.yml"; \
    for f in "$components"/*; do \
      case "$(basename "$f")" in \
        elastic-otel-collector|elastic-otel-collector.spec.yml|fleet-server|fleet-server.spec.yml) ;; \
        *) rm -rf "$f" ;; \
      esac; \
    done; \
    test -x /usr/share/elastic-agent/elastic-agent; \
    test -x "$components/elastic-otel-collector"; \
    test -x "$components/fleet-server"; \
    test -f "$components/fleet-server.spec.yml"; \
    for f in "$components"/*; do \
      case "$(basename "$f")" in \
        elastic-otel-collector|elastic-otel-collector.spec.yml|fleet-server|fleet-server.spec.yml) ;; \
        *) echo "unexpected component: $f" >&2; exit 1 ;; \
      esac; \
    done; \
    echo "=== components ==="; \
    ls -la "$components"; \
    rm -rf /tmp/fleet-export /tmp/servers-meta

USER elastic-agent
