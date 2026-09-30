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
# Confirm slim and full images are the same Elastic build so copied fleet-server
# matches. Compared to each other (not a pinned SHA) using:
# - /usr/share/elastic-agent/.elastic-agent.active.commit
# - package.hash in /usr/share/elastic-agent/manifest.yaml

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
USER root
COPY --from=servers --chown=elastic-agent:elastic-agent /fleet-export/ /tmp/fleet-export/
COPY --from=servers /so-meta/ /tmp/servers-meta/
RUN set -euo pipefail; \
    read_commit() { \
      dir="$1"; which="$2"; \
      if [ "$which" = active ]; then \
        got="$(cat "$dir/.elastic-agent.active.commit")"; \
      else \
        got="$(awk '/^[[:space:]]+hash:[[:space:]]+/ {print $2; exit}' "$dir/manifest.yaml")"; \
      fi; \
      if [ -z "$got" ]; then \
        echo "empty $which commit in $dir" >&2; \
        exit 1; \
      fi; \
      printf '%s' "$got"; \
    }; \
    commits_match() { \
      a="$1"; b="$2"; \
      case "$a" in "$b"*) return 0 ;; esac; \
      case "$b" in "$a"*) return 0 ;; esac; \
      echo "slim/servers commit mismatch: $a vs $b" >&2; \
      exit 1; \
    }; \
    slim_active="$(read_commit /usr/share/elastic-agent active)"; \
    slim_hash="$(read_commit /usr/share/elastic-agent hash)"; \
    servers_active="$(read_commit /tmp/servers-meta active)"; \
    servers_hash="$(read_commit /tmp/servers-meta hash)"; \
    commits_match "$slim_active" "$servers_active"; \
    commits_match "$slim_hash" "$servers_hash"; \
    echo "slim/servers commit ok: $slim_active"; \
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
