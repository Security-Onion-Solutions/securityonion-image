FROM ghcr.io/security-onion-solutions/ubuntu:18.04
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Grafana running in Docker container for use with Security Onion"

ARG GRAFANA_URL="https://dl.grafana.com/oss/release/grafana-8.3.1.linux-amd64.tar.gz"
ARG GF_UID="939"
ARG GF_GID="939"

# Common Ubuntu layer
RUN apt-get update && \
    apt-get --no-install-recommends --no-install-suggests -y install \
        curl \
        ca-certificates \
        build-essential

ENV PATH=/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GF_PATHS_CONFIG="/etc/grafana/grafana.ini" \
    GF_PATHS_DATA="/var/lib/grafana" \
    GF_PATHS_HOME="/usr/share/grafana" \
    GF_PATHS_LOGS="/var/log/grafana" \
    GF_PATHS_PLUGINS="/var/lib/grafana/plugins" \
    GF_PATHS_PROVISIONING="/etc/grafana/provisioning"

RUN apt-get install -y tar libfontconfig && \
    mkdir -p "$GF_PATHS_HOME/.aws" && \
    curl "$GRAFANA_URL" | tar xfvz - --strip-components=1 -C "$GF_PATHS_HOME" && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r -g $GF_GID socore && \
    useradd -r -u $GF_UID -g $GF_GID socore && \
    mkdir -p "$GF_PATHS_PROVISIONING/datasources" \
             "$GF_PATHS_PROVISIONING/dashboards" \
             "$GF_PATHS_LOGS" \
             "$GF_PATHS_PLUGINS" \
             "$GF_PATHS_DATA" && \
    cp "$GF_PATHS_HOME/conf/sample.ini" "$GF_PATHS_CONFIG" && \
    cp "$GF_PATHS_HOME/conf/ldap.toml" /etc/grafana/ldap.toml

RUN grafana-cli --pluginsDir "$GF_PATHS_PLUGINS" plugins install mtanda-histogram-panel \
    && grafana-cli --pluginsDir "$GF_PATHS_PLUGINS" plugins install grafana-piechart-panel \
    && grafana-cli --pluginsDir "$GF_PATHS_PLUGINS" plugins install grafana-clock-panel \
    && grafana-cli --pluginsDir "$GF_PATHS_PLUGINS" plugins install grafana-simple-json-datasource \
    && grafana-cli --pluginsDir "$GF_PATHS_PLUGINS" plugins install ryantxu-ajax-panel \
    && grafana-cli --pluginsDir "$GF_PATHS_PLUGINS" plugins install michaeldmoore-multistat-panel

RUN chown -R socore:socore "$GF_PATHS_DATA" "$GF_PATHS_HOME/.aws" "$GF_PATHS_LOGS" "$GF_PATHS_PLUGINS" && \
    chmod 777 "$GF_PATHS_DATA" "$GF_PATHS_HOME/.aws" "$GF_PATHS_LOGS" "$GF_PATHS_PLUGINS"

EXPOSE 3000

COPY ./run.sh /run.sh
RUN chmod +x /run.sh

USER socore
WORKDIR /
ENTRYPOINT [ "/run.sh" ] 
