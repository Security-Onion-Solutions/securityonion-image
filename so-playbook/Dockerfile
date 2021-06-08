FROM ghcr.io/security-onion-solutions/redmine:4.2.1-passenger

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Playbook running in Docker container for use with Security Onion"

ARG GID=939
ARG UID=939
ARG USERNAME=socore

RUN groupadd --gid ${GID} ${USERNAME} && \
    useradd --uid ${UID} --gid ${GID} \
    --home-dir /opt/so --no-create-home ${USERNAME}
RUN usermod -aG socore redmine

WORKDIR /usr/src/redmine
ADD playbook/circle_theme.tar.bz2   /usr/src/redmine/public/themes
RUN git clone https://github.com/suer/redmine_webhook.git /usr/src/redmine/plugins/redmine_webhook
RUN git clone https://github.com/Security-Onion-Solutions/securityonion-playbook-plugin.git /usr/src/redmine/plugins/redmine_playbook
RUN bundle install --gemfile /usr/src/redmine/Gemfile
COPY playbook/passenger-nginx-config-template.erb /passenger-nginx-config-template.erb

RUN mkdir -p /playbook/log && \
    chown -R socore:socore /playbook && \
    chmod -R 0770 /playbook

CMD ["passenger", "start", "--nginx-config-template", "/passenger-nginx-config-template.erb", "--log-file", "/playbook/log/playbook.log"]
