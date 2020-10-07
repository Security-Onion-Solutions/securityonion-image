FROM redmine:4-passenger

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Playbook running in Docker container for use with Security Onion"

ARG GID=939
ARG UID=939
ARG USERNAME=socore

RUN groupadd --gid ${GID} ${USERNAME} && \
    useradd --uid ${UID} --gid ${GID} \
    --home-dir /opt/so --no-create-home ${USERNAME}

# Add Playbook specific files
WORKDIR /usr/src/redmine
COPY playbook/circle_theme.tar.bz2 /usr/src/redmine/public/themes
RUN git clone https://github.com/suer/redmine_webhook.git /usr/src/redmine/plugins/redmine_webhook
RUN git clone https://github.com/Security-Onion-Solutions/securityonion-playbook-plugin.git /usr/src/redmine/plugins/redmine_playbook
RUN bundle install --gemfile /usr/src/redmine/Gemfile

# Set up passenger config + entrypoint
COPY ./playbook/passenger-nginx-config-template.erb /passenger-nginx-config-template.erb
COPY ./playbook/entrypoint.sh ./entrypoint.sh
RUN chmod +x /usr/src/redmine/entrypoint.sh

# Run app as user socore
RUN chown -R socore:socore /usr/src/redmine
USER socore

ENTRYPOINT [ "/usr/src/redmine/entrypoint.sh" ]
