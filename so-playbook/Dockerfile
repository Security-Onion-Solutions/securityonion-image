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
RUN mkdir /passenger && \
    chown -R socore:socore /passenger
COPY ./playbook/passenger-nginx-config-template.erb /passenger-nginx-config-template.erb
COPY ./playbook/run.sh ./run.sh
RUN chmod +x ./run.sh

CMD [ "/usr/src/redmine/run.sh" ]
