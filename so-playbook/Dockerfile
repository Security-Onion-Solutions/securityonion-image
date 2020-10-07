FROM redmine:4-passenger

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Playbook running in Docker container for use with Security Onion"

ARG GID=939
ARG UID=939
ARG USERNAME=socore

RUN groupadd --gid ${GID} ${USERNAME} && \
    useradd --uid ${UID} --gid ${GID} \
    --home-dir /opt/so --no-create-home ${USERNAME}

WORKDIR /usr/src/redmine
ADD playbook/circle_theme.tar.bz2   /usr/src/redmine/public/themes
RUN git clone https://github.com/suer/redmine_webhook.git /usr/src/redmine/plugins/redmine_webhook
RUN git clone https://github.com/Security-Onion-Solutions/securityonion-playbook-plugin.git /usr/src/redmine/plugins/redmine_playbook
RUN bundle install --gemfile /usr/src/redmine/Gemfile
COPY playbook/passenger-nginx-config-template.erb /passenger-nginx-config-template.erb

RUN mkdir /passenger && \
    chgrp -R socore /passenger && \
    chmod 0770 /passenger

RUN usermod -aG socore redmine

RUN sed -i '$s/$/ \&>\/dev\/null/' /docker-entrypoint.sh

CMD ["passenger", "start", "--nginx-config-template", "/passenger-nginx-config-template.erb", "--log-file", "/passenger/log/passenger.log"]
