FROM redmine:4-passenger

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Playbook (Redmine) running in Docker container for use with Security Onion"

WORKDIR /usr/src/redmine

ADD playbook/circle_theme.tar.bz2   /usr/src/redmine/public/themes

RUN git clone https://github.com/suer/redmine_webhook.git /usr/src/redmine/plugins/redmine_webhook

RUN git clone https://github.com/Security-Onion-Solutions/securityonion-playbook-plugin.git /usr/src/redmine/plugins/redmine_playbook

COPY playbook/passenger-nginx-config-template.erb /passenger-nginx-config-template.erb

CMD ["passenger", "start", "--nginx-config-template", "/passenger-nginx-config-template.erb"]
