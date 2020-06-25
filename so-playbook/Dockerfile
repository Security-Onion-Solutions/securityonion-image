FROM redmine:4-passenger

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Playbook running in Docker container for use with Security Onion"

WORKDIR /usr/src/redmine

ADD playbook/plugin/redmine_playbook.tar.bz2   /usr/src/redmine/plugins

ADD playbook/circle_theme.tar.bz2   /usr/src/redmine/public/themes

RUN git clone https://github.com/suer/redmine_webhook.git /usr/src/redmine/plugins/redmine_webhook

COPY playbook/passenger-nginx-config-template.erb /passenger-nginx-config-template.erb

CMD ["passenger", "start", "--nginx-config-template", "/passenger-nginx-config-template.erb"]
