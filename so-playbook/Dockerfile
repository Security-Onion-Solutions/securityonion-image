FROM redmine:4-passenger

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Playbook running in Docker container for use with Security Onion"

WORKDIR /usr/src/redmine

RUN apt-get update && apt-get install patch && rm -rf /var/lib/apt/lists/*

ADD playbook/plugin/redmine_playbook.tar.bz2   /usr/src/redmine/plugins

ADD playbook/circle_theme.tar.bz2   /usr/src/redmine/public/themes

#ADD playbook/issues_controller.patch /tmp/issues_controller.patch

RUN git clone https://github.com/suer/redmine_webhook.git /usr/src/redmine/plugins/redmine_webhook

#RUN git clone https://github.com/serpi90/redmine_webhook.git /usr/src/redmine/plugins/redmine_webhook

#RUN patch -p1 -i /tmp/issues_controller.patch 

COPY playbook/passenger-nginx-config-template.erb /passenger-nginx-config-template.erb

CMD ["passenger", "start", "--nginx-config-template", "/passenger-nginx-config-template.erb"]
