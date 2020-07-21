FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="TheHive Docker container for use with Security Onion"

# Common Ubuntu layer
RUN apt-get update && \
    apt-get --no-install-recommends --no-install-suggests -y install \
      curl \
      wget \
      ca-certificates \
      build-essential

RUN apt-get --no-install-recommends --no-install-suggests -y install \
  gpg gpg-agent dirmngr \
  apt-transport-https

RUN echo 'deb https://dl.bintray.com/thehive-project/debian-stable any main' | tee -a /etc/apt/sources.list.d/thehive-project.list
RUN curl https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | apt-key add -
RUN apt-get update
RUN apt-get -y install thehive

RUN groupmod -g 939 thehive \
  && usermod -u 939 -g 939 thehive \
  && ls -la /opt \
  && ls -la /opt/thehive
RUN mkdir -p /opt/thehive/conf
RUN chown -R thehive /opt/thehive \
    /var/log/thehive
RUN echo "play.http.secret.key=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 49)" >> /opt/thehive/conf/application.conf \
  && echo -e 'search.host = ["elasticsearch:9300"]\n\
    play.http.secret.key = ${?PLAY_SECRET}' >> /opt/thehive/conf/application.conf
COPY bin/so-thehive.sh /opt/thehive/bin/so-thehive.sh
RUN chmod +x /opt/thehive/bin/so-thehive.sh

USER thehive

EXPOSE 9000

ENTRYPOINT ["/opt/thehive/bin/so-thehive.sh"]
