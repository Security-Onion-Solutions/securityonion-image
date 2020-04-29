FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="TheHive Docker container for use with Security Onion"
RUN yum update -y
RUN yum install -y https://dl.bintray.com/thehive-project/rpm-stable/thehive-3.4.0-1.noarch.rpm
RUN yum -y install thehive wget
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
