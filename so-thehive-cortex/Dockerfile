FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Cortex Docker container for use with Security Onion"
RUN yum update -y
RUN yum install -y https://dl.bintray.com/thehive-project/rpm-stable/cortex-3.0.1-1.noarch.rpm 
RUN yum -y install cortex wget git
RUN groupmod -g 939 cortex \
  && usermod -u 939 -g 939 cortex \
  && ls -la /opt \
  && ls -la /opt/cortex
RUN mkdir -p /opt/cortex/conf
RUN chown -R cortex /opt/cortex \
     /var/log/cortex
     
     
RUN yum update -y && yum -y install epel-release
RUN yum -y install https://centos7.iuscommunity.org/ius-release-el7.rpm
RUN yum -y makecache && yum -y install python36u python36u-pip && pip3.6 install --upgrade pip && yum clean all

RUN git clone https://github.com/TheHive-Project/Cortex-Analyzers

RUN for I in $(find Cortex-Analyzers -name 'requirements.txt'); do pip3 install -r $I || true; done
     
USER cortex

ENTRYPOINT ["/opt/cortex/bin/cortex"]
