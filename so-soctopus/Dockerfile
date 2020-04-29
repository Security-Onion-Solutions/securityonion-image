FROM centos:7

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="API for automating SOC-related functions"

RUN yum update -y && yum -y install epel-release
RUN yum -y install https://centos7.iuscommunity.org/ius-release-el7.rpm
#RUN rpm --import /etc/pki/rpm-gpg/IUS-COMMUNITY-GPG-KEY
RUN yum -y makecache && yum -y install python3 python3-pip git && pip3 install --upgrade pip && yum clean all
RUN mkdir -p /SOCtopus
RUN mkdir -p /SOCtopus/templates
RUN mkdir -p /SOCtopus/playbook
RUN mkdir -p /var/log/SOCtopus
WORKDIR /SOCtopus
COPY ./requirements.txt /SOCtopus/
RUN pip3 install -r requirements.txt

COPY ./so-soctopus /SOCtopus
ENTRYPOINT ["python3", "SOCtopus.py"]

