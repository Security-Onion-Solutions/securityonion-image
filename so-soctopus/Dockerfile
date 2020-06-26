FROM centos:7

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="API for automating SOC-related functions"

WORKDIR /SOCtopus

RUN yum update -y && yum -y install epel-release
RUN yum -y install https://repo.ius.io/ius-release-el7.rpm
RUN yum -y makecache && yum -y install python3 python3-pip python3-devel gcc git && pip3 install --upgrade pip && yum clean all
RUN mkdir -p /SOCtopus/templates
RUN mkdir -p /SOCtopus/playbook
RUN mkdir -p /var/log/SOCtopus

COPY ./requirements.txt /SOCtopus/
RUN pip3 install -r requirements.txt

COPY ./so-soctopus /SOCtopus
ENTRYPOINT ["python3", "SOCtopus.py"]

