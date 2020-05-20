FROM centos:7

# Originally developed by Justin Henderson justin@hasecuritysolutions.com
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Freqserver running in Docker container for use with Security Onion"

# Create a common centos update layer
RUN yum update -y && \
    yum clean all

# Create a common python/git layer
RUN yum update -y && \
    yum install -y python3 git && pip3 install six &&  \
    yum clean all

# Create user
RUN groupadd --gid 935 freqserver && \
    adduser --uid 935 --gid 935 \
      --home-dir /usr/share/freqserver --no-create-home \
      freqserver

# Install and set perms in same layer to save space
RUN mkdir -p /opt/freq_server && \
	cd /opt/freq_server && \
	git clone https://github.com/MarkBaggett/freq.git && \
	chown -R freqserver: /opt/freq_server && \
	mkdir /var/log/freq_server && \
	ln -sf /dev/stderr /var/log/freq_server/freq_server.log

USER freqserver

EXPOSE 10004

STOPSIGNAL SIGTERM

CMD /usr/bin/python3 /opt/freq_server/freq/freq_server.py -s 0 -ip 0.0.0.0 10004 /opt/freq_server/freq/freqtable2018.freq
