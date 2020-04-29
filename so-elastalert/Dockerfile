# Security Onion Elastalert Docker image running on Centos7.

FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"

# Create a common centos update layer
RUN yum update -y && \
    yum clean all

# Set this environment variable to true to set timezone on container start.
ENV SET_CONTAINER_TIMEZONE false

# Default container timezone as found under the directory /usr/share/zoneinfo/.
ENV CONTAINER_TIMEZONE UTC

# URL from which to download Elastalert.
ENV ELASTALERT_URL https://github.com/Yelp/elastalert/archive/master.zip

# Directory holding configuration for Elastalert and Supervisor.
ENV CONFIG_DIR /etc/elastalert/conf

# Elastalert rules directory.
ENV RULES_DIRECTORY /etc/elastalert/rules

# Elastalert configuration file path in configuration directory.
ENV ELASTALERT_CONFIG ${CONFIG_DIR}/elastalert_config.yaml

# Directory to which Elastalert and Supervisor logs are written.
ENV LOG_DIR /var/log/elastalert

# Elastalert home directory name.
ENV ELASTALERT_DIRECTORY_NAME elastalert

# Elastalert home directory full path.
ENV ELASTALERT_HOME /opt/${ELASTALERT_DIRECTORY_NAME}

# Supervisor configuration file for Elastalert.
ENV ELASTALERT_SUPERVISOR_CONF ${CONFIG_DIR}/elastalert_supervisord.conf

# Alias, DNS or IP of Elasticsearch host to be queried by Elastalert. Set in default Elasticsearch configuration file.
ENV ELASTICSEARCH_HOST elasticsearch

# Port on above Elasticsearch host. Set in default Elasticsearch configuration file.
ENV ELASTICSEARCH_PORT 9200

# Add ElastAlert user
RUN groupadd --gid 933 elastalert && \
    adduser --uid 933 --gid 933 \
      --home-dir /usr/share/elastalert --no-create-home \
      elastalert

WORKDIR /opt

# Copy the script used to launch the Elastalert when a container is started.
COPY ./files/start-elastalert.sh /opt/
COPY ./files/elastalert_config.conf ${ELASTALERT_CONFIG}
COPY ./files/elastalert_supervisord.conf ${ELASTALERT_SUPERVISOR_CONF} 

# Install software required for Elastalert and NTP for time synchronization.
RUN yum update -y && yum -y install epel-release && \
    yum install -y \
      https://centos7.iuscommunity.org/ius-release-el7.rpm \
      unzip \
      wget \
      ntp.x86_64 \
      openssl-devel.x86_64 \
      openssl.x86_64 \
      libffi.x86_64 \
      libffi-devel.x86_64 \
      libyaml-devel \
      gcc.x86_64 \
      compat-gcc-44.x86_64 \
      libgcc.x86_64 \
      tzdata.noarch;

RUN yum -y makecache && \
    yum -y install \
      python36-devel.x86_64 \
      python36-libs.x86_64 \
      python36-pip.noarch \
    yum clean all; \

# Download and unpack Elastalert.
    wget ${ELASTALERT_URL}; \
    unzip *.zip; \
    rm -rf *.zip; \
    mv e* ${ELASTALERT_DIRECTORY_NAME}

WORKDIR ${ELASTALERT_HOME}

# Copy over Elastalert mappings
COPY ./files/elastalert.json ./files/past_elastalert.json elastalert/es_mappings/6/

COPY ./files/create_index.py elastalert/

# Install Elastalert.
RUN python3.6 setup.py install; \

# Install Supervisor.
    python3.6 -m pip install supervisor; \

# Install Supervisor.
    easy_install supervisor; \

# Make the start-script executable.
    chmod +x /opt/start-elastalert.sh; \

# Create directories. The /var/empty directory is used by openntpd.
    mkdir -p ${CONFIG_DIR}; \
    mkdir -p ${RULES_DIRECTORY}; \
    mkdir -p ${LOG_DIR}; \
    mkdir -p /var/empty; \
    mkdir -p /var/run/elastalert; \

# Define perms for ElastAlert
    chown -R elastalert:elastalert ${CONFIG_DIR}; \
    chown -R elastalert:elastalert ${RULES_DIRECTORY}; \
    chown -R elastalert:elastalert ${LOG_DIR}; \
    chown -R elastalert:elastalert ${ELASTALERT_HOME}; \
    chown -R elastalert:elastalert /var/run/elastalert/; \
    chown elastalert:elastalert /opt/start-elastalert.sh; \
    chown elastalert:elastalert /usr/local/bin/supervisord; \

# Elastalert configuration:
    # Set the rule directory in the Elastalert config file to external rules directory.
    sed -i -e"s|rules_folder: [[:print:]]*|rules_folder: ${RULES_DIRECTORY}|g" ${ELASTALERT_CONFIG}; \

    # Set the Elasticsearch host that Elastalert is to query.
    sed -i -e"s|es_host: [[:print:]]*|es_host: ${ELASTICSEARCH_HOST}|g" ${ELASTALERT_CONFIG}; \

    # Set the port used by Elasticsearch at the above address.
    sed -i -e"s|es_port: [0-9]*|es_port: ${ELASTICSEARCH_PORT}|g" ${ELASTALERT_CONFIG}; \

# Elastalert Supervisor configuration:
    # Configure Supervisor to run as ElastAlert user
#    sed -i "/\[supervisord\]/a user=elastalert" ${ELASTALERT_SUPERVISOR_CONF}; \
#    sed -i "/\[program:elastalert\]/a user=elastalert" ${ELASTALERT_SUPERVISOR_CONF}; \
    
    # Redirect Supervisor log output to a file in the designated logs directory.
    sed -i -e"s|logfile=.*log|logfile=${LOG_DIR}/elastalert_supervisord.log|g" ${ELASTALERT_SUPERVISOR_CONF}; \

    # Redirect Supervisor stderr output to a file in the designated logs directory.
    sed -i -e"s|stderr_logfile=.*log|stderr_logfile=${LOG_DIR}/elastalert_stderr.log|g" ${ELASTALERT_SUPERVISOR_CONF}; \

    # Modify the start-command.
    sed -i -e"s|python elastalert.py|python3.6 -m elastalert.elastalert --config ${ELASTALERT_CONFIG}|g" ${ELASTALERT_SUPERVISOR_CONF}; \

# Copy the Elastalert configuration file to Elastalert home directory to be used when creating index first time an Elastalert container is launched.
    cp ${ELASTALERT_CONFIG} ${ELASTALERT_HOME}/config.yaml; \


# Add Elastalert to Supervisord.
    supervisord -c ${ELASTALERT_SUPERVISOR_CONF}

# Define mount points.
#VOLUME [ "${CONFIG_DIR}", "${RULES_DIRECTORY}", "${LOG_DIR}"]

# Switch to ElastAlert user
USER elastalert

# Launch Elastalert when a container is started.
CMD ["/opt/start-elastalert.sh"]
