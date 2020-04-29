#!/bin/sh

set -e

# Set the timezone.
if [ "$SET_CONTAINER_TIMEZONE" = "true" ]; then
	setup-timezone -z ${CONTAINER_TIMEZONE} && \
	echo "Container timezone set to: $CONTAINER_TIMEZONE"
else
	echo "Container timezone not modified"
fi

# Force immediate synchronisation of the time and start the time-synchronization service.
# In order to be able to use ntpd in the container, it must be run with the SYS_TIME capability.
# In addition you may want to add the SYS_NICE capability, in order for ntpd to be able to modify its priority.
# ntpd -s

# Support Elastic Auth
if grep -q "^es_username:" ${ELASTALERT_CONFIG}; then
	ELASTICSEARCH_USERNAME=$(grep "^es_username:" ${ELASTALERT_CONFIG} | awk '{print $2}')
	ELASTICSEARCH_PASSWORD=$(grep "^es_password:" ${ELASTALERT_CONFIG} | awk '{print $2}')
	ELASTICSEARCH_AUTH="--user=${ELASTICSEARCH_USERNAME} --password=${ELASTICSEARCH_PASSWORD}"
	ELASTALERT_CREATE_INDEX_AUTH="--username ${ELASTICSEARCH_USERNAME} --password ${ELASTICSEARCH_PASSWORD}"
fi

# Wait until Elasticsearch is online since otherwise Elastalert will fail.
while ! wget ${ELASTICSEARCH_AUTH} ${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT} >/dev/null 2>&1; do
	echo "Waiting for Elasticsearch..."
	sleep 1
done
sleep 5

# Check if the Elastalert index exists in Elasticsearch and create it if it does not.
if wget ${ELASTICSEARCH_AUTH} ${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}/elastalert_status >/dev/null 2>&1; then
	echo "Elastalert index already exists in Elasticsearch."
else
	echo "Creating Elastalert index in Elasticsearch..."
	elastalert-create-index ${ELASTALERT_CREATE_INDEX_AUTH} --host ${ELASTICSEARCH_HOST} --port ${ELASTICSEARCH_PORT} --config ${ELASTALERT_CONFIG} --index elastalert_status --old-index ""
fi

# Elastalert configuration:
# Set the rule directory in the Elastalert config file to external rules directory.
#sed -i -e"s|^rules_folder: [[:print:]]*|rules_folder: ${RULES_DIRECTORY}|g" ${ELASTALERT_CONFIG}; \

# Set the Elasticsearch host that Elastalert is to query.
#sed -i -e"s|^es_host: [[:print:]]*|es_host: ${ELASTICSEARCH_HOST}|g" ${ELASTALERT_CONFIG}; \

# Set the port used by Elasticsearch at the above address.
#sed -i -e"s|^es_port: [0-9]*|es_port: ${ELASTICSEARCH_PORT}|g" ${ELASTALERT_CONFIG}; \

# Elastalert Supervisor configuration:
# Redirect Supervisor log output to a file in the designated logs directory.
sed -i -e"s|logfile=.*log|logfile=${LOG_DIR}/elastalert_supervisord.log|g" ${ELASTALERT_SUPERVISOR_CONF}; \

# Redirect Supervisor stderr output to a file in the designated logs directory.
sed -i -e"s|stderr_logfile=.*log|stderr_logfile=${LOG_DIR}/elastalert_stderr.log|g" ${ELASTALERT_SUPERVISOR_CONF}; \

# Modify the start-command.
sed -i -e"s|python elastalert.py|python3.6 -m elastalert.elastalert --config ${ELASTALERT_CONFIG}|g" ${ELASTALERT_SUPERVISOR_CONF}; \

echo "Starting Elastalert..."
exec supervisord -c ${ELASTALERT_SUPERVISOR_CONF} -n
