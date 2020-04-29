#!/bin/bash

/usr/local/bin/kibana-docker &

#KIBANA_VERSION=7.6.1
#MAX_WAIT=60

# Check to see if Kibana is available
#wait_step=0
#  until curl -s -XGET http://localhost:5601 > /dev/null ; do
#  wait_step=$(( ${wait_step} + 1 ))
#  echo "Waiting on Kibana...Attempt #$wait_step"
#	  if [ ${wait_step} -gt ${MAX_WAIT} ]; then
#			  echo "ERROR: Kibana not available for more than ${MAX_WAIT} seconds."
#			  exit 5
#	  fi
#		  sleep 1s;
#  done

# This is junky but create the index if Kibana decides its not in the mood
#curl -s -X GET "$ELASTICSEARCH_HOST:9200/_cat/indices?v" | grep 'kibana' &> /dev/null

#if [[ $? != 0 ]]; then
#    echo "Kibana Index Isn't There. Let's add it"
#    curl -XPUT $ELASTICSEARCH_HOST:9200/.kibana
#else
#    echo "Kibana Index is there... Next."
#fi
# Let's sleep some more and let Kibana come all the way up.
sleep 30
# Apply Kibana config
#echo
#echo "Applying Kibana config..."
#curl -s -XPOST http://localhost:5601/api/saved_objects/config/$KIBANA_VERSION?overwrite=true  \
#    -H "Content-Type: application/json" \
#    -H "kbn-xsrf: $KIBANA_VERSION" \
#    -d@/usr/share/kibana/config/config.json
#echo

# Apply Kibana template
#  echo
#  echo "Applying Kibana template..."
#  curl -s -XPUT http://$ELASTICSEARCH_HOST:9200/_template/kibana \
#       -H 'Content-Type: application/json' \
#       -d'{"index_patterns" : ".kibana", "settings": { "number_of_shards" : 1, "number_of_replicas" : 0 }, "mappings" : { "search": {"properties": {"hits": {"type": "integer"}, "version": {"type": "integer"}}}}}'
#  echo

#  curl -s -XPUT "$ELASTICSEARCH_HOST:9200/.kibana/_settings" \
#       -H 'Content-Type: application/json' \
#       -d'{"index" : {"number_of_replicas" : 0}}'
#  echo

# Apply all the dashboards
# Load dashboards, visualizations, index pattern(s), etc.
#for i in /usr/share/kibana/dashboards/*.json; do
  #sed -i "s/OSQPLACEHOLDER/$MASTER/g" $i
  #sed -i "s/THEHIVESERVER/$MASTER/g" $i
  #sed -i "s/SENSORONISERVER/$MASTER/g" $i
#	curl -XPOST localhost:5601/api/kibana/dashboards/import?force=true -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d @$i >> /var/log/kibana/dashboards.log 2>&1 &
#	echo -n "."
#done

# Load config file
#curl -XPOST localhost:5601/api/kibana/dashboards/import?force=true -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d @$i

# Add Custom dashboards
#for i in /usr/share/kibana/custdashboards/*.json; do
#	curl -XPOST localhost:5601/api/kibana/dashboards/import?force=true -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d @$i >> /var/log/kibana/dashboards.log 2>&1 &
#	echo -n "."
#done

sleep infinity
