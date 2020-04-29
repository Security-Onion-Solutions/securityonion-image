Suricata 4.0.4

NOTE: This will only work on boxes with the elastic features enabled that use eve.json.

REQUIREMENTS: AF_Packet, Suricata user with uid and gid `940`.


To run for testing:
```
sudo docker run --privileged=true -e INTERFACE=eth1 \ 
-v /opt/so/conf/suricata/suricata.yaml:/usr/local/etc/suricata/suricata.yaml:ro \
-v /opt/so/conf/suricata/rules:/usr/local/etc/suricata/rules:ro \
-v /opt/so/log/suricata/:/usr/local/var/log/suricata/:rw \
--net=host --name=so-suricata -d toosmooth/so-suricata:test2
```

`INTERFACE` being the itnerface you want to monitor

Set the volumes appropriately to where you have the required files.
