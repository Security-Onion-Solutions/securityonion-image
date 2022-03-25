from datetime import datetime
import json
import urllib3
import os
import time

import requests
from config import parser
import playbook
urllib3.disable_warnings()

active_elastalert_counter = 0
inactive_elastalert_counter = 0
active_plays = []
inactive_plays = []
offset = 0

playbook_headers = {'X-Redmine-API-Key': parser.get(
    "playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")


print(f"\n-= Started: {datetime.now()}-=\n")

# Get active plays from Playbook - id = 3
url = f"{playbook_url}/issues.json?offset=0&tracker_id=1&limit=100&status_id=3"
response = requests.get(url, headers=playbook_headers, verify=False).json()

for i in response['issues']:
    active_plays.append(i)

while offset < response['total_count']:
    offset += 100
    url = f"{playbook_url}/issues.json?offset={offset}&tracker_id=1&limit=100&status_id=3"
    response = requests.get(url, headers=playbook_headers, verify=False).json()
    print(f"Active offset: {offset}")
    for i in response['issues']:
        active_plays.append(i)

print(f"\n-= Parsed Playbook Plays: {len(active_plays)} -=\n")

for play in active_plays:

    for item in play['custom_fields']:
        if item['name'] == "PlayID":
            play_id = item['value']

    print(f"\n\n{play_id}")

    play_file = f"/etc/playbook-rules/{play_id}.yaml"
    if os.path.exists(play_file):
        print('All Good - Elastalert Config Exists')
    else:
        print('Warning - Elastalert Config Doesnt Exist')
        active_elastalert_counter += 1
        playbook.elastalert_update(play['id'])
        time.sleep(.5)


# Get inactive plays from Playbook - id = 4
url = f"{playbook_url}/issues.json?offset=0&tracker_id=1&limit=100&status_id=4"
inactive_response = requests.get(url, headers=playbook_headers, verify=False).json()

for i in inactive_response['issues']:
    inactive_plays.append(i)

while offset < inactive_response['total_count']:
    offset += 100
    url = f"{playbook_url}/issues.json?offset={offset}&tracker_id=1&limit=100&status_id=4"
    inactive_response = requests.get(url, headers=playbook_headers, verify=False).json()
    print(f"Inactive offset: {offset}")
    for i in inactive_response['issues']:
        inactive_plays.append(i)

for play in inactive_plays:
    for item in play['custom_fields']:
        if item['name'] == "PlayID":
            play_id = item['value']

    print(f"\n\nInactive - {play_id}")

    play_file = f"/etc/playbook-rules/{play_id}.yaml"
    if os.path.exists(play_file):
        print('Inactive Warning - Elastalert Config Exists')
        os.remove(play_file)
        inactive_elastalert_counter += 1

# Refresh Playbook Navigator Layer
playbook.navigator_update()

print(f"\n\n-= Maintenance Summary =-\n\n"
      f"Active Plays: {response['total_count']}"
      f"\n-----------------\n"
      f"Missing ElastAlert Configs: {active_elastalert_counter}\n"
      f"Inactive Plays: {inactive_response['total_count']}\n"
      f"-----------------\n"
      f"Out of Sync ElastAlert Configs: {inactive_elastalert_counter}"
      f"\n\n-= Completed: {datetime.now()}-=\n")
