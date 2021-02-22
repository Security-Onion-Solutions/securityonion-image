from datetime import datetime
import json
import urllib3
import os
import time

import requests
from config import parser
import playbook
urllib3.disable_warnings()

all_plays = []
offset = 0

playbook_headers = {'X-Redmine-API-Key': parser.get(
    "playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")


print(f"\n-= Started: {datetime.now()}-=\n")

# Get all plays from Playbook
url = f"{playbook_url}/issues.json?offset=0&tracker_id=1&limit=100"
response = requests.get(url, headers=playbook_headers, verify=False).json()

for i in response['issues']:
    all_plays.append(i)

while offset < response['total_count']:
    offset += 100
    url = f"{playbook_url}/issues.json?offset={offset}&tracker_id=1&limit=100"
    response = requests.get(url, headers=playbook_headers, verify=False).json()
    print(f"Active offset: {offset}")
    for i in response['issues']:
        all_plays.append(i)

print(f"\n-= Parsed Playbook Plays: {len(all_plays)} -=\n")

for play in all_plays:
    playbook.play_update(play['id'])
    print(f"\nIssue-ID - {play['id']}\n")