from datetime import datetime
import json
import os
import re
import glob
import time
import hashlib
from pathlib import Path
import urllib3
import subprocess

import requests
import ruamel.yaml
from config import parser
import playbook
urllib3.disable_warnings()
yaml = ruamel.yaml.YAML(typ='safe')

updated_plays = dict()
play_update_counter = 0
play_new_counter = 0
play_noupdate_counter = 0
play_update_available_counter = 0  
plays = []
offset = 0

playbook_headers = {'X-Redmine-API-Key': parser.get(
    "playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")


# Which ruleset categories should be imported / updated?
# rulesets = ['application','apt','cloud','compliance','generic','linux','network', 'proxy', 'web', 'windows']
rulesets = parser.get('playbook', 'playbook_rulesets').split(",")

##############################################################
# update_play(raw_sigma, repo_sigma, ruleset)
# This function compares the uuid of the current rule
# against the Playbook plays. If there is no match, then it
# creates a new play in Playbook.
# If there is a match, it then compares a hash of the sigma:
#    Hash matches --> no update needed
#    Hash doesn't match --> update the play in playbook
# inputs:  raw sigma, sigma dict, and the playbook name
# returns: the status of the play: update / nop / new
def update_play(raw_sigma, repo_sigma, ruleset, ruleset_group, filename): 
    sigma_url = filename.replace('/SOCtopus/sigma/', 'https://github.com/Security-Onion-Solutions/sigma/tree/master/')
    for play in plays:
        if repo_sigma['id'] == play['sigma_id']:
            repo_hash = hashlib.sha256(
                str(repo_sigma).encode('utf-8')).hexdigest()
            playbook_hash = hashlib.sha256(
                str(play['sigma_dict']).encode('utf-8')).hexdigest()
            if repo_hash != playbook_hash:
                    file = filename[filename.rfind('/')+1:]
                    backup_path = "/SOCtopus/custom/sigma/" + file
                    
                    if os.path.exists(backup_path):
                        try:
                            with open(backup_path, encoding="utf-8") as fpi2:
                                raw = fpi2.read()
                            backup_rule = yaml.load(raw)
                            backup_hash = hashlib.sha256(str(backup_rule).encode('utf-8')).hexdigest()
                            
                        except Exception as e:
                            print('Error - Unable to load backup copy' + str(e))

                        if repo_hash != backup_hash:
                            play_status = "available"
                            update_payload = {"issue": {"subject": repo_sigma['title'], "project_id": 1, "tracker": "Play", "custom_fields": [ 
                                {"id": 28, "name": "Update Available", "value": "1"}]}} 
                            url = f"{playbook_url}/issues/{play['issue_id']}.json"
                            r = requests.put(url, data=json.dumps(
                                update_payload), headers=playbook_headers, verify=False)
                            playbook.play_template_backup(play['issue_id'])
                        else:
                            play_status = "nop"
                    else:
                        play_status = "updated"
                        formatted_sigma = f'{{{{collapse(View Sigma)\n<pre><code class="yaml">\n\n{raw_sigma}\n</code></pre>\n}}}}'
                        update_payload = {"issue": {"subject": repo_sigma['title'], "project_id": 1, "status": "Disabled", "tracker": "Play", "custom_fields": [ 
                            {"id": 9, "name": "Sigma", "value": formatted_sigma.strip()}, \
                            {"id": 28, "name": "Sigma URL", "value": sigma_url.strip()}, \
                            {"id": 27, "name": "Sigma File", "value": filename.strip()}]}} 
                        url = f"{playbook_url}/issues/{play['issue_id']}.json"
                        r = requests.put(url, data=json.dumps(
                            update_payload), headers=playbook_headers, verify=False)
            else:
                play_status = "nop"
            break

    else:
        print('No Current Play - Create New Play in Playbook')
        play_status = "new"
        creation_status = playbook.play_create(raw_sigma, repo_sigma,"community", ruleset, ruleset_group, "DRL-1.0", filename, sigma_url)
        print (creation_status)

    return play_status


def rule_update(rulesets):
    global play_update_counter
    global play_new_counter
    global play_noupdate_counter
    global play_update_available_counter
    ruleset_path = f"./sigma/rules/{rulesets}"
    for filename in Path(ruleset_path).glob('**/*.yml'):
        filepath = "/SOCtopus/" + str(filename)
        if "deprecated" in str(filename):
            print(f"\n\n - Not Loading - rule Deprecated - {filename}")
        else:
            print(f"\n\n{filename}")
            sub_group = re.search(rf"{rulesets}\/(.*)\/",str(filename))
            if sub_group != None:
                ruleset_group = sub_group.group(1)
            else:
                ruleset_group = None

            with open(filename, encoding="utf-8") as fpi2:
                raw = fpi2.read()
            try:
                repo_sigma = yaml.load(raw)
                #if folder == 'process_creation':
                    #folder = 'proc' 
                play_status = update_play(raw, repo_sigma, rulesets, ruleset_group, filepath)
                print(play_status)
                if play_status == "updated":
                    play_update_counter += 1
                elif play_status == "new":
                    play_new_counter += 1
                elif play_status == "nop":
                    play_noupdate_counter += 1
                elif play_status == "available":
                    play_update_available_counter += 1
            except Exception as e:
                print('Error - Sigma rule skipped \n' + str(e))
    
    return 

# Starting up....
print(f"\n-= Started: {datetime.now()}-=\n")

print(
    f"\n\n-= Creating/Updating Plays based on the following categories: {rulesets} -=\n\n")

# Get all the current plays from Playbook & parse out metadata
print(f"\n\n-= Parsing current Plays in Playbook -=\n\n")
time.sleep(20)
url = f"{playbook_url}/issues.json?offset=0&tracker_id=1&limit=100"
response = requests.get(url, headers=playbook_headers, verify=False).json()

for i in response['issues']:
    play_meta = playbook.play_metadata(i['id'])
    plays.append(play_meta)

while offset < response['total_count']:
    offset += 100
    url = f"{playbook_url}/issues.json?offset={offset}&tracker_id=1&limit=100"
    response = requests.get(url, headers=playbook_headers, verify=False).json()
    print(f"offset: {offset}")
    for i in response['issues']:
        play_meta = playbook.play_metadata(i['id'])
        plays.append(play_meta)

print(f"\n-= Parsed Playbook Plays: {len(plays)} -=\n")


# Create / Update the community Sigma repo
sigma_repo = f"sigma/README.md"
if os.path.exists(sigma_repo):
    git_status = subprocess.run(
        ["git", "pull"], stdout=subprocess.PIPE, encoding='ascii',cwd='/SOCtopus/sigma')
else:
    git_status = subprocess.run(
        ["git", "clone", "https://github.com/Security-Onion-Solutions/sigma.git"], stdout=subprocess.PIPE, encoding='ascii')


'''
Next, loop through each sigma rule in the folder
Compare the uuid of the current rule against the Playbook plays
If no match, then create a new play in playbook
If there is a match, compare a hash of the sigma:
    Hash matches --> no update needed
    Hash doesn't match --> update the play in playbook
'''
for ruleset in rulesets:
    rule_update(ruleset)
    print (ruleset)

# Finally, print a summary of new or updated plays
summary = (
    f"\n\n-= Update Summary =-\n\nSigma Community Repo:\n {git_status.stdout.strip()}\n\nUpdated Plays: {play_update_counter}\n"
    f"Updates Available: {play_update_available_counter}\nNew Plays: {play_new_counter}\nNo Updates Needed: {play_noupdate_counter}\n\nEnabled Rulesets:\n{rulesets}\n")
print (summary)

print (f"\n\n-= Completed: {datetime.now()}-=\n")    
