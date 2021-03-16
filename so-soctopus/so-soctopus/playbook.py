#!/usr/bin/env python
# -*- coding: utf-8 -*-
import fileinput
import json
import os
import re
import shutil
import subprocess
import uuid
from time import gmtime, strftime
import sys
import tempfile
import glob
from pathlib import Path

import requests

from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

import ruamel.yaml
from config import parser

yaml = ruamel.yaml.YAML(typ='safe')

playbook_headers = {'X-Redmine-API-Key': parser.get("playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")
playbook_external_url = parser.get("playbook", "playbook_ext_url")
playbook_unit_test_index = parser.get("playbook", "playbook_unit_test_index")
playbook_verifycert = parser.getboolean('playbook', 'playbook_verifycert', fallback=False)

hive_headers = {'Authorization': f"Bearer {parser.get('hive', 'hive_key')}", 'Accept': 'application/json, text/plain',
                'Content-Type': 'application/json;charset=utf-8'}

es_url = parser.get("es", "es_url")
es_ip = parser.get("es", "es_ip")
es_verifycert = parser.getboolean('es', 'es_verifycert', fallback=False)

# Moves a community rule into /custom/sigma/ for hash comparison for rule updates
# This function is called when a user selects to disable auto update rules
def play_template_backup(issue_id): 

    play_meta = play_metadata(issue_id)
    if play_meta['playbook'] == "community":
        if play_meta['auto_update_sigma'] == "0": # Do not autoupdate Sigma is checked
            source = str(play_meta['sigma_file'])
            fileloc = source.rfind('/')
            file = source[source.rfind('/') + 1:]
            dst = "/SOCtopus/custom/sigma/" + file
            shutil.copyfile(source, dst)
        else:
            source = str(play_meta['sigma_file'])
            file = source[source.rfind('/') + 1:]
            dst = "/SOCtopus/custom/sigma/" + file
            if os.path.exists(dst):
                os.remove(dst)
    else:
        update_payload = {"issue": {"project_id": 3, "tracker": "Play", "custom_fields": [ 
        {"id": 30, "name": "Auto Update Sigma", "value": 0}]}} #changed adding filename to sigma after importing
        url = f"{playbook_url}/issues/{issue_id}.json"
        r = requests.put(url, data=json.dumps(update_payload), headers=playbook_headers, verify=False)

    return

# Updates the SMTP template when an SMTP option is changed
def smtp_update(issue_id): 
    url = f"{playbook_url}/issues/{issue_id}.json"
    smtp_tls = "false"
    r = requests.get(url, headers=playbook_headers, verify=playbook_verifycert).json()


    for item in r['issue']['custom_fields']:
        if item['name'] == "SMTP Server":
            smtp_host = re.sub(r'["\']', '', item['value'])
        elif item['name'] == "SMTP Port":
            smtp_port = re.sub(r'["\']', '', item['value'])
        elif item['name'] == "SMTP TLS Enabled":
            if item['value'] == "1":
                smtp_tls = "true"
        elif item['name'] == "Alert From Email Address":
            smtp_from = re.sub(r'["\']', '', item['value'])
        elif item['name'] == "Alert Email Address":
            smtp_to = re.sub(r'["\']', '', item['value'])


    f = open("/etc/playbook-rules/generic_email.template", 'r+')
    content = f.read()
    f.seek(0)
    f.truncate()
    content = re.sub(r'email:.*', f"email: \"{smtp_to}\"", content.rstrip())
    content = re.sub(r'from_addr:.*', f"from_addr: \"{smtp_from}\"", content.rstrip())
    content = re.sub(r'smtp_host:.*', f"smtp_host: \"{smtp_host}\"", content.rstrip())
    content = re.sub(r'smtp_port:.*', f"smtp_port: {smtp_port}", content.rstrip())
    content = re.sub(r'smtp_ssl:.*', f"smtp_ssl: {smtp_tls}", content.rstrip())
    f.write(content)
    f.close()

  
    success = smtp_update_rule()
 
    return

# Recreates elastalert rule for any play with email notifications enabled - this will update the SMTP configuration in the rule
# Called from smtp_update when a SMTP option is changed 
def smtp_update_rule():
    plays = []

    plays = get_plays()

    for play in plays:
        if play['email_notifications'] == "1" and play['status'] == "Active":     
            elastalert_update(play['issue_id'])          
            
    return success

def get_plays():
    plays = []
    offset = 0
    url = f"{playbook_url}/issues.json?offset=0&tracker_id=1&limit=100"
    response = requests.get(url, headers=playbook_headers, verify=False).json()

    for i in response['issues']:
        play_meta = play_metadata(i['id'])
        plays.append(play_meta)

    while offset < response['total_count']:
        offset += 100
        url = f"{playbook_url}/issues.json?offset={offset}&tracker_id=1&limit=100"
        response = requests.get(url, headers=playbook_headers, verify=False).json()
        print(f"offset: {offset}")

        for i in response['issues']:
            play_meta = play_metadata(i['id'])
            plays.append(play_meta)

    return plays

# Imports rules when Sigma Options -> Import Rules is selected in Redmine
# If a rule (matched by rule id) exists, the rule is updated with the imported rule, if not a new rule is created
# Template is moved to /custom/sigma/ as well
def play_import(issue_id):
    plays = []
    ruleset_path = "/SOCtopus/custom/import/"
    filen = ""

    plays = get_plays()

    for filename in Path(ruleset_path).glob('*.yml'):
        filen = str(filename)
        with open(filename, encoding="utf-8") as fpi2:
            raw = fpi2.read()
        repo_sigma = yaml.load(raw)
        
        #if folder == 'process_creation':
            #folder = 'proc' 
        for play in plays:
            if repo_sigma['id'] == play['sigma_id']:
                formatted_sigma = f'{{{{collapse(View Sigma)\n<pre><code class="yaml">\n\n{raw}\n</code></pre>\n}}}}'
                update_payload = {"issue": {"subject": repo_sigma['title'], "project_id": 1, "status": "Disabled", "tracker": "Play", "custom_fields": [ 
                    {"id": 9, "name": "Sigma", "value": formatted_sigma.strip()}, \
                    {"id": 30, "name": "Auto Update Sigma", "value": "0"}, \
                    {"id": 13, "name": "Playbook", "value": "imported"}, \
                    {"id": 27, "name": "Sigma File", "value": filen.strip()}]}} #changed adding filename to sigma after importing
                url = f"{playbook_url}/issues/{play['issue_id']}.json"
                r = requests.put(url, data=json.dumps(
                    update_payload), headers=playbook_headers, verify=False)
                break
        else:
            creation_status = play_create(raw, repo_sigma,"imported", "import", "import", "DRL-1.0", filen, "NA") #changed filename added to play_create
        
        fileloc = filen.rfind('/')
        file = filen[filen.rfind('/') + 1:]
        dst = "/SOCtopus/custom/sigma/" + file
        shutil.copyfile(filen, dst)
        

    update_payload = {"issue": {"subject": "Sigma Options", "project_id": 3, "tracker": "Sigma Options", "custom_fields": [ 
        {"id": 38, "name": "Import Custom Sigmas", "value": 0}]}} #changed adding filename to sigma after importing
    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(update_payload), headers=playbook_headers, verify=False)

    return 

# Imports rules when Sigma Options -> Backup is selected - backs up up all non community rules or community rules with auto update disabled 
# Backed up to /custom/backup
def play_backup(issue_id):
    plays = []
    
    plays = get_plays()
    
    for play in plays:
        if play['playbook'] != "community" or play['auto_update_sigma'] == "0":
            file = ("/SOCtopus/custom/backup/" + play['title'] + ".yml").replace(" ", "_")
            with open(file, 'w') as f:
                f.write(play['sigma_raw'])

    update_payload = {"issue": {"subject": "Sigma Options", "project_id": 3, "tracker": "Sigma Options", "custom_fields": [ 
        {"id": 37, "name": "Backup Custom Sigmas", "value": 0}]}} #changed adding filename to sigma after importing
    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(update_payload), headers=playbook_headers, verify=False)
    return

# Removes the update available flag when Sigma Options - Remove update available (all) is run
# If a major Sigma update is implemented on all rules (format change for instance), users may want to run this to remove the udpate available flag on all rules
def play_clear_update_available(issue_id):
    plays = []

    plays = get_plays()

    for play in plays:
        if play['update_available'] == "1":
            update_payload = {"issue": {"custom_fields": [ 
                {"id": 31, "name": "Update Available", "value": 0}]}} #changed adding filename to sigma after importing
            url = f"{playbook_url}/issues/{play['issue_id']}.json"
            r = requests.put(url, data=json.dumps(update_payload), headers=playbook_headers, verify=False)

    update_payload = {"issue": {"custom_fields": [ 
        {"id": 39, "name": "Clear Update Status (all)", "value": 0}]}} #changed adding filename to sigma after importing
    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(update_payload), headers=playbook_headers, verify=False)

    return

def navigator_update():
    # Get play data from Redmine
    url = f"{playbook_url}/issues.json?status_id=3&limit=100"
    response_data = requests.get(url, headers=playbook_headers, verify=playbook_verifycert).json()
 
    technique_payload = []
    for play in response_data['issues']:
        for custom_field in play['custom_fields']:
            if custom_field['id'] == 15 and (custom_field['value']):
                technique_id = custom_field['value'][0]
                technique_payload.append(
                    {"techniqueID": technique_id, "color": "#5AADFF", "comment": "", "enabled": True, "metadata": []})

    try:
        with open('/etc/playbook/nav_layer_playbook.json') as nav_layer_r:
            curr_json = json.load(nav_layer_r)
        curr_json['version'] = "3.0"
        curr_json['description'] = f'Current Coverage of Playbook - Updated {strftime("%Y-%m-%d %H:%M", gmtime())}'
        curr_json['techniques'] = technique_payload

    except FileNotFoundError as e:
        curr_json = \
            {
                "name": "Playbook",
                "version": "3.0",
                "domain": "mitre-enterprise",
                "description": f'Current Coverage of Playbook - Updated {strftime("%Y-%m-%d %H:%M", gmtime())}',
                "filters": {
                    "stages": ["act"],
                    "platforms": [
                        "windows",
                        "linux",
                        "mac"
                    ]
                },
                "sorting": 0,
                "viewMode": 0,
                "hideDisabled": False,
                "techniques": technique_payload,
                "gradient": {
                    "colors": ["#ff6666", "#ffe766", "#8ec843"],
                    "minValue": 0,
                    "maxValue": 100
                },
                "metadata": [],
                "showTacticRowBackground": False,
                "tacticRowBackground": "#dddddd",
                "selectTechniquesAcrossTactics": False
            }
    
    with open('/etc/playbook/nav_layer_playbook.json', 'w+') as nav_layer_w:
        json.dump(curr_json, nav_layer_w)


def thehive_casetemplate_update(issue_id):
    # Get play metadata - specifically the raw Sigma
    play_meta = play_metadata(issue_id)

    # Generate Sigma metadata
    sigma_meta = sigma_metadata(play_meta['sigma_raw'], play_meta['sigma_dict'], play_meta['playid'])

    # Check to see if there are any tasks - if so, get them formatted
    tasks = []
    if sigma_meta.get('tasks'):
        task_order = 0
        for task_title, task_desc in sigma_meta.get('tasks').items():
            task_order += 1
            tasks.append({"order": task_order, "title": task_title, "description": task_desc})
    else:
        tasks = []

    for analyzer in play_meta['case_analyzers']:
        minimal_name = re.sub(r' - \S*$', '', analyzer)
        tasks.insert(0, {"order": 0, "title": f"Analyzer - {minimal_name}", "description": minimal_name})

    # Build the case template
    case_template = \
        {
            "name": play_meta['playid'], 
            "severity": 2, 
            "tlp": 3, 
            "metrics": {}, 
            "customFields": {
                "playObjective": {
                    "string": sigma_meta['description']
                },
                "playbookLink": {
                    "string": f"{playbook_url}/issues/{issue_id}"
                }
            },
            "description": sigma_meta['description'],
            "tasks": tasks
        }

    # Is there a Case Template already created?
    if play_meta['hiveid']:
        # Case Template exists - let's update it
        url = f"{parser.get('hive', 'hive_url')}api/case/template/{play_meta['hiveid']}"
        requests.patch(url, data=json.dumps(case_template), headers=hive_headers,
                       verify=parser.getboolean('hive', 'hive_verifycert', fallback=False)).json()
    else:
        # Case Template does not exist - let's create it
        url = f"{parser.get('hive', 'hive_url')}api/case/template"
        r = requests.post(url, data=json.dumps(case_template), headers=hive_headers,
                          verify=parser.getboolean('hive', 'hive_verifycert', fallback=False))

        if r.status_code != 201:    
            print(f"TheHive Template Creation Failed: {r.__dict__}", file=sys.stderr)
        else:
            # Update Play (on Redmine) with Case Template ID
            r = r.json()
            url = f"{playbook_url}/issues/{issue_id}.json"
            data = '{"issue":{"custom_fields":[{"id":7,"value":"' + r['id'] + '"}]}}'
            requests.put(url, data=data, headers=playbook_headers, verify=playbook_verifycert)

    return 200, "success"


def elastalert_update(issue_id):
    # Get play metadata - specifically the raw Sigma
    play_meta = play_metadata(issue_id)

    # Generate Sigma metadata
    sigma_meta = sigma_metadata(play_meta['sigma_raw'], play_meta['sigma_dict'], play_meta['playid'])

    play_file = f"/etc/playbook-rules/{play_meta['playid']}.yaml"

    if os.path.exists(play_file):
        os.remove(play_file)

    if sigma_meta['level'] == "low":
        event_severity = 1
    elif sigma_meta['level'] == "medium":
        event_severity = 2
    elif sigma_meta['level'] == "high":
        event_severity = 3
    elif sigma_meta['level'] == "critical":
        event_severity = 4
    elif sigma_meta['level'] == "":
        event_severity = 2

    if play_meta['group'] != None:
        rule_category = play_meta['group']
    elif play_meta['ruleset'] != None:
        rule_category = play_meta['ruleset']
    else:
        rule_category = "None"
        
    try:
        if sigma_meta['product'] == 'osquery':
            shutil.copy('/etc/playbook-rules/osquery.template', play_file)
        elif sigma_meta['product'] != 'osquery' and play_meta['email_notifications'] == "1":
            shutil.copy('/etc/playbook-rules/generic_email.template', play_file)
        else:
            shutil.copy('/etc/playbook-rules/generic.template', play_file)
        with open(play_file, 'r+') as f:
            content = f.read()
            f.seek(0)
            f.truncate()
            # If Severity is High (3) or Critical (4), substitute Play metadata in TheHive alerter
            if event_severity >= 3:
                # Sub Severity 
                content = re.sub(r' severity:.*', f" severity: {event_severity}", content.rstrip())
                # Sub Play Name & Play ID for Elastalert Rule Name
                content = re.sub(r' title:.*', f" title: '{{rule[name]}} - {play_meta['playbook']}'", content.rstrip())          
                # Sub Play Name and Playbook Name for TheHive Alert Title
                content = re.sub(r'\btitle: .*', f"title: \"{sigma_meta['title']} - {play_meta['playbook']}\"", content.rstrip())          
                # Sub Play Tags
                content = re.sub(r'tags:.*', f"tags: ['playbook','playid-{play_meta['playid']}','{play_meta['playbook']}']",
                            content.rstrip())
                # Sub Redmine IssueID
                content = re.sub(r'\/6000', f"/{issue_id}", content.rstrip())
                # Sub Case Template
                content = re.sub(r'caseTemplate:.*', f"caseTemplate: '{play_meta['playid']}'", content.rstrip())
            else:
                # This is a low Severity alert - Remove TheHive alerter 
                content = re.sub(r"- \"hivealerter\"[\s\S]*5000'", "", content.rstrip()) 
            # Sub details in the ES_Alerter - play URL, etc
            content = re.sub(r'rule\.category:.*', f"rule.category: \"{rule_category}\"", content.rstrip())
            content = re.sub(r'\/6000', f"/{issue_id}", content.rstrip())
            content = re.sub(r'play_title:.\"\"', f"play_title: \"{sigma_meta['title']}\"", content.rstrip())
            content = re.sub(r'play_id:.\"\"', f"play_id: \"{play_meta['playid']}\"", content.rstrip())            
            content = re.sub(r'event\.severity:.*', f"event.severity: {event_severity}", content.rstrip())
            content = re.sub(r'sigma_level:.\"\"', f"sigma_level: \"{sigma_meta['level']}\"\n", content.rstrip())
            content = f"{content}\n{sigma_meta['raw_elastalert']}"
            f.write(content)
            f.close()

            # Check newly-written elastalert config file to make sure it is valid
            elastalert_config_status = "invalid"
            file = open(play_file, "r")
            for line in file:
                if re.search('realert', line):
                    elastalert_config_status = "valid"

            if elastalert_config_status != "valid":
                print ("Elastalert rule file invalid - deleting it")
                os.remove(play_file)

    except FileNotFoundError:
        print("ElastAlert Template File not found")
    except:
        print("Something else went wrong")
        if os.path.exists(play_file):
            os.remove(play_file)

    return 200, "success"


def elastalert_disable(issue_id):
    play = play_metadata(issue_id)
    play_file = f"/etc/playbook-rules/{play['playid']}.yaml"
    if os.path.exists(play_file):
        os.remove(play_file)
    return 200, "success"


def play_update(issue_id):
    # Get play metadata - specifically the raw Sigma
    play_meta = play_metadata(issue_id)

    # Generate Sigma metadata
    sigma_meta = sigma_metadata(play_meta['sigma_raw'], play_meta['sigma_dict'], play_meta['playid'])

    payload = {"issue": {"subject": sigma_meta['title'], "project_id": 1, "tracker": "Play", "custom_fields": [ \
        {"id": 1, "name": "Title", "value": sigma_meta['title']}, \
        {"id": 10, "name": "Level", "value": sigma_meta['level']}, \
        {"id": 6, "name": "ElastAlert Config", "value": sigma_meta['esquery']}, \
        {"id": 20, "name": "Product", "value": sigma_meta['product']}, \
        {"id": 3, "name": "Objective", "value": sigma_meta['description']}, \
        {"id": 2, "name": "Author", "value": sigma_meta['author']}, \
        {"id": 8, "name": "References", "value": sigma_meta['references']}, \
        {"id": 5, "name": "Analysis", "value": f"{sigma_meta['falsepositives']}{sigma_meta['logfields']}"}, \
        {"id": 15, "name": "Tags", "value": sigma_meta['tags']}]}}

    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(payload), headers=playbook_headers, verify=playbook_verifycert)

    return 'success', 200


def play_metadata(issue_id):
    play = dict()
    url = f"{playbook_url}/issues/{issue_id}.json"

    r = requests.get(url, headers=playbook_headers, verify=playbook_verifycert).json()
    if r['issue']['status']['name'] == "Active":
        status = "Active"
    else:
        status = "Not_Active" 
    for item in r['issue']['custom_fields']:
        if item['name'] == "Sigma":
            sigma_raw = item['value']
        elif item['name'] == "HiveID":
            play['hiveid'] = item['value']
        elif item['name'] == "PlayID":
            play['playid'] = item['value']
        elif item['name'] == "Playbook":
            play['playbook'] = item['value']
        elif item['name'] == "Case Analyzers":
            play['case_analyzers'] = item['value']
        elif item['name'] == "Rule ID":
            play['sigma_id'] = item['value']
        elif item['name'] == "Target Log":
            play['target_log'] = item['value']
        elif item['name'] == "Ruleset":
            play['ruleset'] = item['value']
        elif item['name'] == "Group":
            play['group'] = item['value']
        elif item['name'] == "Email Notifications":
            play['email_notifications'] = item['value']
        elif item['name'] == "Auto Update Sigma":
            play['auto_update_sigma'] = item['value']
        elif item['name'] == "Update Available":
            play['update_available'] = item['value']
        elif item['name'] == "Sigma File":
            play['sigma_file'] = item['value']
        elif item['name'] == "Sigma File":
            play['sigma_file'] = item['value']
        elif item['name'] == "Title":
            play['title'] = item['value']
    # Cleanup the Sigma data to get it ready for parsing
    sigma_raw = re.sub(
        "{{collapse\(View Sigma\)|<pre><code class=\"yaml\">|</code></pre>|}}", "", sigma_raw)
    sigma_dict = yaml.load(sigma_raw)

    return {
        'issue_id': issue_id,
        'playid': play.get('playid'),
        'hiveid': play.get('hiveid'),
        'sigma_dict': sigma_dict,
        'sigma_raw': sigma_raw,
        'sigma_formatted': f'{{{{collapse(View Sigma)\n<pre><code class="yaml">\n\n{sigma_raw}\n</code></pre>\n}}}}',
        'sigma_id': play.get('sigma_id'),
        'playbook': play.get('playbook'),
        'case_analyzers': play.get('case_analyzers'),
        'target_log': play.get('target_log'),
        'ruleset': play.get('ruleset'),
        'group': play.get('group'),
        'email_notifications': play.get('email_notifications'),
        'auto_update_sigma': play.get('auto_update_sigma'),
        'update_available': play.get('update_available'),
        'sigma_file': play.get('sigma_file'),
        'title': play.get('title'),
        'status': status
    }


def sigmac_generate(sigma):
    # Call sigmac tool to generate Elasticsearch config
    temp_file = tempfile.NamedTemporaryFile(mode='w+t')
    print(sigma, file=temp_file)
    temp_file.seek(0)

    sigmac_output = subprocess.run(["sigmac", "-t", "es-qs", "-c", "playbook/sysmon.yml",
                                    "-c", "playbook/securityonion-baseline.yml", "--backend-option", "keyword_whitelist=source.ip,destination.ip,source.port,destination.port", "--backend-option", "keyword_field=.keyword", "--backend-option", "analyzed_sub_field_name=.security", "--backend-option", "wildcard_use_keyword=false", temp_file.name],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='ascii')

    es_query = sigmac_output.stdout.strip() + sigmac_output.stderr.strip()
    return es_query


def sigma_metadata(sigma_raw, sigma, play_id):
    play = dict()

    # Call sigmac tool to generate ElastAlert config
    temp_file = tempfile.NamedTemporaryFile(mode='w+t')
    print(sigma_raw, file=temp_file)
    temp_file.seek(0)

    product = sigma['logsource']['product'] if 'product' in sigma['logsource'] else 'none'

    esquery = subprocess.run(["sigmac", "-t", "elastalert", "-c", "playbook/sysmon.yml",
                                    "-c", "playbook/securityonion-baseline.yml", "--backend-option", "keyword_whitelist=source.ip,destination.ip,source.port,destination.port", "--backend-option", "keyword_field=.keyword", "--backend-option", "analyzed_sub_field_name=.security", "--backend-option", "wildcard_use_keyword=false", temp_file.name],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='ascii')

    ea_config = re.sub(r'alert:\n.*filter:\n', 'filter:\n', esquery.stdout.strip(), flags=re.S)

    # Edit this to add the playid after the title - 
    ea_config = re.sub(r'name:\s\S*', f"name: {sigma.get('title')} - {play_id}", ea_config)

    # Prep ATT&CK Tags
    tags = re.findall(r"t\d{4}", ''.join(
        sigma.get('tags'))) if sigma.get('tags') else ''
    play['tags'] = [element.upper() for element in tags]

    return {
        'references': '\n'.join(sigma.get('references')) if sigma.get('references') else 'none',
        'title': sigma.get('title') if sigma.get('title') else 'none',
        'description': sigma.get('description') if sigma.get('description') else 'none',
        'level': sigma.get('level') if sigma.get('level') else 'none',
        'tags': play['tags'],
        'sigma': f'{{{{collapse(View Sigma)\n<pre><code class="yaml">\n\n{yaml2.dump(sigma)}\n</code></pre>\n}}}}',
        'author': sigma.get('author') if sigma.get('author') else 'none',
        'falsepositives': '_False Positives_\n' + '\n'.join(sigma.get('falsepositives')) if sigma.get(
            'falsepositives') else '_False Positives_\n Unknown',
        'logfields': '\n\n_Interesting Log Fields_\n' + '\n'.join(sigma.get('fields')) if sigma.get('fields') else '',
        'esquery': f'{{{{collapse(View ElastAlert Config)\n<pre><code class="yaml">\n\n{ea_config}\n</code></pre>\n}}}}',
        'raw_elastalert': ea_config,
        'tasks': sigma.get('tasks'),
        'product': product.lower(),
        'sigid': sigma.get('id') if sigma.get('id') else 'none'
    }


def play_create(sigma_raw, sigma_dict, playbook="imported", ruleset="", group="", license="", filename="", sigma_url=""):
    # Expects Sigma in dict format

    # Generate a unique ID for the Play
    play_id = uuid.uuid4().hex

    # Extract out all the relevant metadata from the Sigma YAML
    play = sigma_metadata(sigma_raw, sigma_dict, play_id[0:9])

    # If ElastAlert config = "", return with an error
    if play['raw_elastalert'] == "":
        return "Sigmac error when generating ElastAlert config"
    play_notes = "Play imported successfully."
    #play_status = "6" if play['raw_elastalert'] == "" else "2"
    #play_notes = "Play status set to Disabled - Sigmac error when generating ElastAlert config." \
    #    if play['raw_elastalert'] == "" else "Play imported successfully."

    # Create the payload
    payload = {"issue": {"subject": play['title'], "project_id": 1, "status_id": "2", "tracker": "Play",
                         "custom_fields": [
                             {"id": 1, "name": "Title", "value": play['title']},
                             {"id": 13, "name": "Playbook", "value": playbook},
                             {"id": 6, "name": "ElastAlert Config", "value": play['esquery']},
                             {"id": 10, "name": "Level", "value": play['level']},
                             {"id": 20, "name": "Product", "value": play['product']},
                             {"id": 3, "name": "Objective", "value": play['description']},
                             {"id": 2, "name": "Author", "value": play['author']},
                             {"id": 8, "name": "References", "value": play['references']},
                             {"id": 5, "name": "Analysis", "value": f"{play['falsepositives']}{play['logfields']}"},
                             {"id": 11, "name": "PlayID", "value": play_id[0:9]},
                             {"id": 15, "name": "Tags", "value": play['tags']},
                             {"id": 12, "name": "Rule ID", "value": play['sigid']},
                             {"id": 9, "name": "Sigma", "value": play['sigma']},
                             {"id": 18, "name": "Ruleset", "value": ruleset},
                             {"id": 19, "name": "Group", "value": group},
                             {"id": 26, "name": "License", "value": license},
                             {"id": 28, "name": "Sigma URL", "value": sigma_url},
                             {"id": 27, "name": "Sigma File", "value": filename}]}} #changed added update of filename field


    # POST the payload to Redmine to create the Play (ie Redmine issue)
    url = f"{playbook_url}/issues.json"
    r = requests.post(url, data=json.dumps(payload), headers=playbook_headers, verify=playbook_verifycert)

    # If Play creation was successful, update the Play notes & return the Play URL
    if r.status_code == 201:
        # Update the Play notes
        notes_payload = {"issue": {"notes": play_notes}}
        new_issue_id = r.json()
        url = f"{playbook_url}/issues/{new_issue_id['issue']['id']}.json"
        r = requests.put(url, data=json.dumps(notes_payload), headers=playbook_headers, verify=playbook_verifycert)
        # Notate success & Play URL
        play_creation = 201
        play_url = f"{playbook_external_url}/issues/{new_issue_id['issue']['id']}"
    # If Play creation was not successful, return the status code
    else:
        print("Play Creation Error - " + r.text, file=sys.stderr)
        play_creation = r.status_code
        play_url = "failed"

    return {
        'play_creation': play_creation,
        'play_url': play_url
    }


def play_unit_test (issue_id,unit_test_trigger,only_normalize=False):

    # Get Play metadata
    play_meta = play_metadata(issue_id)

    if not play_meta['target_log']:
        return "No Target Log"

    # Get Sigma metadata
    sigma_meta = sigma_metadata(play_meta['sigma_raw'], play_meta['sigma_dict'], play_meta['playid'])

    # If needed, normalize the Target Log if the trigger is "Target Log Updated"
    if unit_test_trigger == "Target Log Updated":
        if not "collapse(View Log)" in play_meta['target_log']:
            play_unit_test_normalize_log(play_meta['target_log'],issue_id,sigma_meta['title'])
            if only_normalize:
                return "only_normalize = True"
            
    # Insert the Target Log into Elasticsearch
    insert_log = play_unit_test_insert_log (play_meta['target_log'],play_meta['playid'])
    if insert_log['status_code'] != 201:
        play_unit_test_closeout(issue_id,"Failed",unit_test_trigger,f"Target Log insert into Elasticsearch failed: {insert_log['debug'] }")
        return
  
    # Tweak Play Elastalert alert for use with elastalert-test-rule & output to a temp file
    newline = '\n'
    elastalert_alert = f"es_host: {es_ip}{newline}es_port: 9200{newline}{sigma_meta['raw_elastalert']}{newline}alert: debug"
    elastalert_alert = re.sub(r"index: .*", f"index: {playbook_unit_test_index}", elastalert_alert)

    temp_file = tempfile.NamedTemporaryFile(mode='w+t')
    print(elastalert_alert, file=temp_file)
    temp_file.seek(0)

    # Run elastalert-test-rule
    elastalert_output = subprocess.run(["elastalert-test-rule", "--config", "playbook_elastalert_config.yaml", temp_file.name, "--formatted-output"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='ascii')

    if elastalert_output.returncode != 0:
        play_unit_test_closeout(issue_id,"Failed",unit_test_trigger,f"Stage - elastalert-test-rule execution failed: {elastalert_output}")
        return

    # Cleanup stdout, just leaving the status in JSON format
    elastalert_output = json.loads(f"{{{elastalert_output.stdout.strip().split('{', 1)[-1]}")

    if elastalert_output.get('writeback', {}).get('elastalert_error'):
        play_unit_test_closeout(issue_id,"Failed",unit_test_trigger,f"Stage - elastalert-test-rule: {elastalert_output['writeback']}")
    elif elastalert_output.get('writeback', {}).get('elastalert_status'):
        if  elastalert_output['writeback']['elastalert_status']['hits'] >= 1:
            print ("Passed")
            elastalert_status = "Passed"
            unit_test_debug = "N/A"
        else:
            print ("Failed")
            elastalert_status = "Failed"
            unit_test_debug = f"Stage - elastalert-test-rule: {elastalert_output['writeback']}"
    else:
        print ("Failed")
        elastalert_status = "Failed"
        unit_test_debug = f"Stage - elastalert-test-rule: {elastalert_output['writeback']}"

    # Closeout the unit test
    play_unit_test_closeout(issue_id,elastalert_status,unit_test_trigger,unit_test_debug)

    return {
        'unit_test_status': elastalert_status
    }

def play_unit_test_normalize_log (target_log, issue_id, play_name): 

    normalized_log =  f'{{{{collapse(View Log)\n<pre><code class="json">\n\n{target_log}\n</code></pre>\n}}}}',
    normalized_string = ''.join(normalized_log)

    payload = {"issue": {"project_id": 1, "tracker": "Play", "subject":play_name, "custom_fields": [ \
    {"id": 21, "value": normalized_string}]}}

    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(payload), headers=playbook_headers, verify=playbook_verifycert)

    return r

def play_unit_test_insert_log (target_log, playid):
    
    now_timestamp = strftime("%Y-%m-%d"'T'"%H:%M:%S", gmtime())

    target_log = re.sub("{{collapse\(View Log\)|<pre><code class=\"json\">|</code></pre>|}}", "",target_log)
    target_log = re.sub(r"@timestamp\":.\".*?,", f"@timestamp\": \"{now_timestamp}\",", target_log)
    target_log = json.loads(target_log).pop("_source")

    headers = {'Content-Type': 'application/json'}
    url = f"http://{es_ip}:9200/{playbook_unit_test_index}/_doc"
    r = requests.post(url, data=json.dumps(target_log), headers=headers, verify=es_verifycert)

    return { 
        'status_code': r.status_code,
        'debug': r.__dict__
    }

def play_unit_test_closeout (issue_id, status, unit_test_trigger, unit_test_debug="N/A"):
    newline = '\n'
    now_timestamp = strftime("%Y-%m-%d"'T'"%H:%M:%S", gmtime())
    play_note = f"Unit Test {status} - {now_timestamp}{newline}Test Triggered by: {unit_test_trigger}{newline}Debug: {unit_test_debug}"

    # Update Play Notes with details of the unit test's outcome
    play_update_notes(issue_id,play_note)

    # Update Play Unit-Test field with the status of the unit test (Passed|Failed)
    play_update_unit_test_field(issue_id,status)

    return


def play_update_notes (issue_id, play_notes):
    
    notes_payload = {"issue": {"notes": play_notes}}
    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(notes_payload), headers=playbook_headers, verify=playbook_verifycert)

    return {
        r.status_code
    }

def play_update_unit_test_field (issue_id, unit_test_status):
   
    payload = {"issue": {"project_id": 1, "tracker": "Play", "custom_fields": [ \
        {"id": 22, "value": unit_test_status}]}}

    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(payload), headers=playbook_headers, verify=playbook_verifycert)

    return {
        r.status_code
    }


def play_update_custom_field (issue_id, field_id, field_value, play_name):
   
    payload = {"issue": {"project_id": 1, "tracker": "Play", "subject":play_name, "custom_fields": [ \
        {"id": field_id, "value": field_value}]}}

    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(payload), headers=playbook_headers, verify=playbook_verifycert)

    return {
        r.status_code
    }


class YAMLPB(YAML):
    def dump(self, data, stream=None, **kw):
        inefficient = False
        if stream is None:
            inefficient = True
            stream = StringIO()
        YAML.dump(self, data, stream, **kw)
        if inefficient:
            return stream.getvalue()


yaml2 = YAMLPB()
