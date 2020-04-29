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

import requests

from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

import ruamel.yaml
from config import parser

yaml = ruamel.yaml.YAML(typ='safe')

playbook_headers = {'X-Redmine-API-Key': parser.get("playbook", "playbook_key"), 'Content-Type': 'application/json'}
playbook_url = parser.get("playbook", "playbook_url")

hive_headers = {'Authorization': f"Bearer {parser.get('hive', 'hive_key')}", 'Accept': 'application/json, text/plain',
                'Content-Type': 'application/json;charset=utf-8'}

playbook_verifycert = parser.getboolean('playbook', 'playbook_verifycert', fallback=False)

def navigator_update():
    # Get play data from Redmine
    url = f"{playbook_url}/issues.json?status_id=3"
    response_data = requests.get(url, headers=playbook_headers, verify=playbook_verifycert).json()

    technique_payload = []
    for play in response_data['issues']:
        for custom_field in play['custom_fields']:
            if custom_field['id'] == 27 and (custom_field['value']):
                technique_id = custom_field['value'][0]
                technique_payload.append(
                    {"techniqueID": technique_id, "color": "#5AADFF", "comment": "", "enabled": "true", "metadata": []})

    payload = {"name": "Playbook", "version": "2.1", "domain": "mitre-enterprise",
               "description": f"Current Coverage of Playbook - Updated {strftime('%Y-%m-%d %H:%M', gmtime())}",
               "filters": {"stages": ["act"], "platforms": ["windows"]}, "sorting": 0, "viewMode": 0,
               "hideDisabled": "false", "techniques": technique_payload,
               "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
               "metadata": [], "showTacticRowBackground": "false", "tacticRowBackground": "#dddddd",
               "selectTechniquesAcrossTactics": "true"}
    nav_layer = open('/etc/playbook/nav_layer_playbook.json', 'w')
    print(json.dumps(payload), file=nav_layer)
    nav_layer.close()


def thehive_casetemplate_update(issue_id):
    # Get play metadata - specifically the raw Sigma
    play_meta = play_metadata(issue_id)

    # Generate Sigma metadata
    sigma_meta = sigma_metadata(play_meta['sigma_raw'], play_meta['sigma_dict'])

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
    case_template = {"name": play_meta['playid'], "severity": 2, "tlp": 3, "metrics": {}, "customFields": { \
        "playObjective": {"string": sigma_meta['description']}, \
        "playbookLink": {"string": f"{playbook_url}/issues/{issue_id}"}}, \
                     "description": sigma_meta['description'], \
                     "tasks": tasks}

    # Is there a Case Template already created?
    if play_meta['hiveid']:
        # Case Template exists - let's update it
        url = f"{parser.get('hive', 'hive_url')}/api/case/template/{play_meta['hiveid']}"
        requests.patch(url, data=json.dumps(case_template), headers=hive_headers,
                       verify=parser.getboolean('hive', 'hive_verifycert', fallback=False)).json()

    else:
        # Case Template does not exist - let's create it
        url = f"{parser.get('hive', 'hive_url')}/api/case/template"
        r = requests.post(url, data=json.dumps(case_template), headers=hive_headers,
                          verify=parser.getboolean('hive', 'hive_verifycert', fallback=False)).json()

        # Update Play (on Redmine) with Template ID
        url = f"{playbook_url}/issues/{issue_id}.json"
        data = '{"issue":{"custom_fields":[{"id":8,"value":"' + r['id'] + '"}]}}'
        requests.put(url, data=data, headers=playbook_headers, verify=playbook_verifycert)

    return 200, "success"


def elastalert_update(issue_id):
    # Get play metadata - specifically the raw Sigma
    play_meta = play_metadata(issue_id)

    # Generate Sigma metadata
    sigma_meta = sigma_metadata(play_meta['sigma_raw'], play_meta['sigma_dict'])

    play_file = f"/etc/playbook-rules/{play_meta['playid']}.yaml"
    ea_config_raw = re.sub("{{collapse\(View ElastAlert Config\)|<pre><code class=\"yaml\">|</code></pre>|}}", "",
                           sigma_meta['esquery'])
    if os.path.exists(play_file):
        os.remove(play_file)

    if sigma_meta['level'] == "medium" or sigma_meta['level'] == "low":
        shutil.copy('/etc/playbook-rules/es-generic.template', play_file)
        for line in fileinput.input(play_file, inplace=True):
            line = re.sub(r'\/6000', f"/{issue_id}", line.rstrip())
            line = re.sub(r'play_title:.\"\"', f"play_title: \"{sigma_meta['title']}\"", line.rstrip())
            line = re.sub(r'sigma_level:.\"\"', f"sigma_level: \"{sigma_meta['level']}\"\n{ea_config_raw}",
                          line.rstrip())
            print(line)
    else:
        try:
            if sigma_meta['product'] == 'osquery':
                shutil.copy('/etc/playbook-rules/osquery.template', play_file)
            else:
                shutil.copy('/etc/playbook-rules/generic.template', play_file)
            for line in fileinput.input(play_file, inplace=True):
                line = re.sub(r'-\s''', f"- {play_meta['playbook']}", line.rstrip())
                line = re.sub(r'tags:.*$', f"tags: ['playbook','{play_meta['playid']}','{play_meta['playbook']}']",
                              line.rstrip())
                line = re.sub(r'\/6000', f"/{issue_id}", line.rstrip())
                line = re.sub(r'caseTemplate:.*', f"caseTemplate: '{play_meta['playid']}'\n{ea_config_raw}",
                              line.rstrip())
                print(line)

        except FileNotFoundError:
            print("ElastAlert Template File not found")

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
    sigma_meta = sigma_metadata(play_meta['sigma_raw'], play_meta['sigma_dict'])

    payload = {"issue": {"subject": sigma_meta['title'], "project_id": 1, "tracker": "Play", "custom_fields": [ \
        {"id": 6, "name": "Title", "value": sigma_meta['title']}, \
        {"id": 23, "name": "Level", "value": sigma_meta['level']}, \
        {"id": 15, "name": "ES Query", "value": sigma_meta['esquery']}, \
        {"id": 25, "name": "Product", "value": sigma_meta['product']}, \
        {"id": 2, "name": "Description", "value": sigma_meta['description']}, \
        {"id": 17, "name": "Author", "value": sigma_meta['author']}, \
        {"id": 16, "name": "References", "value": sigma_meta['references']}, \
        {"id": 7, "name": "Analysis", "value": f"{sigma_meta['falsepositives']}{sigma_meta['logfields']}"}, \
        {"id": 27, "name": "Tags", "value": sigma_meta['tags']}]}}

    url = f"{playbook_url}/issues/{issue_id}.json"
    r = requests.put(url, data=json.dumps(payload), headers=playbook_headers, verify=playbook_verifycert)

    return 'success', 200


def play_metadata(issue_id):
    play = dict()
    url = f"{playbook_url}/issues/{issue_id}.json"

    r = requests.get(url, headers=playbook_headers, verify=playbook_verifycert).json()

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
        elif item['name'] == "Signature ID":
            play['sigma_id'] = item['value']

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
        'case_analyzers': play.get('case_analyzers')
    }


def sigmac_generate(sigma):
    # Call sigmac tool to generate Elasticsearch config
    temp_file = tempfile.NamedTemporaryFile(mode='w+t')
    print(sigma, file=temp_file)
    temp_file.seek(0)

    sigmac_output = subprocess.run(["sigmac", "-t", "es-qs", temp_file.name, "-c", "playbook/sysmon.yml", "-c",
                                    "playbook/securityonion-network.yml", "-c", "playbook/securityonion-baseline.yml"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='ascii')

    es_query = sigmac_output.stdout.strip() + sigmac_output.stderr.strip()
    return es_query


def sigma_metadata(sigma_raw, sigma):
    play = dict()

    # Call sigmac tool to generate ElastAlert config
    temp_file = tempfile.NamedTemporaryFile(mode='w+t')
    print(sigma_raw, file=temp_file)
    temp_file.seek(0)

    product = sigma['logsource']['product'] if 'product' in sigma['logsource'] else 'none'

    esquery = subprocess.run(["sigmac", "-t", "elastalert", temp_file.name, "-c", "playbook/sysmon.yml", "-c",
                              "playbook/securityonion-network.yml", "-c", "playbook/securityonion-baseline.yml"],
                             stdout=subprocess.PIPE, encoding='ascii')

    ea_config = re.sub(r'alert:\n.*filter:\n', 'filter:\n', esquery.stdout.strip(), flags=re.S)
    ea_config = re.sub(r'name:\s\S*', f"name: {sigma.get('title')}", ea_config)

    # Prep ATT&CK Tags
    tags = re.findall(r"t\d{4}", ''.join(
        sigma.get('tags'))) if sigma.get('tags') else ''
    play['tags'] = [element.upper() for element in tags]

    return {
        'playid': play.get('playid'),
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


def play_create(sigma_raw, sigma_dict, playbook="imported", ruleset=""):
    # Expects Sigma in dict format

    # Extract out all the relevant metadata from the Sigma YAML
    play = sigma_metadata(sigma_raw, sigma_dict)

    # Generate a unique ID for the Play
    play_id = uuid.uuid4().hex

    # If ElastAlert config = "", set the play status to Disabled (id=7) else set it to Draft (id=1)
    # Also add a note to the play to make it clear as to why the status is Disabled
    play_status = "7" if play['raw_elastalert'] == "" else "1"
    play_notes = "Play status set to Disabled - Sigmac error when generating ElastAlert config." \
        if play['raw_elastalert'] == "" else "Play imported successfully."

    # Create the payload
    payload = {"issue": {"subject": play['title'], "project_id": 1, "status_id": play_status, "tracker": "Play",
                         "custom_fields": [
                             {"id": 6, "name": "Title", "value": play['title']},
                             {"id": 24, "name": "Playbook", "value": playbook},
                             {"id": 15, "name": "ES Query", "value": play['esquery']},
                             {"id": 23, "name": "Level", "value": play['level']},
                             {"id": 25, "name": "Product", "value": play['product']},
                             {"id": 2, "name": "Description", "value": play['description']},
                             {"id": 17, "name": "Author", "value": play['author']},
                             {"id": 16, "name": "References", "value": play['references']},
                             {"id": 7, "name": "Analysis", "value": f"{play['falsepositives']}{play['logfields']}"},
                             {"id": 28, "name": "PlayID", "value": play_id[0:9]},
                             {"id": 27, "name": "Tags", "value": play['tags']},
                             {"id": 30, "name": "Signature ID", "value": play['sigid']},
                             {"id": 21, "name": "Sigma", "value": play['sigma']},
                             {"id": 32, "name": "Category", "value": ruleset}
                             ]}}

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
        play_url = f"{playbook_url}/issues/{new_issue_id['issue']['id']}"
    # If Play creation was not successful, return the status code
    else:
        print("Play Creation Error - " + r.text, file=sys.stderr)
        play_creation = r.status_code
        play_url = "failed"

    return {
        'play_creation': play_creation,
        'play_url': play_url
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
