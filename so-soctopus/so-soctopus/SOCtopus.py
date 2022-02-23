#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect
from flask_bootstrap import Bootstrap
from destinations import createHiveAlert, createHiveCase, createMISPEvent, createSlackAlert, createFIREvent, \
    createRTIRIncident, showESResult, playbookWebhook, eventModifyFields, eventUpdateFields, \
    sendHiveAlert, sendHiveCase, processHiveReq, playbookSigmac, playbookCreatePlay
import ruamel.yaml
import sys
import random
import string

sys.getfilesystemencoding = lambda: 'UTF-8'

app = Flask(__name__)
Bootstrap(app)
app.secret_key = "".join([random.choice(string.printable) for i in range(500)])

yaml = ruamel.yaml.YAML(typ='safe')


@app.route("/fir/event/<esid>")
def sendFIR(esid):
    return createFIREvent(esid)


@app.route("/grr/flow/<esid>+<flow_name>")
def sendGRR(esid, flow_name):
    return createGRRFlow(esid, flow_name)


@app.route("/thehive/alert/<esid>")
def createAlertHive(esid):
    return createHiveAlert(esid)

@app.route("/thehive/case/<esid>")
def createCaseHive(esid):
    return createHiveCase(esid)

@app.route("/thehive/alert/send", methods=['POST'])
def sendAlertHive():
    if request.method == 'POST':
        if request.form['submit_button'] == 'Submit':
            result = request.form.to_dict()
            title = result['title']
            tlp = result['tlp']
            description = result['description'].strip('\"')
            tags = result['tags']
            artifact_string = result['artifact_string']
            sourceRef = result['sourceRef']
            return sendHiveAlert(title, tlp, tags, description, sourceRef, artifact_string)
        else:
            return render_template("cancel.html")

@app.route("/thehive/case/send", methods=['POST'])
def sendCaseHive():
    if request.method == 'POST':
        if request.form['submit_button'] == 'Submit':
            result = request.form.to_dict()
            title = result['title']
            #tlp = result['tlp']
            description = result['description'].strip('\"')
            #tags = result['tags']
            #artifact_string = result['artifact_string']
            #sourceRef = result['sourceRef']
            severity = result['severity']
            return sendHiveCase(title, description, severity)
        else:
            return render_template("cancel.html")

@app.route("/misp/event/<esid>")
def sendMISP(esid):
    return createMISPEvent(esid)


@app.route("/rtir/incident/<esid>")
def sendRTIR(esid):
    return createRTIRIncident(esid)


@app.route("/slack/<esid>")
def sendSlack(esid):
    return createSlackAlert(esid)

@app.route("/playbook/webhook", methods=['POST'])
def sendPlaybook():
    webhook_content = request.get_json()
    return playbookWebhook(webhook_content)


@app.route("/playbook/sigmac", methods=['POST'])
def sendSigma():
    raw = request.get_data(as_text=True)
    return playbookSigmac(raw)


@app.route("/playbook/play", methods=['POST'])
def sendSigmaYaml():
    sigma_raw = request.get_data(as_text=True)
    sigma_dict = yaml.load(sigma_raw)
    return playbookCreatePlay(sigma_raw, sigma_dict)


@app.route("/es/showresult/<esid>")
def sendESQuery(esid):
    return showESResult(esid)


@app.route("/es/event/modify/<esid>")
def sendModifyESEvent(esid):
    return eventModifyFields(esid)


@app.route("/es/event/update", methods=['GET', 'POST'])
def sendESEventUpdate():
    if request.method == 'POST':
        result = request.form
        esid = result['esid']
        esindex = result['esindex']
        tags = result['tags']
        return eventUpdateFields(esindex, esid, tags)


@app.route("/enrich", methods=['POST'])
def sendEnrich():
    if request.method == 'POST':
        webhook_content = request.get_json()
        return processHiveReq(webhook_content)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=7000)
