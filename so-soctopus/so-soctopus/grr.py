import json
import requests
from requests.auth import HTTPBasicAuth

def listProcessFlow(client_id,grr_url,headers,cookies,grr_user,grr_pass):
    data = {
    "flow": {
      "args": {
        "@type": "type.googleapis.com/ListProcessesArgs"
      },
      "name": "ListProcesses"
    }
    }

    response = requests.post(grr_url + "/api/v2/clients/" + client_id + "/flows",
                           headers=headers, data=json.dumps(data),
                           cookies=cookies, auth=HTTPBasicAuth(grr_user, grr_pass))

    decoded_response = response.content.decode("utf-8")
    result = decoded_response.lstrip(")]}'")
    flow_result = json.loads(result)
    flow_id = flow_result["flowId"]
  
    return flow_id


def checkFlowStatus(client_id,grr_url,flow_id,headers,cookies,grr_user,grr_pass):
    response = requests.get(grr_url + "/api/clients/" + client_id + "/flows/" + flow_id,
                       headers=headers,
                       cookies=cookies, auth=HTTPBasicAuth(grr_user, grr_pass))

    decoded_response = response.content.decode("utf-8")
    result = decoded_response.lstrip(")]}'")
    status_check = json.loads(result)
    status = str(status_check["value"]["state"]["value"].lower())

    return status

def downloadFlowResults(client_id,grr_url,flow_id,headers,cookies,grr_user,grr_pass):
    response = requests.get(grr_url + "/api/clients/" + client_id + "/flows/" + flow_id + "/exported-results/csv-zip",
                           headers=headers,
                           cookies=cookies, auth=HTTPBasicAuth(grr_user, grr_pass))
    filepath = "/tmp/soctopus/" + client_id + ".zip"
    with open(filepath, "wb") as compressed_flow_results:
      compressed_flow_results.write(response.content)
