#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
from requests.utils import quote
from config import parser, es_index

esserver = parser.get('es', 'es_url')
es_user = parser.get('es', 'es_user', fallback="")
es_pass = parser.get('es', "es_pass", fallback="")
es_verifycert = parser.getboolean('es', 'es_verifycert', fallback=False)

search_index = f'*:{es_index}'


def get_hits(esid: str) -> dict:
    query = {"query": {"bool": {"must": {"match": {'_id': esid}}}}}
    res_json = __es_search__(query)
    if res_json['hits']['total']['value'] > 0:
        return res_json


def get_conn(conn_id: str) -> dict:
    query = {"bool": {"must": [{"match": {"event_type": "bro_conn"}}, {"match": {"uid": conn_id}}]}}
    res_json = __es_search__(query)
    if res_json['hits']['total']['value'] > 0:
        return res_json


def do_update(esindex: str, esid: str, tags: str) -> dict:
    local_index = esindex.split(":")[1]
    query = {"doc": {"tags": tags}}
    return __es_update__(index=local_index, es_query=query, es_id=esid)


def __es_search__(es_query: dict) -> dict:
    if es_user and es_pass:
        response = requests.get(f'{esserver}/{quote(search_index)}/_search', json=es_query,
                                verify=es_verifycert, auth=(es_user, es_pass))
    else:
        response = requests.get(f'{esserver}/{quote(search_index)}/_search', json=es_query,
                                verify=es_verifycert)
    return response.json()


def __es_update__(index: str, es_query: dict, es_id: str) -> dict:
    if es_user and es_pass:
        response = requests.post(f'{esserver}/{quote(index)}/_update/{quote(es_id)}?refresh=true',
                                 json=es_query, verify=es_verifycert, auth=(es_user, es_pass))
    else:
        response = requests.post(f'{esserver}/{quote(index)}/_update/{quote(es_id)}?refresh=true',
                                 json=es_query, verify=es_verifycert)
    return response.json()
