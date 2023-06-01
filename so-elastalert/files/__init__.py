# -*- coding: utf-8 -*-
import copy
import time

from elasticsearch import Elasticsearch
from elasticsearch.client import EqlClient
from elasticsearch.exceptions import TransportError


class EqlClient(EqlClient):
    """ Extension of low level :class:`Elasticsearch` client with additional version resolving features """

    def __init__(self, conf):
        """
        :arg conf: es_conn_config dictionary. Ref. :func:`~util.build_es_conn_config`
        """
        super(EqlClient, self).__init__(Elasticsearch(
                                                  hosts=conf.get('es_hosts'),
                                                  verify_certs=conf['verify_certs'],
                                                  ca_certs=conf['ca_certs'],
                                                  basic_auth=(conf['es_username'],conf['es_password']),
                                                  ssl_show_warn=conf['ssl_show_warn'],
                                                  headers=conf['headers'],
                                                  timeout=conf['es_conn_timeout'],
                                                  client_cert=conf['client_cert'],
                                                  client_key=conf['client_key']))
        self._conf = copy.copy(conf)
        self._es_version = None

    @property
    def conf(self):
        """
        Returns the provided es_conn_config used when initializing the class instance.
        """
        return self._conf

    @property
    def es_version(self):
        """
        Returns the reported version from the Elasticsearch server.
        """
        if self._es_version is None:
            self._es_version = util.get_version_from_cluster_info(self)

        return self._es_version

    def is_atleastseven(self):
        """
        Returns True when the Elasticsearch server version >= 7
        """
        return int(self.es_version.split(".")[0]) >= 7

    def is_atleasteight(self):
        """
        Returns True when the Elasticsearch server version >= 8
        """
        return int(self.es_version.split(".")[0]) >= 8


    def resolve_writeback_index(self, writeback_index, doc_type):
        if doc_type == 'silence':
            return writeback_index + '_silence'
        elif doc_type == 'past_elastalert':
            return writeback_index + '_past'
        elif doc_type == 'elastalert_status':
            return writeback_index + '_status'
        elif doc_type == 'elastalert_error':
            return writeback_index + '_error'
        return writeback_index
        
class ElasticSearchClient(Elasticsearch):
    """ Extension of low level :class:`Elasticsearch` client with additional version resolving features """

    def __init__(self, conf):
        """
        :arg conf: es_conn_config dictionary. Ref. :func:`~util.build_es_conn_config`
        """
        super(ElasticSearchClient, self).__init__(
                                                  hosts=conf.get('es_hosts'),
                                                  verify_certs=conf['verify_certs'],
                                                  ca_certs=conf['ca_certs'],
                                                  basic_auth=(conf['es_username'], conf['es_password']),
                                                  ssl_show_warn=conf['ssl_show_warn'],
                                                  headers=conf['headers'],
                                                  timeout=conf['es_conn_timeout'],
                                                  client_cert=conf['client_cert'],
                                                  client_key=conf['client_key'])
        self._conf = copy.copy(conf)
        self._es_version = None

    @property
    def conf(self):
        """
        Returns the provided es_conn_config used when initializing the class instance.
        """
        return self._conf

    @property
    def es_version(self):
        """
        Returns the reported version from the Elasticsearch server.
        """
        if self._es_version is None:
            self._es_version = util.get_version_from_cluster_info(self)

        return self._es_version

    def is_atleastseven(self):
        """
        Returns True when the Elasticsearch server version >= 7
        """
        return int(self.es_version.split(".")[0]) >= 7

    def is_atleasteight(self):
        """
        Returns True when the Elasticsearch server version >= 8
        """
        return int(self.es_version.split(".")[0]) >= 8


    def resolve_writeback_index(self, writeback_index, doc_type):
        if doc_type == 'silence':
            return writeback_index + '_silence'
        elif doc_type == 'past_elastalert':
            return writeback_index + '_past'
        elif doc_type == 'elastalert_status':
            return writeback_index + '_status'
        elif doc_type == 'elastalert_error':
            return writeback_index + '_error'
        return writeback_index
