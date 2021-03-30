#!/usr/bin/env python3
# encoding: utf-8

import sys
import json

from elasticsearch import Elasticsearch
from cortexutils.analyzer import Analyzer

class ElasticsearchAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')

        self.es_cloudid = self.get_param('config.es_cloudid', None, 'Missing Elasticsearch Cloud ID')
        self.es_user = self.get_param('config.es_user', None, 'Missing Elasticsearch User')
        self.es_password = self.get_param('config.es_password', None, 'Missing Elasticsearch Password')

        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.proxies = self.get_param('config.proxy', None)

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "AssemblyLine"
        predicate = "RetrieveAnalysis"
        value = "0"

        if self.service == "RetrieveAnalysis":
            predicate = "RetrieveAnalysis"

        result = {
            "success": True
        }

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def search_for_analysis(self, ip, domain):
        es = Elasticsearch(cloud_id=self.es_cloudid,http_auth=(self.es_user,self.es_password))
        results = es.search(index="logs-*", body={"query": {"match": {"source.ip":"45.32.224.152"}}})
        # response = al_client.search.submission("file.md5:")
        response = results

    def run(self):
        if self.service == 'SearchIP':
            searchValue = self.get_param('ip', None, 'IP Address is missing')
            self.search_for_results(ip=filepath)

        elif self.service == 'SearchDomain':
            searchValue = self.get_param('domain', None, 'Domain is missing')
            self.search_for_results(domain=hashValue)

        else:
            self.error('Invalid service')

if __name__ == '__main__':
    ElasticsearchAnalyzer().run()