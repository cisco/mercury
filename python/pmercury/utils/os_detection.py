import os
import sys
import gzip
import json
import math

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.pmercury_utils import *


class LogR:
    def __init__(self, coef, intc, labels):
        self.coef = coef
        self.intc = intc
        self.labels = labels

    def classify(self, x):
        scores = []
        for i in range(len(self.intc)):
            exp_ = (self.intc[i] + sum([a*b for a,b in zip(self.coef[i], x)]))
            scores.append(1/(1+math.e**(-exp_)))
        max_ = scores.index(max(scores))
        return self.labels[max_]


class OSDetection:
    def __init__(self):
        self.fingerprint_db_tcp  = self.read_db('resources/fingerprint-db-tcp-os.json.gz')
        self.fingerprint_db_tls  = self.read_db('resources/fingerprint-db-tls-os.json.gz')
        self.fingerprint_db_http = self.read_db('resources/fingerprint-db-http-os.json.gz')

        coef, intc, labels, self.os_map, self.os_len = self.get_model('resources/os_detection_model.json')
        self.clf = clf = LogR(coef, intc, labels)


    def classify(self, fps):
        sample = [0.0]*(self.os_len*3)
        for fp_type in fps:
            for str_repr in fps[fp_type]:
                self.update_sample(sample, str_repr, fp_type)

        if sum(sample) > 1:
            sample = self.normalize_sample(sample)
            return self.clf.classify(sample)
        else:
            return None

    def read_db(self, fname):
        fname = find_resource_path(fname)
        db = {}
        for line in gzip.open(fname):
            fp = json.loads(line)
            db[fp['str_repr']] = fp
        return db


    def get_os_info(self, os_str):
        platform = os_str[:os_str.index(')')]+')'
        edition  = os_str[:os_str.index(')',os_str.index(')')+1)]+')'
        return platform, edition, os_str


    def get_model(self, path):
        path = find_resource_path(path)
        for line in open(path):
            model = json.loads(line)
            break

        return model['coefficients'], model['intercepts'], model['labels'], model['os_map'], model['os_len']


    def update_sample(self, sample, str_repr, fp_type):
        os_info = None
        if fp_type == 'tcp' and str_repr in self.fingerprint_db_tcp:
            os_info = self.fingerprint_db_tcp[str_repr]['os_info']
            multiplier = 0
        elif fp_type == 'tls' and str_repr in self.fingerprint_db_tls:
            os_info = self.fingerprint_db_tls[str_repr]['os_info']
            multiplier = 1
        elif fp_type == 'http' and str_repr in self.fingerprint_db_http:
            os_info = self.fingerprint_db_http[str_repr]['os_info']
            multiplier = 2

        if os_info == None:
            return sample

        for k in os_info:
            if k in self.os_map:
                sample[self.os_map[k]+multiplier*self.os_len] += os_info[k]

        return sample


    def normalize_sample(self, sample):
        tcp_  = sample[0:self.os_len]
        tls_  = sample[self.os_len:2*self.os_len]
        http_ = sample[2*self.os_len:3*self.os_len]
        s1_ = sum(tcp_)
        s2_ = sum(tls_)
        s3_ = sum(http_)
        tcp_s  = list(map(lambda f_: f_/s1_ if s1_ > 0.0 else f_, tcp_))
        tls_s  = list(map(lambda f_: f_/s2_ if s2_ > 0.0 else f_, tls_))
        http_s = list(map(lambda f_: f_/s3_ if s3_ > 0.0 else f_, http_))
        r = []
        r.extend(tcp_s)
        r.extend(tls_s)
        r.extend(http_s)
        return r
