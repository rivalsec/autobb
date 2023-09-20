import yaml
from utils.yaml_loader import Loader
import os
from pymongo import MongoClient
from utils.common import tsnow, file_to_list
import importlib


def load_scopes():
    scopes = []
    for scope in config['scope']:
        if not 'domains' in scope:
            scope['domains'] = []
        if not isinstance(scope["domains"], list):
            raise ValueError(f'scope "{scope["name"]}" domains is not a List !!!')
        if 'sub_filters' not in scope:
            scope['sub_filters'] = []
        if 'domains_file' in scope:
            scope['domains'].extend(file_to_list(scope['domains_file']))
        if 'cidr_file' in scope:
            if 'cidr' not in scope:
                scope['cidr'] = []
            scope['cidr'].extend(file_to_list(scope['cidr_file']))
        if 'ips_file' in scope:
            if 'ips' not in scope:
                scope['ips'] = []
            scope['ips'].extend(file_to_list(scope['ips_file']))
        scope['subs_recon'] = scope.get('subs_recon', True)
        scopes.append(scope)
    return scopes


class Globals:
    def __init__(self) -> None:
        ts_now = tsnow()
        self.cwd = os.path.dirname(os.path.realpath(__file__))
        self.httprobes_savedir = f"httprobes/{ts_now}"
        self.tmp_dir = f"tmp/{ts_now}"


with open("config.yaml","r") as config_stream:
    config = yaml.load(config_stream, Loader=Loader)

scopes = load_scopes()

mongodb_client = MongoClient(config['db']['conn_str'])
db = mongodb_client[config['db']['database']]

#set alerter from config and set alerter config (token etc)
alerter_name = config['alerts']['use']
alerter = importlib.import_module(f"modules.alerts.{alerter_name}")
alerter.config = config['alerts'][alerter_name]

glob = Globals()
