import yaml
from utils.yaml_loader import Loader
import os
from pymongo import MongoClient
from utils.common import tsnow, file_to_list
from modules.db_indexes import ensure_indexes
import importlib


def load_scopes():
    scopes = []
    for scope in config['scope']:
        if not 'domains' in scope:
            scope['domains'] = []
        if not isinstance(scope["domains"], list):
            raise ValueError(f'scope "{scope["name"]}" domains is not a List !!!')
        if 'sub_refilters' not in scope:
            scope['sub_refilters'] = []
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
        # ephemeral run-time dirs (kept off the mount so files don't end up
        # owned by container-root on the host); harvested/ stays on cwd to
        # persist via the bind mount.
        runtime_root = os.environ.get('AUTOBB_RUNTIME_DIR', '.')
        self.httprobes_savedir = f"{runtime_root}/httprobes/{ts_now}"
        self.fuzz_savedir = f"{runtime_root}/ffuf/{ts_now}"
        self.tmp_dir = f"{runtime_root}/tmp/{ts_now}"
        self.harvested_dir = f"harvested/{ts_now}"


with open("config.yaml","r") as config_stream:
    config = yaml.load(config_stream, Loader=Loader)

scopes = load_scopes()

mongodb_client = MongoClient(config['db']['conn_str'])
db = mongodb_client[config['db']['database']]
ensure_indexes(db)

#set alerter(s) from config and set alerter config (token etc)
#alerts.use can be a single name ("telegram") or a list (["telegram", "email"])
_alerts_use = config['alerts']['use']
if isinstance(_alerts_use, str):
    _alerts_use = [_alerts_use]

class _MultiAlerter:
    def __init__(self, names):
        self.backends = []
        for name in names:
            mod = importlib.import_module(f"modules.alerts.{name}")
            mod.config = config['alerts'][name]
            self.backends.append((name, mod))

    def notify(self, msg, **kwargs):
        results = []
        for name, mod in self.backends:
            try:
                results.append(mod.notify(msg, **kwargs))
            except TypeError:
                results.append(mod.notify(msg))
            except Exception as e:
                print(f"[alerts:{name}] notify failed: {e}")
        return results

alerter = _MultiAlerter(_alerts_use)

glob = Globals()
