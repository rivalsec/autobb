import yaml
from utils.yaml_loader import Loader
import os
from datetime import datetime
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
        # Paths are materialized lazily on first access (see _lazy_dir) so that
        # scripts which merely `import config` (export.py, juicy.py, fullscan.py,
        # tests) don't litter empty timestamped dirs they never write to.
        runtime_root = os.environ.get('AUTOBB_RUNTIME_DIR', '.')
        self._dir_paths = {
            'httprobes_savedir': f"{runtime_root}/httprobes/{ts_now}",
            'fuzz_savedir': f"{runtime_root}/ffuf/{ts_now}",
            'tmp_dir': f"{runtime_root}/tmp/{ts_now}",
            'harvested_dir': f"harvested/{ts_now}",
        }
        self._dirs_created = set()

    def _lazy_dir(self, key: str) -> str:
        '''Return the path for `key`, creating the directory on first access.'''
        path = self._dir_paths[key]
        if key not in self._dirs_created:
            os.makedirs(path, exist_ok=True)
            self._dirs_created.add(key)
        return path

    @property
    def httprobes_savedir(self) -> str:
        return self._lazy_dir('httprobes_savedir')

    @property
    def fuzz_savedir(self) -> str:
        return self._lazy_dir('fuzz_savedir')

    @property
    def tmp_dir(self) -> str:
        return self._lazy_dir('tmp_dir')

    @property
    def harvested_dir(self) -> str:
        return self._lazy_dir('harvested_dir')


with open("config.yaml","r") as config_stream:
    config = yaml.load(config_stream, Loader=Loader)

scopes = load_scopes()


def http_header_args():
    '''Single source of truth for User-Agent / custom headers shared by all
    HTTP-making tools (httpx, nuclei, ffuf). Returns a list of CLI args
    (`-H "Name: Value"`) that each tool appends to its command.'''
    cfg = config.get('http_headers') or {}
    args = []
    ua = cfg.get('user_agent')
    if ua:
        args += ['-H', f'User-Agent: {ua}']
    for h in cfg.get('custom') or []:
        if h:
            args += ['-H', h]
    return args

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

    def notify(self, msg, *, source=None, items=None, **kwargs):
        dispatch = {}
        results = []
        for name, mod in self.backends:
            try:
                results.append(mod.notify(msg, **kwargs))
                dispatch[name] = "ok"
            except TypeError:
                results.append(mod.notify(msg))
                dispatch[name] = "ok"
            except Exception as e:
                dispatch[name] = f"{type(e).__name__}: {e}"
                print(f"[alerts:{name}] notify failed: {e}")
        if source is not None:
            try:
                doc = {
                    "created_at": datetime.now(),
                    "source": source,
                    "msg": msg,
                    "items": list(items) if items else [],
                    "dispatch": dispatch,
                }
                if kwargs:
                    doc["kwargs"] = kwargs
                db["alerts"].insert_one(doc)
            except Exception as e:
                print(f"[alerts:persist] insert failed: {e}")
        return results

alerter = _MultiAlerter(_alerts_use)

glob = Globals()
