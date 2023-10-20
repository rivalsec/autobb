import datetime
from modules.vulns import nuclei_active
from subs import db_get_modified, nuclei_notify
import logging
import compare
import random
import math
import os


def alert(nuclei_hits, chunk_index, chunks_len):
    nuclei_notify(
        nuclei_hits,
        lambda x: f'{x["scope"]}: {x["matched-at"]} [{x["info"]["severity"]}] {x["template-id"]} {x.get("matcher-name","")} {x.get("extracted-results","")}',
        f"FullScan chunk {chunk_index}/{chunks_len}\n"
    )


def fullscan(hosts):
    nuclei_hits = list(nuclei_active(config['fullscan']['nuclei_cmd'], hosts))
    #new nuclei hits
    up_fields = ["template-id","info","type","matcher-name","host","matched-at","meta","extracted-results","interaction","scope","curl-command"]
    index_fields = ["template-id","matcher-name","matched-at"]
    nuclei_hits_new = db_get_modified(nuclei_hits, db['nuclei_hits'], index_fields, up_fields, compare.nuclei_hit)
    return nuclei_hits


if __name__ == "__main__":
    from config import config, scopes, db, glob, alerter
    os.makedirs(glob.tmp_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt='%Y-%m-%d %H:%M',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(glob.tmp_dir + '/fullscan.log', 'w')
        ]
    )

    ndaysago = datetime.datetime.now() - datetime.timedelta(days=config['fullscan']['host_alive_in_days'])
    q = {"last_alive": {"$gte": ndaysago}}

    db_res = db['http_probes'].find(q)

    http_probes = list(db_res)
    random.shuffle(http_probes)
    
    allc = len(http_probes)
    
    # medium chunk size
    chunks_num = math.ceil(allc / config['fullscan']['chunk_max'])
    chunk_size = math.ceil(allc / chunks_num)

    logging.info(f"Fullscan of {len(http_probes)} with chunk medium size {chunk_size}")
    
    chi = 1
    for i in range(0, allc, chunk_size):
        logging.info(f"start chunk {chi}/{chunks_num}")
        x = i
        chunk = http_probes[x:x+chunk_size]
        nuclei_hits = fullscan(chunk)
        if len(nuclei_hits) > 0:
            alert(nuclei_hits, chi, chunks_num)
        chi += 1
