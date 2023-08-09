#!/usr/bin/env python3
from config import scopes, db
import datetime
import argparse
import json


def cli_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description='exporter')
    parser.add_argument('-g', '--get', choices=['scopes', 'domains', 'ports', 'http_probes'], help='get one of')
    parser.add_argument('-s', '--scope', help='scope to get, if not - all scopes')
    parser.add_argument('-l', '--last-alive',type=int, help='days then last time was alive', default=30)
    parser.add_argument('-p', '--print-field', type=str, help='object field to print, object json if not set')
    args = parser.parse_args()
    return args


def iprint(items, field = ''):
    for i in items:
        if field:
            print(i[field])
        else:
            print(json.dumps(i,default=str))


if __name__ == "__main__":
    args = cli_args()

    if args.get == "scopes":
        iprint(scopes, args.print_field)
        exit()
    
    ndaysago = datetime.datetime.now() - datetime.timedelta(days=args.last_alive)
    q = {"last_alive": {"$gte": ndaysago}}
    p = {}
    if args.print_field:
        p[args.print_field] = 1
    if args.scope:
        q['scope'] = args.scope
    db_res = db[args.get].find(q, p)
    iprint(db_res, args.print_field)
