#!/usr/bin/env python3
import re
import sys
import json

def domain_cname_notinscope(domain, scopes, filters, weight = 10):
    """cname is not born from scope domains, except filters['cname']"""
    cnames = domain.get('cname',[])
    for cname in cnames:
        scope_parents = next( (s['domains'] for s in scopes if s['name']==domain['scope']) )
        #global filter cnames suffixes
        scope_parents.extend(filters['cname'])
        if not cname.lower().rstrip('.').endswith( tuple([x for x in scope_parents]) ):
            return f" !CNAME:{cname}", weight


def probe_cert_notinscope(http_probe, scopes, filters, weight = 10):
    """cert common name is not compare with scope domains"""
    if 'tls' not in http_probe:
        return False
    cert_cn = []
    # extension_server_name is not validate domain! don't add it )
    if 'subject_cn' in http_probe['tls']:
        cert_cn.append( re.sub("^\*\.",'', http_probe['tls']['subject_cn']) )
    cert_cn.extend( [re.sub("^\*\.",'',x) for x in http_probe['tls'].get('subject_an', []) ])
    cert_cn = list(dict.fromkeys(cert_cn)) # remove dupes same order
    for cn in cert_cn:
        scope_parents = next( (s['domains'] for s in scopes if s['name']==http_probe['scope']) )
        scope_parents.extend(filters['tls_dns'])
        if cn.lower().endswith( tuple([x for x in scope_parents]) ):
            return False #valid
    return f" !TLS_DNS:{cert_cn[:2]}", weight


def probe_cname_404(http_probe, scopes, filters, weight = 10):
    """cname is not born from scope domains, except filters['cname']"""
    cnames = http_probe.get('cnames',[]) #there is a cnameS in probe not cname
    for cname in cnames:
        scope_parents = next( (s['domains'] for s in scopes if s['name']==http_probe['scope']) )
        #global filter cnames suffixes
        scope_parents.extend(filters['cname'])
        if http_probe['status_code'] == 404 and not cname.lower().rstrip('.').endswith( tuple([x for x in scope_parents]) ):
            return f" !CNAME404:{cname}", weight


def probe_unusual404title(http_probe, scopes, filters, weight = 1):
    """Usually title on 404 is not exists or empty"""
    title = http_probe.get('title', '')
    for filter in filters.get('title404',''):
        if filter in title:
            return False
    if http_probe['status_code'] == 404 and len(title) > 0:
        return f" !404t:{len(title)}", weight


def have_diffs(item, scopes, filters, weight_by_diff = 1):
    """
    more diffs more weight
    """
    if 'diffs' in item:
        return f" !diffs:{item['diffs']}", weight_by_diff * len(item['diffs'])


def probe_location_notinscope(http_probe, scopes, filters, weight = 10):
    """redirected to domain outside the scope"""
    if 'location' not in http_probe:
        return False
    hostm = re.match(r'(http|https)://([0-9a-z\._-]+):?\d*', http_probe['location'].lower())
    if not hostm:
        return False
    host = hostm.group(2)
    scope_parents = next( (s['domains'] for s in scopes if s['name']==http_probe['scope']) )
    scope_parents.extend(filters.get('locations', []))

    if host.endswith( tuple([x for x in scope_parents]) ):
        return False #valid

    return f" !30x:{host}", weight


def probe_unusual_ports(http_probe, scopes, filters, weight = 20):
    if int(http_probe['port']) not in [80, 443]:
        return f" !port:{http_probe['port']}", weight


def juicer(items, validators, scopes, filters):
    """items juicer"""
    for item in items:
        item['juicy_weight'] = 0
        item['juicy_info'] = ''
        for validator in validators:
            res = validator(item, scopes, filters)
            if res:
                item['juicy_weight'] += res[1]
                item['juicy_info'] += res[0]


# validators
domain_validators = [domain_cname_notinscope,have_diffs]
http_probes_validators = [probe_unusual_ports, probe_cert_notinscope, probe_cname_404, probe_unusual404title, probe_location_notinscope, have_diffs]


if __name__=="__main__":
    from config import config, db, scopes
    juicy_sorts = [ 
        {'name':'domains', 'db':'domains', 'validator':domain_validators}, 
        {'name':'http_probes', 'db':'http_probes', 'validator':http_probes_validators}, 
    ]
    if len(sys.argv) != 2 or sys.argv[1] not in [x['name'] for x in juicy_sorts]:
        print(f"Error! Choose the type of juice from: {', '.join([x['name'] for x in juicy_sorts])}")
        print('Example: ./juicy.py domains | jq \'[.host, .juicy_weight, .juicy_info, .title] | join(" ")\' -r')
        sys.exit(1)

    juicy_type = next( (x for x in juicy_sorts if x['name'] == sys.argv[1]) )
    
    items = []
    for sn in [x['name'] for x in scopes]:
        items.extend(db[juicy_type['db']].find( {'scope':sn} ))
    juicer(items, juicy_type['validator'], scopes, config['juicer_filters'])
    items.sort(key=lambda x: x['juicy_weight'], reverse=True)
    for it in items:
        if it['juicy_weight'] == 0:
            continue
        it.pop('_id')
        it.pop('add_date')
        it.pop('last_alive')
        print(json.dumps(it))

