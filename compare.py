#!/usr/bin/env python3
from pkgutil import iter_modules
import re
import tldextract

# CDN/WAF *front* detection for ASN-change noise suppression. Deliberately
# excludes general cloud *hosting* (AWS/GCP/Azure): those serve real origins, so
# a move onto them is a possible leaked origin we want to alert. CDN_FRONT_ASNS
# is populated from config['asn']['cdn_front_asns'] at startup (subs.py); the
# name pattern catches unlisted fronting providers by as_name (CDNVIDEO/CDNETWORKS).
CDN_FRONT_ASNS = set()
CDN_FRONT_NAME_RE = re.compile(
    r'(CDN|CLOUDFLARE|AKAMAI|FASTLY|CLOUDFRONT|INCAPSULA|IMPERVA|STACKPATH|'
    r'EDGECAST|EDGIO|LIMELIGHT|LLNW|HIGHWINDS|QUANTIL|GCORE|G-CORE|BUNNY|'
    r'KEYCDN|SUCURI|CACHEFLY|MEDIANOVA|EDGENEXUS)', re.I)


def _is_cdn_front(asn):
    """True when an asn dict looks like a CDN/WAF fronting provider (not general
    cloud hosting). Used to silence CDN<->CDN rotation while still surfacing a
    move to a real origin (including cloud-hosted ones)."""
    if not asn:
        return False
    num = asn.get('as_number')
    if num is not None and int(num) in CDN_FRONT_ASNS:
        return True
    return bool(CDN_FRONT_NAME_RE.search(asn.get('as_name') or ''))


def nuclei_hit(new, old, compare_history = False):
    """ NO COMPARE AT ALL
    """
    #    compare_fields = ["extracted-results","meta"] ???
    return {'equal':True, 'diffs':{}}

def _same_ips(new, old):
    """True only when both docs carry the same (non-empty) A-record set. Used to
    tell a real infra move from ASN dataset/BGP churn on an unchanged IP."""
    n, o = new.get('a'), old.get('a')
    return bool(n) and bool(o) and set(n) == set(o)


def _suppress_asn_noise(new, old, res):
    """Drop an asn.prefix diff (updating the value silently in the db) when it's
    not a meaningful infra change:
      - same IP -> dataset/BGP re-attribution on an unchanged IP, or
      - new network is a CDN/WAF front -> CDN<->CDN rotation / origin->CDN noise.
    The kept signal is a move TO a real origin, INCLUDING cloud-hosted ones
    (AWS/GCP/Azure are not treated as fronts). Other diffs still alert."""
    if 'asn.prefix' in res['diffs'] and (_same_ips(new, old) or _is_cdn_front(new.get('asn'))):
        del res['diffs']['asn.prefix']
        res['equal'] = not res['diffs']
    return res


def domain(new, old, compare_history = False):
    """
    cname only first, on others there are to many clouds chages
    """
    compare_fields = ['cname.0','asn.prefix']
    field_res = field_comparer(new,old,compare_fields, [tld_isequal_comp, asn_null_isequal_comp], compare_history)
    return _suppress_asn_noise(new, old, field_res)


def http_probe(new, old, compare_history = False):
    """
    'status_code','title','cnames'??,'tls-grab.fingerprint_sha256'
    """
    compare_fields = ['status_code','title','cnames.0','tls-grab.common_name.0','asn.prefix']
    field_res = field_comparer(new,old, compare_fields, [tld_isequal_comp, redirect_title_isequal_comp, asn_null_isequal_comp], compare_history)
    return _suppress_asn_noise(new, old, field_res)


def port(new, old, compare_history = False):
    return {'equal':True, 'diffs':{}}


def secret_hit(new, old, compare_history = False):
    """Never re-alert: secret workflow dedupes by stable leak fingerprint."""
    return {'equal':True, 'diffs':{}}


def http_path(new, old, compare_history = False):
    """
    fuzz hits: alert again only on status_code change
    """
    compare_fields = ['status_code']
    return field_comparer(new, old, compare_fields, [], compare_history)


def list_to_dict(l):
    return dict([ (str(i),v) for i,v in enumerate(l)])


def redirect_title_isequal_comp(field_name, new_val, old_val):
    """'Redirecting to <url>' titles carry volatile query params (oauth
    nonce/state, csrf tokens) that change on every probe. Treat as equal
    when the destination url is the same once its query string is dropped."""
    if field_name != 'title' or not new_val or not old_val:
        return False
    prefix = 'Redirecting to '
    if not (new_val.startswith(prefix) and old_val.startswith(prefix)):
        return False
    base = lambda t: t[len(prefix):].split('?', 1)[0]
    return base(new_val) == base(old_val)


def asn_null_isequal_comp(field_name, new_val, old_val):
    """asn enrichment is best-effort: a missing dataset (failed/disabled
    download) or an unresolved IP yields no asn. Treat any null<->prefix
    transition as equal so a failed download or first-time population never
    alerts; only a real prefix->prefix change is a meaningful diff."""
    if field_name != 'asn.prefix':
        return False
    return not new_val or not old_val


def tld_isequal_comp(field_name, new_val, old_val, fields = ['tls-grab.common_name.0','cnames.0','cname.0']):
    if field_name not in fields or not new_val or not old_val:
        return False
    tld_o = tldextract.extract(old_val)
    tld_n = tldextract.extract(new_val)
    if tld_o.suffix == tld_n.suffix and tld_o.domain == tld_n.domain:
        return True


def in_history(field_k, field_v, item, filters=[]):
    if '_diffs_history' not in item:
        return False
    if not field_v:
        field_v = 'null'
    for diff in item['_diffs_history']:
        if field_k not in diff:
            continue
        if diff[field_k] == field_v or any([filter(field_k, field_v, diff[field_k]) for filter in filters]):
            return True


def field_comparer(new, old, compare_fields, filters = [], compare_history = False):
    """
    compare by field 
    """
    diffs = {}
    for f in compare_fields:
        old_v = old
        new_v = new 
        for nf in f.split('.'):
            old_v = old_v.get(nf, {})
            new_v = new_v.get(nf, {})
            if isinstance(old_v, list):
                old_v = list_to_dict(old_v)
            if isinstance(new_v, list):
                new_v = list_to_dict(new_v)
        if old_v != new_v and not any([filter(f, new_v, old_v) for filter in filters]):
            if not compare_history:
                diffs[f] = old_v if old_v else 'null'
            else:
                if not in_history(f, new_v, old, filters=filters):
                    diffs[f] = old_v if old_v else 'null'
                else:
                    #not history diff write to history on compare_history if in_history! ahaha))
                    updiff = {f: old_v if old_v else 'null'}
                    if updiff not in old['_diffs_history']:
                        old['_diffs_history'].append(updiff)

            
    equal = True if not diffs else False
    return {'equal':equal, 'diffs':diffs}
