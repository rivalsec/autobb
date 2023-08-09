#!/usr/bin/env python3
from pkgutil import iter_modules
import tldextract

def nuclei_hit(new, old, compare_history = False):
    """ NO COMPARE AT ALL
    """
    #    compare_fields = ["extracted-results","meta"] ???
    return {'equal':True, 'diffs':{}}

def domain(new, old, compare_history = False):
    """
    cname only first, on others there are to many clouds chages
    """
    compare_fields = ['cname.0']
    field_res = field_comparer(new,old,compare_fields, [tld_isequal_comp], compare_history)
    return field_res


def http_probe(new, old, compare_history = False):
    """
    'status_code','title','cnames'??,'tls-grab.fingerprint_sha256'
    """
    compare_fields = ['status_code','title','cnames.0','tls-grab.common_name.0']
    field_res = field_comparer(new,old, compare_fields, [tld_isequal_comp], compare_history)
    return field_res


def port(new, old, compare_history = False):
    return {'equal':True, 'diffs':{}}


def list_to_dict(l):
    return dict([ (str(i),v) for i,v in enumerate(l)])


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
