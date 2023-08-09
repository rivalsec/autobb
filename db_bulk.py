from pymongo import InsertOne, UpdateOne, DeleteOne, collection
from datetime import datetime


def timenow():
    return datetime.now().replace(microsecond=0)


def findone_list(lst, query):
    item_iter = ( i for i in lst if all(i[k] == v for k, v in query.items()) ) 
    item = next(item_iter , None)
    return item


def db_get_modified_bulk(items, db_collection, key_fields, fields, compare_func):
    """returns modified

    key_field - key for find same item in db,
    fields - use only these to insert and update items in db collection,
    db_collection - mongodb collection,
    compare_func - funqction to find modified
    """
    coll_preload = list(db_collection.find())
    bulk_changes = {
        "insert": [], 
        "update": []
    }
    out = []
    #kostili ) for back comp
    if not isinstance(key_fields, list):
        key_fields = [key_fields]

    for item in items:
        find_q = {}
        for key_field in key_fields:
            find_q[key_field] = item.get(key_field)
        
        #update item (update all) always
        update_item = {'last_alive': timenow()}
        for f in fields:
            if f in item:
                update_item[f] = item[f]

        #find in preloaded list
        old_item = findone_list(coll_preload, find_q)

        if not old_item:
            update_item['add_date'] = timenow()
            bulk_changes["insert"].append(update_item)
        else:
            #unset fields
            unset_query = {}
            for f in fields:
                if f not in item:
                    unset_query[f] = ''

            # find changed based on compare_func
            item['_id'] = old_item['_id']
            item['_diffs_history'] = old_item.get('_diffs_history',[])
            update_item['_diffs_history'] = item['_diffs_history']
            
            # only if changed
            comp_res = compare_func(item, old_item, True)
            if not comp_res['equal']:
                update_item['update_date'] = timenow()
                # if not comp_res['diffs'] in item['_diffs_history']:
                item['diffs'] = comp_res['diffs']
                if comp_res['diffs'] not in item['_diffs_history']:
                    item['_diffs_history'].append(comp_res['diffs']) 
                out.append(item) # why here?

            # update all always dates / diff filtered by comparer func etc
            bulk_changes["update"].append(UpdateOne({'_id':item['_id']}, {'$set': update_item, '$unset': unset_query}))

    # bulk insert 
    if bulk_changes["insert"]:
        insert_res = db_collection.insert_many(bulk_changes["insert"])
        # _id is auto updates in bulk_changes["insert"] item
        out.extend(bulk_changes["insert"])

    #bulk update
    if bulk_changes["update"]:
        update_res = db_collection.bulk_write(bulk_changes["update"])
        #out append? 

    return out