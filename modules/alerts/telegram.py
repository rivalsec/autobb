#!/usr/bin/env python3
import requests
import json
import datetime


config = None

msg_max_size = 4000
silent_start = "23:00"
silent_end = "9:00"
my_tz = datetime.timezone(datetime.timedelta(hours=5))

def is_silent_time():
    startTime =  datetime.datetime.strptime(silent_start, "%H:%M").time()
    endTime = datetime.datetime.strptime(silent_end, "%H:%M").time()
 
    nowTime = datetime.datetime.now(my_tz).time()
    if startTime < endTime: 
        return nowTime >= startTime and nowTime <= endTime 
    else: 
        #Over midnight: 
        return nowTime >= startTime or nowTime <= endTime 


def get_proxies():
    #optional alerts.proxy, e.g. socks5h://127.0.0.1:1080 or http://user:pass@host:3128
    proxy = config.get('proxy') if config else None
    if not proxy:
        return None
    if isinstance(proxy, str):
        return {'http': proxy, 'https': proxy}
    return proxy


def notify(msg, disable_notification = False):
    global msg_max_size
    if config and 'msg_max_size' in config:
        msg_max_size = config['msg_max_size']
    API_KEY = config['token']
    CHAT_ID = config['chat_id']
    proxies = get_proxies()

    file_msg = None
    if len(msg) > msg_max_size:
        file_msg = msg
        msg = msg[:msg_max_size] + "\n..."
    
    if is_silent_time():
        disable_notification = True

    data = {
        'chat_id': CHAT_ID,
        'disable_notification': disable_notification,
        'disable_web_page_preview': True
    }
    if not file_msg:
        data['text'] = msg
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        return requests.post(f"https://api.telegram.org/bot{API_KEY}/sendMessage", data=json.dumps(data), headers=headers, proxies=proxies)
    else:
        # telegram max caption 1024
        if len(msg) > 1010:
            msg = msg[:1010] + "\n..."
        data['caption'] = msg
        #full lines len
        linesc = len(file_msg.splitlines())
        files = {
            'document': (f'full{linesc}.txt', file_msg)
        }
        return requests.post(f"https://api.telegram.org/bot{API_KEY}/sendDocument", data=data, files=files, proxies=proxies)


if __name__=='__main__':
    import sys
    from pprint import pprint
    if len(sys.argv) not in (4, 5):
        print(f"Usage:\necho 'test' | {sys.argv[0]} BOT_TOKEN CHAT_ID MAX_MSG_SIZE [PROXY]", file=sys.stderr)
        sys.exit()
    msg = sys.stdin.read()
    if len(msg.strip()) > 0:
        config = {
            'token': sys.argv[1],
            'chat_id': sys.argv[2],
            'msg_max_size': int(sys.argv[3]),
            'proxy': sys.argv[4] if len(sys.argv) == 5 else None
        }
        pprint(vars(notify(msg)))
