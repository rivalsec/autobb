import requests


config = None
msg_max_size = 4000


def notify(msg):
    global msg_max_size
    if config and 'msg_max_size' in config:
        msg_max_size = config['msg_max_size']
    file_msg = None
    if len(msg) > msg_max_size:
        file_msg = msg
        msg = msg[:msg_max_size] + "\n..."
    data = {
        'token': config['token'],
        'chatId': config['chat_id'],
    }
    if not file_msg:
        data['text'] = msg
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        return requests.post(f"https://{config['host']}/bot/v1/messages/sendText", data=data, headers=headers)
    else:
        data['caption'] = msg
        files = {
            'file': ('full.txt', file_msg)
        }
        return requests.post(f"https://{config['host']}/bot/v1/messages/sendFile", data=data, files=files)


if __name__=='__main__':
    import sys
    from pprint import pprint
    if len(sys.argv) != 4:
        print(f"Usage:\necho 'test' | {sys.argv[0]} API_HOST BOT_TOKEN CHAT_ID", file=sys.stderr)
        sys.exit()
    msg = sys.stdin.read()
    if len(msg.strip()) > 0:
        config = {
            'host': sys.argv[1],
            'token': sys.argv[2],
            'chat_id': sys.argv[3],
        }
        pprint(vars(notify(msg)))
