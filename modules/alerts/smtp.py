#!/usr/bin/env python3
import smtplib
import ssl
from email.message import EmailMessage


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

    host = config['host']
    port = int(config.get('port', 587))
    username = config.get('username')
    password = config.get('password')
    sender = config.get('from', username)
    recipients = config['to']
    if isinstance(recipients, str):
        recipients = [recipients]
    subject = config.get('subject', 'autobb alert')
    use_tls = config.get('tls', True)
    use_ssl = config.get('ssl', False)
    timeout = int(config.get('timeout', 30))

    email_msg = EmailMessage()
    email_msg['Subject'] = subject
    email_msg['From'] = sender
    email_msg['To'] = ', '.join(recipients)
    email_msg.set_content(msg)

    if file_msg:
        linesc = len(file_msg.splitlines())
        email_msg.add_attachment(
            file_msg.encode('utf-8'),
            maintype='text',
            subtype='plain',
            filename=f'full{linesc}.txt',
        )

    context = ssl.create_default_context()
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=timeout) as server:
            if username:
                server.login(username, password)
            server.send_message(email_msg)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as server:
            server.ehlo()
            if use_tls:
                server.starttls(context=context)
                server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(email_msg)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 6:
        print(
            f"Usage:\necho 'test' | {sys.argv[0]} HOST PORT USERNAME PASSWORD TO [FROM]",
            file=sys.stderr,
        )
        sys.exit()
    msg = sys.stdin.read()
    if len(msg.strip()) > 0:
        config = {
            'host': sys.argv[1],
            'port': int(sys.argv[2]),
            'username': sys.argv[3],
            'password': sys.argv[4],
            'to': sys.argv[5],
            'from': sys.argv[6] if len(sys.argv) > 6 else sys.argv[3],
        }
        notify(msg)
