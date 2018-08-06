#!/usr/bin/env python2

from pwn import *
import sys, random
from vbot import VBot
from pwnlib.util.fiddling import randoms

CHECK_DELAY = 1
CHECK_TIMES = 10

def _encode(raw, encoding):
    if encoding == 'hex':
        return raw.encode('hex')
    elif encoding == 'b64':
        return raw.encode('base64').replace('\n', '')
    else:
        return raw

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])

    class MyVBot(VBot):
        def target_ready(self, e):
            VBot.target_ready(self, e)

            self.checks = 0
            self.schedule('translate_check', CHECK_DELAY, self.translate_check,
                    repeat=True)
            self.message_check()

        def message_check(self):
            # check direct message
            msgs = {
                    'ping': 'pong',
                    'tip': 'try another challenge',
                    'bye': 'good choice, bye!',
                    }
            msg = random.choice(msgs.keys())

            log.info('checking msg %s', msg)
            if self.message_sync(self.make_message(self.target, msg)) != msgs[msg]:
                self.check_fail('unmatched response for %s' % msg)

        def translate_check(self):
            self.checks += 1
            if self.checks >= CHECK_TIMES:
                self.check_done()
                return
            method = random.choice(['echo', randoms(4)])
            try:
                if method == 'echo':
                    raw = randoms(random.randint(0, 10))
                    encoding = random.choice([None, 'hex', 'b64'])
                    data = _encode(raw, encoding)
                    log.info('checking echo %s %s', data, encoding)
                    ret = self.translate(method, data, encoding)
                    assert ret == raw
                else:
                    raw = randoms(random.randint(0, 10))
                    encoding = random.choice([None, 'hex', 'b64'])
                    data = _encode(raw, encoding)
                    log.info('checking %s %s %s', method, data, encoding)
                    ret = self.translate(method, data, encoding)
                    assert ret == ''
            except Exception as e:
                self.check_fail(e)

    xmpp = MyVBot((host, port))
    xmpp.connect()
    xmpp.process(block=True)

    sys.exit(0)


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    # context.log_level = 'DEBUG'
    main()
