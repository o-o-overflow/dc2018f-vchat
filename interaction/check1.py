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
    else:
        return raw

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])

    class MyVBot(VBot):
        def target_ready(self):
            VBot.target_ready(self)

            self.checks = 0
            self.schedule('translate_check', CHECK_DELAY, self.translate_check,
                    repeat=True)

        def translate_check(self):
            self.checks += 1
            if self.checks >= CHECK_TIMES:
                self.set_stop()
                self.disconnect()
                return
            method = random.choice(['echo', randoms(4)])
            try:
                if method == 'echo':
                    raw = randoms(random.randint(0, 10))
                    encoding = random.choice([None, 'hex'])
                    data = _encode(raw, encoding)
                    log.info('checking echo %s %s', data, encoding)
                    ret = self.translate(method, data, encoding)
                    assert ret == raw
                else:
                    raw = randoms(random.randint(0, 10))
                    encoding = random.choice([None, 'hex'])
                    data = _encode(raw, encoding)
                    log.info('checking %s %s %s', method, data, encoding)
                    ret = self.translate(method, data, encoding)
                    assert ret == ''
            except Exception as e:
                self.set_stop()
                self.disconnect()
                log.warn('translate check fail: %r', e)

    xmpp = MyVBot((host, port), 'ahaha@ooo.vchat', '')
    xmpp.connect()
    xmpp.process(block=True)

    sys.exit(0)


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    # context.log_level = 'DEBUG'
    main()
