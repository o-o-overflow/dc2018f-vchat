#!/usr/bin/env python2

from pwn import *
import sys, random, hashlib
from vbot import VBot
from pwnlib.util.fiddling import randoms

CHECK_DELAY = 1
CHECK_TIMES = 5

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

            for i in xrange(CHECK_TIMES):
                if not self.qrcode_check():
                    break
            self.check_done()

        def qrcode_check(self):
            txt = randoms(random.randint(10, 40))
            log.info('qrencode %s', txt)
            qr = self.translate('qrencode', txt)
            encoding = random.choice(['b64', 'hex'])
            log.info('qrdecode (%s)', encoding)
            txt_ = self.translate('qrdecode', _encode(qr, encoding),
                    encoding)
            if txt != txt_:
                self.check_fail('%s not matched %s' % (txt, txt_))
                return False
            return True


    xmpp = MyVBot((host, port))
    xmpp.connect()
    xmpp.process(block=True)

    sys.exit(0)


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    # context.log_level = 'DEBUG'
    main()
