#!/usr/bin/env python2

from pwn import *
import sys, random, hashlib
from vbot import VBot
from pwnlib.util.fiddling import randoms

CHECK_DELAY = 1
CHECK_TIMES = 10

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])

    class MyVBot(VBot):
        def target_ready(self, e):
            VBot.target_ready(self, e)
            txts = {
                    'hello': '9c642bbc9eb2f34f50a1e54d7264b8d5',
                    'ooo': '4557f41c10ef0a996e40785144b18649',
                    'defcon': '7996fa8a813b4afe2f3a7ff96e6925e9',
                    'ctf': 'fafd4d0b916f284542a95d97aee1a118',
                    }
            txt = random.choice(txts.keys())
            log.info('speak %s', txt)
            now = time.time()
            v = self.translate('speak', txt)
            h = hashlib.md5(v).hexdigest()
            log.info('%s used %fs %s', txt, time.time() - now, h)
            if txts[txt] != h:
                self.check_fail('%s not matched %s' % (txt, txts[txt]))
            else:
                self.check_done()


    xmpp = MyVBot((host, port))
    xmpp.connect()
    xmpp.process(block=True)

    sys.exit(0)


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    # context.log_level = 'DEBUG'
    main()
