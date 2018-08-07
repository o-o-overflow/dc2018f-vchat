#!/usr/bin/env python2

from pwn import *
from vbot import VBot

CHECK_DELAY = 0
CHECK_TIMES = 40

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

            self.can_translate = True
            self.can_crash = False

            self.checks = 0
            for _ in xrange(CHECK_TIMES):
                if not self.translate_check():
                    break
                time.sleep(CHECK_DELAY)
            self.check_done()

        def translate_check(self):
            method = random.choice(['echo', 'echo', 'listen', 'msg', randoms(4)])
            try:
                expected = None
                if method == 'echo':
                    raw = randoms(random.randint(0, 10))
                    encoding = random.choice([None, 'hex', 'b64'])
                    data = _encode(raw, encoding)
                    log.info('checking echo %s %s', data, encoding)
                    expected = raw
                    ret = self.translate(method, data, encoding)
                elif method == 'listen':
                    raw = randoms(random.randint(10, 80), ''.join(map(chr, range(0x100))))
                    encoding = random.choice(['hex', 'b64'])
                    data = _encode(raw, encoding)
                    log.info('checking listen %s %s', data, encoding)
                    expected = "Sorry, I can't hear you"
                    ret = self.translate(method, data, encoding)
                elif method == 'msg':
                    # check direct message
                    msgs = {
                            'ping': 'pong',
                            'tip': 'try another challenge',
                            'bye': 'good choice, bye!',
                            }
                    msg = random.choice(msgs.keys())
                    expected = msgs[msg]
                    log.info('checking msg %s', msg)
                    ret = self.message_sync(self.make_message(self.target, msg))
                else:
                    raw = randoms(random.randint(0, 10))
                    encoding = random.choice([None, 'hex', 'b64'])
                    data = _encode(raw, encoding)
                    log.info('checking %s %s %s', method, data, encoding)
                    expected = ''
                    ret = self.translate(method, data, encoding)

                if method == 'msg':
                    if msg is 'bye':
                        self.can_translate = False
                        self.can_crash = True
                    else:
                        self.can_translate = True
                elif not self.can_translate:
                    expected = 'service-unavailable'

                if ret is None and self.can_crash:
                    # we might have triggered the bug and it crashs
                    log.warn('probably crashed?')
                    self.check_done()
                    return False

                assert expected == ret, 'got %s expected %r' % (ret,
                        expected)

            except Exception as e:
                self.check_fail(e)
                return False
            return True

    xmpp = MyVBot((host, port))
    xmpp.connect()
    xmpp.process(block=True)

    sys.exit(0)


if __name__ == '__main__':
    # logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    main()
