from pwn import *

from Queue import Queue, Empty
from sleekxmpp import ClientXMPP, Iq
from sleekxmpp.xmlstream import ElementBase, register_stanza_plugin
from sleekxmpp.exceptions import IqError, IqTimeout, XMPPError

from xml.etree import cElementTree as ET

DEFAULT_JID = 'ahaha@ooo.vchat'

class VBotTranslate(ElementBase):
    name = 'translate'
    namespace = 'vbot:translate'
    plugin_attrib = 'translate'
    interfaces = set(('method', 'data'))
    sub_interfaces = interfaces

class VBotBase(ClientXMPP):
    def __init__(self):
        ClientXMPP.__init__(self, DEFAULT_JID, '')

        self.add_event_handler('session_bind', self.session_bind)
        self.add_event_handler("session_start", self.session_start)
        self.add_event_handler('message', self.message)

        self.target = None

        register_stanza_plugin(Iq, VBotTranslate)

    def check_fail(self, e=None):
        if e is not None:
            log.warn('checking fail: %r', e)
        print 'ERROR:', str(e)
        sys.exit(1)
        self.check_done()

    def check_done(self):
        self.set_stop()
        self.disconnect()
        sys.exit(0)

    def session_bind(self, event):
        log.info('logged in as %s', self.boundjid.user)

    def session_start(self, event):
        self.send_presence()
        self.get_roster()

    def message(self, msg):
        log.debug('recv %s', msg)

    def message_sync(self, msg, timeout=3):
        q = Queue()

        def waiter_handler(msg):
            res = msg.get('body')
            q.put(res)
        
        self.add_event_handler('message', waiter_handler, threaded=True, disposable=True)
        msg.send()

        try:
            return q.get(block=True, timeout=timeout)
        except Empty:
            return None

    def translate(self, method, data, encoding=None, timeout=None):
        assert self.target is not None
        iq = self.make_iq_get(ito=self.target)
        m = ET.Element('method')
        m.text = method
        p = ET.Element('data')
        p.text = data
        if encoding is not None:
            p.set('encode', {
                'hex': '1',
                'b64': '2',
                }[encoding])
        iq['translate'].append(m)
        iq['translate'].append(p)

        try:
            resp = iq.send(timeout=timeout)

            vt = resp['translate']

            enc = vt.find(vt._fix_ns('data')).get('encode')
            raw = vt['data']

            if enc == '1':
                raw = raw.decode('hex')
            elif enc == '2':
                raw = raw.decode('base64')
            log.debug('%s(%s) = %s', method, data,
                    raw.encode('hex'))
            return raw
        except IqError as e:
            return e.condition
        except IqTimeout as e:
            log.warn('Iq timeout')
            return None

class VBot(VBotBase):
    def __init__(self, server, *args, **kwargs):
        VBotBase.__init__(self, *args, **kwargs)
        self.remote_server = server
        self.add_event_handler('target_ready', self.target_ready, threaded=True, disposable=True)
        self.add_event_handler("message", self.first_message, disposable=True)

    def first_message(self, msg):
        assert self.target is None
        # whoever send the first message is the target vbot
        self.target = msg.get_from()
        self.event('target_ready')

    def target_ready(self, e):
        log.info('chatting with %s', self.target)

    def session_start(self, event):
        VBotBase.session_start(self, event)
        # connect to launcher
        conn = remote(*self.remote_server)
        conn.sendline(self.boundjid.user)
        conn.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    xmpp = VBotBase()
    xmpp.connect()
    xmpp.process(block=True)
