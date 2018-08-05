import logging
from pwn import *

from sleekxmpp import ClientXMPP, Iq
from sleekxmpp.xmlstream import ElementBase, register_stanza_plugin
from sleekxmpp.exceptions import IqError, IqTimeout, XMPPError

from xml.etree import cElementTree as ET

class VBotTranslate(ElementBase):
    name = 'translate'
    namespace = 'vbot:translate'
    plugin_attrib = 'translate'
    interfaces = set(('method', 'data'))
    sub_interfaces = interfaces

class VBotBase(ClientXMPP):

    def __init__(self, jid, password):
        ClientXMPP.__init__(self, jid, password)

        self.add_event_handler("session_start", self.session_start)
        self.add_event_handler("message", self.first_message, disposable=True)
        self.add_event_handler('target_ready', self.target_ready, threaded=True)

        self.target = None

        register_stanza_plugin(Iq, VBotTranslate)

    def check_fail(self, e=None):
        if e is not None:
            log.warn('checking fail: %s', e)
        self.check_done()

    def check_done(self):
        self.set_stop()
        self.disconnect()

    def session_start(self, event):
        self.send_presence()
        self.get_roster()
        log.info('logged in as %s', self.boundjid.user)

    def first_message(self, msg):
        assert self.target is None
        # whoever send the first message is the target vbot
        self.target = msg.get_from()
        self.add_event_handler('message', self.message)
        self.event('target_ready')

    def message(self, msg):
        log.debug('recv %s', msg)
        pass
        if msg['type'] in ('chat', 'normal'):
            msg.reply("Thanks for sending: %(body)s" % msg).send()

    def target_ready(self, e):
        log.info('chatting with %s', self.target)

    def message_sync(self, msg, timeout=3):
        o = []

        def waiter_handler(msg):
            res = msg.get('body')
            o.append(res)
        
        self.add_event_handler('message', waiter_handler, threaded=True, disposable=True)
        msg.send()

        end = time.time() + timeout
        while time.time() < end and len(o) == 0:
            time.sleep(0.1)
        return o[0]

    def translate(self, method, data, encoding=None):
        assert self.target is not None
        iq = self.make_iq_get(ito=self.target)
        m = ET.Element('method')
        m.text = method
        p = ET.Element('data')
        p.text = data
        if encoding is not None:
            p.set('encode', {
                'hex': '1'
                }[encoding])
        iq['translate'].append(m)
        iq['translate'].append(p)

        resp = iq.send()
        vt = resp['translate']
        enc = vt.find(vt._fix_ns('data')).get('encode')
        raw = vt['data']
        if enc == '1':
            raw = raw.decode('hex')
        log.debug('%s(%s) = %s', method, data,
                raw.encode('hex'))
        return raw

class VBot(VBotBase):
    def __init__(self, server, *args, **kwargs):
        VBotBase.__init__(self, *args, **kwargs)
        self.remote_server = server

    def session_start(self, event):
        VBotBase.session_start(self, event)
        # connect to launcher
        conn = remote(*self.remote_server)
        conn.sendline(self.boundjid.user)
        conn.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
    xmpp = VBotBase('ahaha@ooo.vchat', '')
    xmpp.connect()
    xmpp.process(block=True)
