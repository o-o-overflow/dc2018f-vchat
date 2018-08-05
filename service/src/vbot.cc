#include <map>
#include <cstring>
#include <iostream>
#include <gloox/gloox.h>
#include <gloox/client.h>
#include <gloox/message.h>
#include <gloox/disco.h>
#include <gloox/util.h>
#include <gloox/messagehandler.h>
#include <gloox/messagesessionhandler.h>
#include <gloox/connectionlistener.h>
#include <gloox/stanzaextension.h>

static const std::string XMLNS_VBOT_TRANSLATE = "vbot:translate";
enum encoding {
    EncodingNone,
    EncodingHex,
};

inline uint8_t h2d(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return 0;
}

static std::string decode_hex(const std::string &raw) {
    size_t len = raw.length() / 2;
    char *buf = new char[len];
    for (int i = 0, j = 0; i < len; i++, j += 2) {
        if (isxdigit(raw[j]) && isxdigit(raw[j + 1])) {
            buf[i] = (h2d(raw[j]) << 4) + h2d(raw[j + 1]);
        } else {
            buf[i] = 0;
            break;
        }
    }
    return std::string(buf, len);
}

static std::string encode_hex(const std::string &raw) {
    static char hexdigits[] = "0123456789abcdef";
    size_t len = raw.length() * 2;
    char *buf = new char[len];
    for (int i = 0, j = 0; j < len; i++, j += 2) {
        uint8_t c = raw[i];
        buf[j] = hexdigits[c >> 4];
        buf[j + 1] = hexdigits[c & 0xf];
    }
    return std::string(buf, len);
}

class VTranslate: public gloox::StanzaExtension {
public:
    static const int type = gloox::StanzaExtensionType::ExtUser + 1;

    VTranslate(const gloox::Tag *tag) : gloox::StanzaExtension(type), valid_(false), encoding_(EncodingNone)
    {
        if (tag->hasChild("method") && tag->hasChild("data"))
        {
            valid_ = true;
            method_ = tag->findChild("method")->cdata();
            auto data = tag->findChild("data");
            data_ = data->cdata();
            encoding_ = static_cast<enum encoding>(atoi(data->findAttribute("encode").c_str()));
            switch (encoding_) {
                case EncodingHex:
                    data_ = decode_hex(data->cdata());
                    break;
                case EncodingNone:
                default:
                    data_ = data->cdata();
                    break;
            }
        }
    }

    virtual const std::string &filterString() const {
        static const std::string filter = "/iq/translate[@xmlns='" + XMLNS_VBOT_TRANSLATE + "']";
        return filter;
    }

    virtual gloox::StanzaExtension *newInstance(const gloox::Tag *tag) const {
        return new VTranslate(tag);
    }

    virtual gloox::Tag *tag() const {
        if (!valid_) {
            return nullptr;
        }
        auto *tag = new gloox::Tag("translate", gloox::XMLNS, XMLNS_VBOT_TRANSLATE);
        new gloox::Tag(tag, "method", method_);
        auto *data = new gloox::Tag(tag, "data", data_);
        if (encoding_ != EncodingNone) {
            data->addAttribute("encode", static_cast<int>(encoding_));
        }
        return tag;
    }
    
    virtual gloox::StanzaExtension *clone() const {
        return new VTranslate(*this);
    }

    const std::string &method() const {
        return method_;
    }

    const std::string &data() const {
        return data_;
    }

    void setData(const std::string &data) {
        if (gloox::util::checkValidXMLChars(data)) {
            data_ = data;
            encoding_ = EncodingNone;
        } else {
            data_ = encode_hex(data);
            encoding_ = EncodingHex;
        }
    }

private:
    std::string method_;
    std::string data_;
    bool valid_;
    enum encoding encoding_;
};

class VBot : public gloox::ConnectionListener,
             gloox::MessageSessionHandler,
             gloox::MessageHandler,
#ifdef DEBUG
             gloox::LogHandler,
#endif
             gloox::IqHandler
{
  public:
    VBot(const char *host, const char *target)
    {
        self_.setServer(host);
        self_.setUsername("vbot");
        target_.setServer(host);
        target_.setUsername(target);

        client_ = new gloox::Client(self_, "");
        client_->registerConnectionListener(this);
        client_->setTls(gloox::TLSDisabled);
        client_->setCompression(false);
        client_->disco()->setVersion("vbot", "0.1");
        client_->registerMessageSessionHandler(this, 0);
        client_->registerStanzaExtension(new VTranslate(new gloox::Tag("translate", gloox::XMLNS, XMLNS_VBOT_TRANSLATE)));
        client_->registerIqHandler(this, VTranslate::type);
#ifdef DEBUG
        client_->logInstance().registerLogHandler(gloox::LogLevelDebug, -1, this);
#endif
    }

    virtual ~VBot()
    {
        delete client_;
    }

    void start()
    {
        client_->connect(true);
    }

    virtual void onConnect()
    {
#ifdef DEBUG
        std::cout << "connected " << client_->username() << std::endl;
#endif

        auto session = new gloox::MessageSession(client_, target_);
        addMessageSession(session);
        session->send("hello");
    }

    virtual void onDisconnect(gloox::ConnectionError e)
    {
#ifdef DEBUG
        std::cout << "disconnected " << e << std::endl;
#endif
    }

    virtual bool onTLSConnect(const gloox::CertInfo &info)
    {
        return true;
    }

    virtual void handleMessageSession(gloox::MessageSession *session)
    {
#ifdef DEBUG
        std::cout << "new session with " << session->target() << std::endl;
#endif
        addMessageSession(session);
    }

    void addMessageSession(gloox::MessageSession *session)
    {
        auto username = session->target().username();
        if (vbot_sessions_.find(username) == vbot_sessions_.end()) {
            session->registerMessageHandler(this);
            vbot_sessions_[username] = session;
        }
    }

    void removeMessageSession(gloox::MessageSession *session)
    {
        auto username = session->target().username();
        auto key = vbot_sessions_.find(username);
        if (key != vbot_sessions_.end()) {
            vbot_sessions_.erase(key);
            auto s = key->second;
            s->removeMessageHandler();
            delete s;
        }
    }

    virtual void handleMessage(const gloox::Message &msg, gloox::MessageSession *session)
    {
#ifdef DEBUG
        std::cout << "subject " << msg.subject() << " body " << msg.body() << std::endl;
#endif
        auto body = msg.body();
        if (body == "ping") {
            session->send("pong");
        } else if (body == "tip") {
            session->send("try another challenge");
        } else if (body == "bye") {
            session->send("good choice, bye!");
            removeMessageSession(session);
        }
    }

    virtual bool handleIq(const gloox::IQ &iq) {
        auto username = iq.from().username();
#ifdef DEBUG
        std::cout << "got Iq from " << username << iq.tag()->xml() << std::endl;
#endif

        if (vbot_sessions_.find(username) == vbot_sessions_.end()) {
            return false;
        }
        switch (iq.subtype()) {
            case gloox::IQ::Get: {
                auto vt = static_cast<VTranslate *>(iq.findExtension<VTranslate>(VTranslate::type)->clone());
                if (vt == nullptr) {
                    break;
                }
                
                auto method = vt->method();
                auto data = vt->data();

                if (method == "echo") {
                    vt->setData(data);
                } else {
                    vt->setData("");
                }

                gloox::IQ re(gloox::IQ::Result, iq.from(), iq.id());
                re.setFrom(iq.to());
                re.addExtension(vt);
                client_->send(re);
                return true;
            }
            default:
                break;
        }

        return false;
    }

    virtual void handleIqID(const gloox::IQ &iq, int context) {
    }

#ifdef DEBUG
    virtual void handleLog(gloox::LogLevel level, gloox::LogArea area, const std::string &message)
    {
        std::cout << level << " " << message << std::endl;
    }
#endif

  private:
    gloox::JID self_, target_;
    gloox::Client *client_;
    VTranslate *vtranslate_ext_;
    std::map<std::string, gloox::MessageSession *> vbot_sessions_;
};

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("usage: %s host user\n", argv[0]);
    } else {
        VBot bot(argv[1], argv[2]);
        bot.start();
    }
    return 0;
}
