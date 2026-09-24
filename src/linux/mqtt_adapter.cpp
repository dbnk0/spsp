/**
 * @file mqtt_adapter.cpp
 * @author Dávid Benko (davidbenko@davidbenko.dev)
 * @brief MQTT adapter for Linux plaform
 *
 * @copyright Copyright (c) 2024
 *
 */

#include <chrono>
#include <thread>

#include "spsp/logger.hpp"
#include "spsp/mac.hpp"
#include "spsp/mqtt_adapter.hpp"

using namespace std::chrono_literals;

// Log tag
static const char* SPSP_LOG_TAG = "SPSP/Far/MQTT/Adapter";

namespace
{
    // Paho invokes MQTTAsync_connected() on its receive thread while holding
    // its internal mutex. MQTTAsync_waitForCompletion() would try to acquire
    // the same mutex and deadlock that thread.
    thread_local bool inConnectedCallback = false;

    class ConnectedCallbackScope
    {
        bool m_previous;

    public:
        ConnectedCallbackScope() : m_previous{inConnectedCallback}
        {
            inConnectedCallback = true;
        }

        ~ConnectedCallbackScope()
        {
            inConnectedCallback = m_previous;
        }
    };
} // namespace

namespace SPSP::FarLayers::MQTT
{
    Adapter::Adapter(const Config& conf) : m_conf{conf}
    {
        int ret;

        // Client ID
        std::string clientId;

        if (m_conf.auth.clientId.empty()) {
            clientId = MQTT_CLIENT_ID_PREFIX;

            uint8_t mac[8];
            char macStr[16];
            getLocalMAC(mac);
            sprintf(macStr, "%02x%02x%02x%02x%02x%02x",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            clientId += macStr;
        } else {
            clientId = m_conf.auth.clientId;
        }

        // Create client
        ret = MQTTAsync_create(&m_mqtt, m_conf.connection.uri.c_str(),
                               clientId.c_str(), MQTTCLIENT_PERSISTENCE_NONE,
                               nullptr);
        if (ret != MQTTASYNC_SUCCESS) {
            throw AdapterError(std::string("MQTT handle create failed: ") +
                               MQTTAsync_strerror(ret));
        }

        // Set callbacks
        ret = MQTTAsync_setCallbacks(m_mqtt, this, &Adapter::connLostCb,
                                     &Adapter::subMsgCb, nullptr);
        if (ret != MQTTASYNC_SUCCESS) {
            MQTTAsync_destroy(&m_mqtt);
            throw AdapterError(std::string("Set underlaying callbacks failed: ") +
                               MQTTAsync_strerror(ret));
        }

        // Establish connection
        if (!this->connect()) {
            MQTTAsync_destroy(&m_mqtt);
            throw AdapterError("Connection failed");
        }
    }

    Adapter::~Adapter()
    {
        MQTTAsync_destroy(&m_mqtt);
    }

    bool Adapter::connect()
    {
        int ret;

        MQTTAsync_willOptions lastWillOpts = MQTTAsync_willOptions_initializer;
        MQTTAsync_SSLOptions sslOptions = MQTTAsync_SSLOptions_initializer;
        MQTTAsync_connectOptions connOpts = MQTTAsync_connectOptions_initializer;

        // Populate connection options
        lastWillOpts.topicName = this->stringToCOrNull(m_conf.lastWill.topic);
        lastWillOpts.message = this->stringToCOrNull(m_conf.lastWill.msg);
        lastWillOpts.qos = m_conf.lastWill.qos;
        lastWillOpts.retained = m_conf.lastWill.retain;

        sslOptions.trustStore = this->stringToCOrNull(m_conf.connection.verifyCrt);
        sslOptions.keyStore = this->stringToCOrNull(m_conf.auth.crt);
        sslOptions.privateKey = this->stringToCOrNull(m_conf.auth.crtKey);
        sslOptions.enableServerCertAuth = !m_conf.connection.verifyCrt.empty();
        sslOptions.verify = !m_conf.connection.verifyCrt.empty();

        connOpts.automaticReconnect = true;
        connOpts.keepAliveInterval = m_conf.connection.keepalive;
        connOpts.cleansession = true;
        connOpts.will = m_conf.lastWill.topic.empty() ? nullptr : &lastWillOpts;
        connOpts.username = m_conf.auth.username.c_str();
        connOpts.password = this->stringToCOrNull(m_conf.auth.password);
        connOpts.ssl = &sslOptions;
        connOpts.onFailure = &Adapter::connFailureCb;
        connOpts.context = this;

        // Set connected callback
        ret = MQTTAsync_setConnected(m_mqtt, this, &Adapter::connectedCb);
        if (ret != MQTTASYNC_SUCCESS) {
            SPSP_LOGE("Couldn't set connected callback: %s",
                      MQTTAsync_strerror(ret));
            return false;
        }

        // Connect
        ret = MQTTAsync_connect(m_mqtt, &connOpts);
        if (ret != MQTTASYNC_SUCCESS) {
            SPSP_LOGE("Connect: %s", MQTTAsync_strerror(ret));
        }
        return ret == MQTTASYNC_SUCCESS;
    }

    bool Adapter::publish(const std::string& topic, const std::string& payload)
    {
        MQTTAsync_message msg = MQTTAsync_message_initializer;
        msg.payload = const_cast<char*>(payload.c_str());
        msg.payloadlen = static_cast<int>(payload.size());
        msg.qos = m_conf.connection.qos;

        MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;

        // Enqueue
        // Doesn't wait for delivery!
        return MQTTAsync_sendMessage(m_mqtt, topic.c_str(), &msg, &opts) == MQTTASYNC_SUCCESS;
    }

    bool Adapter::subscribe(const std::string& topic)
    {
        int ret;
        MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;

        ret = MQTTAsync_subscribe(m_mqtt, topic.c_str(), m_conf.connection.qos, &opts);
        if (ret != MQTTASYNC_SUCCESS) {
            return false;
        }

        if (inConnectedCallback) {
            // The request has been queued. Do not wait for its SUBACK here:
            // this is Paho's receive thread, which must return before it can
            // process that acknowledgement.
            SPSP_LOGD("Subscribe request queued during reconnection: '%s'",
                      topic.c_str());
            return true;
        }

        // Wait for result
        ret = MQTTAsync_waitForCompletion(m_mqtt, opts.token, 5000);
        return ret == MQTTASYNC_SUCCESS;
    }

    bool Adapter::unsubscribe(const std::string& topic)
    {
        int ret;
        MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;

        ret = MQTTAsync_unsubscribe(m_mqtt, topic.c_str(), &opts);
        if (ret != MQTTASYNC_SUCCESS) {
            return false;
        }

        // Wait for result
        ret = MQTTAsync_waitForCompletion(m_mqtt, opts.token, 5000);
        return ret == MQTTASYNC_SUCCESS;
    }

    void Adapter::connectedCb(void* ctx, char* cause)
    {
        auto inst = static_cast<Adapter*>(ctx);

        SPSP_LOGI("Connected");

        if (inst->getConnectedCb() != nullptr) {
            const ConnectedCallbackScope scope;
            inst->getConnectedCb()();
        }
    }

    void Adapter::connFailureCb(void* ctx, MQTTAsync_failureData* resp)
    {
        SPSP_LOGE("Connection failed: %s (%s)", MQTTAsync_strerror(resp->code),
                  resp->message ? resp->message : "no additional info");
    }

    void Adapter::connLostCb(void* ctx, char* cause)
    {
        SPSP_LOGW("Connection lost. Reconnection will be done automatically...");
    }

    int Adapter::subMsgCb(void* ctx, char* topicC, int topicLen, MQTTAsync_message* msg)
    {
        auto inst = static_cast<Adapter*>(ctx);
        std::string topic = std::string(static_cast<char*>(topicC));
        std::string data = std::string(static_cast<char*>(msg->payload), msg->payloadlen);

        SPSP_LOGD("Received data '%s' on topic '%s'",
                  data.c_str(), topic.c_str());

        // Call subscription data callback if defined
        if (inst->getSubDataCb() != nullptr) {
            std::thread t(inst->getSubDataCb(), topic, data);
            t.detach();
        }

        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(topicC);

        return true;
    }

    void Adapter::setSubDataCb(AdapterSubDataCb cb)
    {
        m_subDataCb = cb;
    }

    AdapterSubDataCb Adapter::getSubDataCb() const
    {
        return m_subDataCb;
    }

    void Adapter::setConnectedCb(AdapterConnectedCb cb)
    {
        m_connectedCb = cb;
    }

    AdapterConnectedCb Adapter::getConnectedCb() const
    {
        return m_connectedCb;
    }
}
