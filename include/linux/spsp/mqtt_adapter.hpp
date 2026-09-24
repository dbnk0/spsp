/**
 * @file mqtt_adapter.hpp
 * @author Dávid Benko (davidbenko@davidbenko.dev)
 * @brief MQTT adapter for Linux plaform
 *
 * @copyright Copyright (c) 2024
 *
 */

#pragma once

#include "MQTTAsync.h"

#include "spsp/mqtt_adapter_if.hpp"
#include "spsp/mqtt_types.hpp"

namespace SPSP::FarLayers::MQTT
{
    /**
     * @brief MQTT adapter for Linux platform
     *
     * Only one MQTT instance can use this at a time and
     * there may be many `Adapter` instances at a time.
     */
    class Adapter : public IAdapter
    {
        Config m_conf;                               //!< Configuration
        MQTTAsync m_mqtt;                            //!< MQTT client instance
        AdapterSubDataCb m_subDataCb = nullptr;      //!< Subscription data callback
        AdapterConnectedCb m_connectedCb = nullptr;  //!< Connected callback

    public:
        /**
         * @brief Constructs a new MQTT layer object
         *
         * Requires already initialized WiFi (with IP address).
         *
         * @param conf Configuration
         * @throw AdapterError when MQTT client can't be created and started
         */
        Adapter(const Config& conf);

        /**
         * @brief Destroys MQTT layer object
         *
         */
        ~Adapter();

        /**
         * @brief Publishes message coming from node
         *
         * This doesn't block.
         *
         * @param topic Topic
         * @param payload Payload (data)
         * @return true Delivery successful
         * @return false Delivery failed
         */
        bool publish(const std::string& topic, const std::string& payload);

        /**
         * @brief Subscribes to given topic
         *
         * This blocks, except when called from the Paho connection callback.
         * In that context the request is queued and this function returns
         * before the broker acknowledges it, because waiting would deadlock
         * Paho's receive thread.
         *
         * @param topic Topic
         * @return true Subscribe successful
         * @return false Subscribe failed
         */
        bool subscribe(const std::string& topic);

        /**
         * @brief Unsubscribes from given topic
         *
         * This blocks.
         *
         * @param topic Topic
         * @return true Unsubscribe successful
         * @return false Unsubscribe failed
         */
        bool unsubscribe(const std::string& topic);

        /**
         * @brief Sets callback for incoming subscription data
         *
         * @param cb Callback
         */
        void setSubDataCb(AdapterSubDataCb cb);

        /**
         * @brief Gets callback for incoming subscription data
         *
         * @return Callback
         */
        AdapterSubDataCb getSubDataCb() const;

        /**
         * @brief Sets connected callback
         *
         * Should be called on successful connection and reconnection.
         *
         * @param cb Callback
         */
        void setConnectedCb(AdapterConnectedCb cb);

        /**
         * @brief Gets connected callback
         *
         * @return Callback
         */
        AdapterConnectedCb getConnectedCb() const;

    protected:
        /**
         * @brief Connects to MQTT server
         *
         * @return true Connection process started successfully
         * @return false Connection failed
         */
        bool connect();

        /**
         * @brief Connected callback
         *
         * Passed to underlaying library.
         *
         * @param ctx Context
         * @param cause Cause
         */
        static void connectedCb(void* ctx, char* cause);

        /**
         * @brief Connection failure callback
         *
         * Passed to underlaying library.
         *
         * @param ctx Context
         * @param resp Response
         */
        static void connFailureCb(void* ctx, MQTTAsync_failureData* resp);

        /**
         * @brief Connection lost callback
         *
         * Passed to underlaying library.
         *
         * @param ctx Context
         * @param cause Cause
         */
        static void connLostCb(void* ctx, char* cause);

        /**
         * @brief Subscription message callback
         *
         * Passed to underlaying library.
         *
         * @param ctx Context
         * @param topic Topic
         * @param topicLen Length of topic
         * @param msg MQTT message
         */
        static int subMsgCb(void* ctx, char* topic, int topicLen,
                            MQTTAsync_message* msg);

        /**
         * @brief Helper to convert `std::string` to C string or `nullptr`
         *
         * @param str String
         * @return If string is empty, `nullptr`, otherwise C string.
         */
        inline static const char* stringToCOrNull(const std::string& str)
        {
            return str.empty() ? nullptr : str.c_str();
        }
    };
} // namespace SPSP::FarLayers::MQTT
