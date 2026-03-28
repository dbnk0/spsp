/**
 * @file bridge_espnow.cpp
 * @author Dávid Benko (davidbenko@davidbenko.dev)
 * @brief SPSP bridge for Linux platform
 *
 * @copyright Copyright (c) 2024
 *
 */

#include <csignal>
#include <cstdio>
#include <iostream>

#include "ini.h"
#include "spsp/spsp.hpp"

#define SAVE_OPTION(var, section, attr, type)             \
    do {                                                  \
        auto const sections = config.Sections();          \
        if (sections.find(section) != sections.end()) {   \
            auto const attrs = config.Get(section);       \
            if (attrs.find(attr) != attrs.end()) {        \
                var = config.Get<type>(section, attr);    \
            }                                             \
        }                                                 \
    } while (0)

//! Return codes
enum ReturnCode { SUCCESS = 0, FAIL = 1 };

//! Far layers
enum FarLayer { FL_MQTT, FL_LOCAL_BROKER };

/**
 * @brief Blocks until SIGINT or SIGTERM is received
 *
 */
void waitForTermination()
{
    // Set signal handlers
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

    // Wait for termination
    int sig;
    sigwait(&sigset, &sig);
}

/**
 * @brief Sets log level
 *
 * @param logLevelStr Log level string
 *
 * @throw std::runtime_error If logLevelStr is invalid.
 */
void setLogLevel(const std::string& logLevelStr)
{
    if      (logLevelStr == "debug") SPSP::logLevel = SPSP::LogLevel::DEBUG;
    else if (logLevelStr == "info")  SPSP::logLevel = SPSP::LogLevel::INFO;
    else if (logLevelStr == "warn")  SPSP::logLevel = SPSP::LogLevel::WARN;
    else if (logLevelStr == "error") SPSP::logLevel = SPSP::LogLevel::ERROR;
    else if (logLevelStr == "off")   SPSP::logLevel = SPSP::LogLevel::OFF;
    else {
        throw std::runtime_error("Invalid log level '" + logLevelStr + "'");
    }
}

void printHelp()
{
    std::cerr << "Usage: spsp_bridge_espnow CONFIG_FILE.ini" << std::endl
              << std::endl
              << "See: https://github.com/dbnk0/spsp/blob/main/linux/"
                 "bridge_espnow_config.ini.example" << std::endl;
}

int main(int argc, char const* argv[])
{
    if (argc != 2 || argv[1][0] == '-') {
        // Print help
        printHelp();
        return FAIL;
    }

    // Parse config
    inih::INIReader config;
    try {
        config = inih::INIReader(argv[1]);
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return FAIL;
    }

    std::string iface;
    FarLayer farLayer;
    SPSP::LocalLayers::ESPNOW::Config espnowConfig = {};
    SPSP::FarLayers::MQTT::Config mqttConfig = {};
    std::string localBrokerTopicPrefix;

    // Process all present options
    try {
        // Interface
        iface = config.Get<std::string>("espnow", "interface");

        // Far layer switch
        std::string farLayerStr = config.Get<std::string>("", "far_layer");

        if      (farLayerStr == "mqtt") farLayer = FL_MQTT;
        else if (farLayerStr == "local_broker") farLayer = FL_LOCAL_BROKER;
        else {
            throw std::runtime_error("Invalid far layer '" + farLayerStr + "'");
        }

        // Set log level
        setLogLevel(config.Get<std::string>("", "log_level", "info"));

        // ESP-NOW config
        SAVE_OPTION(espnowConfig.ssid, "espnow", "ssid", uint32_t);
        SAVE_OPTION(espnowConfig.password, "espnow", "password", std::string);
        if (espnowConfig.password.length() != 32) {
            throw std::runtime_error("ESP-NOW password must be 32 bytes long");
        }

        // MQTT config
        auto timeoutMs = mqttConfig.connection.timeout.count();
        SAVE_OPTION(mqttConfig.connection.uri, "mqtt", "uri", std::string);
        SAVE_OPTION(mqttConfig.connection.verifyCrt, "mqtt", "verify_crt", std::string);
        SAVE_OPTION(mqttConfig.connection.keepalive, "mqtt", "keepalive", uint32_t);
        SAVE_OPTION(mqttConfig.connection.qos, "mqtt", "qos", int);
        SAVE_OPTION(mqttConfig.connection.retain, "mqtt", "retain", bool);
        SAVE_OPTION(timeoutMs, "mqtt", "conn_timeout", typeof(timeoutMs));
        SAVE_OPTION(mqttConfig.auth.username, "mqtt", "username", std::string);
        SAVE_OPTION(mqttConfig.auth.password, "mqtt", "password", std::string);
        SAVE_OPTION(mqttConfig.auth.clientId, "mqtt", "client_id", std::string);
        SAVE_OPTION(mqttConfig.auth.crt, "mqtt", "crt", std::string);
        SAVE_OPTION(mqttConfig.auth.crtKey, "mqtt", "crt_key", std::string);
        SAVE_OPTION(mqttConfig.lastWill.topic, "mqtt", "ltw_topic", std::string);
        SAVE_OPTION(mqttConfig.lastWill.msg, "mqtt", "ltw_msg", std::string);
        SAVE_OPTION(mqttConfig.lastWill.qos, "mqtt", "ltw_qos", int);
        SAVE_OPTION(mqttConfig.lastWill.retain, "mqtt", "ltw_retain", bool);
        SAVE_OPTION(mqttConfig.pubTopicPrefix, "mqtt", "topic_prefix", std::string);
        mqttConfig.connection.timeout = std::chrono::milliseconds(timeoutMs);

        // Local broker config
        SAVE_OPTION(localBrokerTopicPrefix, "local_broker", "topic_prefix", std::string);
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return FAIL;
    }

    try {
        // Initialize ESP-NOW
        SPSP::WiFi::Dummy wifi;
        SPSP::LocalLayers::ESPNOW::Adapter llAdapter{iface};
        SPSP::LocalLayers::ESPNOW::ESPNOW ll{llAdapter, wifi, espnowConfig};

        if (farLayer == FL_MQTT) {
            // Initialize MQTT
            SPSP::FarLayers::MQTT::Adapter flAdapter{mqttConfig};
            SPSP::FarLayers::MQTT::MQTT fl{flAdapter, mqttConfig};

            // Create bridge
            SPSP::Nodes::Bridge br{&ll, &fl};

            // Block
            waitForTermination();
        } else if (farLayer == FL_LOCAL_BROKER) {
            // Initialize local broker
            SPSP::FarLayers::LocalBroker::LocalBroker fl{localBrokerTopicPrefix};

            // Create bridge
            SPSP::Nodes::Bridge br{&ll, &fl};

            // Block
            waitForTermination();
        }
    } catch (const SPSP::Exception& e) {
        std::cerr << "SPSP exception: " << e.what() << std::endl;
        return FAIL;
    }

    return SUCCESS;
}
