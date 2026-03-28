/**
 * @file espnow_esp_adapter.cpp
 * @author Dávid Benko (davidbenko@davidbenko.dev)
 * @brief ESP-NOW adapter for ESP platform
 *
 * @copyright Copyright (c) 2023
 *
 */

#include <thread>

#include "esp_idf_version.h"
#include "esp_now.h"

#include "spsp/espnow_adapter.hpp"
#include "spsp/exception_check.hpp"

// Log tag
static const char* SPSP_LOG_TAG = "SPSP/Local/ESPNOW/Adapter";

namespace SPSP::LocalLayers::ESPNOW
{
    // Instance pointer
    // ESP-NOW callbacks don't take `void*` context pointers, so we have to get
    // creative.
    static Adapter* _adapterInstance = nullptr;

    // Wrapper for C receive callback
    void _receiveCallback(const esp_now_recv_info_t* espnowInfo, const uint8_t* data, int dataLen)
    {
        auto cb = _adapterInstance->getRecvCb();
        auto rssi = espnowInfo->rx_ctrl->rssi;

        if (cb == nullptr) {
            return;
        }

        // Create new thread for receive handler
        // Otherwise creates deadlock, because receive callback tries to send
        // response, but ESP-NOW's internal mutex is still held by this
        // unfinished callback.
        std::thread t(cb, espnowInfo->src_addr,
                      std::string((char*) data, dataLen), rssi);

        // Run independently
        t.detach();
    }

    // Wrapper for C send callback
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
    void _sendCallback(const esp_now_send_info_t *tx_info, esp_now_send_status_t status)
    {
        auto cb = _adapterInstance->getSendCb();
        if (cb == nullptr) {
            return;
        }

        cb(tx_info->des_addr, status == ESP_NOW_SEND_SUCCESS);
    }
#else
    void _sendCallback(const uint8_t *dst, esp_now_send_status_t status)
    {
        auto cb = _adapterInstance->getSendCb();
        if (cb == nullptr) {
            return;
        }

        cb(dst, status == ESP_NOW_SEND_SUCCESS);
    }
#endif

    Adapter::Adapter()
    {
        SPSP_ERROR_CHECK(esp_now_init(),
                         AdapterError("Initialization failed"));
        SPSP_ERROR_CHECK(esp_now_register_recv_cb(_receiveCallback),
                         AdapterError("Internal receive callback registration failed"));
        SPSP_ERROR_CHECK(esp_now_register_send_cb(_sendCallback),
                         AdapterError("Internal send callback registration failed"));

        _adapterInstance = this;
    }

    Adapter::~Adapter()
    {
        esp_now_deinit();
    }

    void Adapter::setRecvCb(AdapterRecvCb cb) noexcept
    {
        m_recvCb = cb;
    }

    AdapterRecvCb Adapter::getRecvCb() const noexcept
    {
        return m_recvCb;
    }

    void Adapter::setSendCb(AdapterSendCb cb) noexcept
    {
        m_sendCb = cb;
    }

    AdapterSendCb Adapter::getSendCb() const noexcept
    {
        return m_sendCb;
    }

    void Adapter::send(const LocalAddrT& dst, const std::string& data)
    {
        // Get MAC address
        esp_now_peer_info_t peerInfo = {};
        dst.toMAC(peerInfo.peer_addr);

        SPSP_ERROR_CHECK(esp_now_send(peerInfo.peer_addr,
                                      (const uint8_t*) data.c_str(),
                                      data.length()),
                         AdapterError("Sending failed"));
    }

    void Adapter::addPeer(const LocalAddrT& peer)
    {
        // Get MAC address
        esp_now_peer_info_t peerInfo = {};
        peer.toMAC(peerInfo.peer_addr);

        SPSP_ERROR_CHECK(esp_now_add_peer(&peerInfo),
                         AdapterError("Adding peer failed"));
    }

    void Adapter::removePeer(const LocalAddrT& peer)
    {
        // Get MAC address
        esp_now_peer_info_t peerInfo = {};
        peer.toMAC(peerInfo.peer_addr);

        SPSP_ERROR_CHECK(esp_now_del_peer(peerInfo.peer_addr),
                         AdapterError("Deleting peer failed"));
    }
} // namespace SPSP::LocalLayers::ESPNOW
