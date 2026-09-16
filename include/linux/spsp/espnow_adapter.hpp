/**
 * @file espnow_adapter.hpp
 * @author Dávid Benko (davidbenko@davidbenko.dev)
 * @brief ESP-NOW adapter for Linux platform
 *
 * @copyright Copyright (c) 2024
 *
 */

#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

#include "spsp/espnow_adapter_if.hpp"
#include "spsp/espnow_packet_ieee80211.hpp"
#include "spsp/espnow_types.hpp"

namespace SPSP::LocalLayers::ESPNOW
{
    /**
     * @brief ESP-NOW adapter for Linux platform
     *
     * Low level API for ESP-NOW communication.
     *
     * Implements `IAdapter` interface.
     */
    class Adapter : public IAdapter
    {
    protected:
        /**
         * @brief Wrapper of raw socket
         *
         * Created to correctly handle deinitialization.
         */
        struct RawSocket
        {
            int fd;
            RawSocket();
            ~RawSocket();
        };

        /**
         * @brief Wrapper of event file descriptor
         *
         * Created to correctly handle deinitialization.
         */
        struct EventFD
        {
            int fd;
            EventFD();
            ~EventFD();
        };

        RawSocket m_sock;                               //!< Socket
        EventFD m_eventFd;                              //!< Epoll event file descriptor
        int m_epollFd;                                  //!< Epoll file descriptor
        LocalAddrT m_localAddr;                         //!< Cached local MAC address
        AdapterRecvCb m_recvCb = nullptr;               //!< Receive callback
        AdapterSendCb m_sendCb = nullptr;               //!< Send callback
        std::thread m_thread;                           //!< Handler thread
        std::atomic_bool m_fatalError = false;           //!< Whether packet capture has failed

    public:
        /**
         * @brief Constructs a new ESP-NOW adapter
         *
         * Starts packet capture on 802.11 interface identified by `ifname`.
         *
         * @param ifname Interface name (must be in monitor mode)
         *
         * @throw AdapterError when any call to underlaying library fails
         */
        Adapter(const std::string& ifname);

        /**
         * @brief Destroys the adapter
         *
         */
        ~Adapter();

        /**
         * @brief Checks whether packet capture failed irrecoverably.
         *
         * A failure means the packet socket can no longer be used. The owner
         * should destroy and recreate the adapter.
         *
         * @return true Packet capture failed
         * @return false Packet capture is still operational
         */
        bool hasFatalError() const noexcept { return m_fatalError.load(); }

        /**
         * @brief Sets receive callback
         *
         * Callback should be called in new thread.
         *
         * @param cb Callback
         */
        void setRecvCb(AdapterRecvCb cb) noexcept { m_recvCb = cb; }

        /**
         * @brief Gets receive callback
         *
         * @param cb Callback
         */
        AdapterRecvCb getRecvCb() const noexcept { return m_recvCb; }

        /**
         * @brief Sets send callback
         *
         * @param cb Callback
         */
        void setSendCb(AdapterSendCb cb) noexcept { m_sendCb = cb; }

        /**
         * @brief Gets send callback
         *
         * @param cb Callback
         */
        AdapterSendCb getSendCb() const noexcept { return m_sendCb; }

        /**
         * @brief Sends local message
         *
         * Injects IEEE 802.11 packet onto the packet capture interface.
         *
         * @param dst Destination address
         * @param data Raw data to be sent
         * @throw AdapterError when call to send function fails
         *        (not when packet undelivered)
         */
        void send(const LocalAddrT& dst, const std::string& data);

        /**
         * @brief Adds peer to peer list
         *
         * Doesn't do anything on Linux plaform.
         *
         * @param peer Peer address
         */
        void addPeer(const LocalAddrT& peer) {}

        /**
         * @brief Removes peer from peer list
         *
         * Doesn't do anything on Linux plaform.
         *
         * @param peer Peer address
         */
        void removePeer(const LocalAddrT& peer) {}

    protected:
        /**
         * @brief Function of thread handling incoming packets
         *
         */
        void handlerThread();

        /**
         * @brief Attaches BPF filter to the socket
         *
         * @throw AdapterError when any call to underlaying library fails
         */
        void attachSocketFilter();

        /**
         * @brief Processes incoming raw IEEE 802.11 packet
         *
         * @param data Raw data
         * @param len Data length
         */
        void processIEEE80211RawPacket(const uint8_t* data, size_t len);

        /**
         * @brief Parses radiotap header of IEEE 802.11 frame
         *
         * @param data Raw data
         * @param len Data length
         * @param rpf Parsed radiotap fields. Those not present are left unmodified!
         * @return true If the header is valid
         * @return false If the header is invalid
         */
        bool parseRadiotap(const uint8_t* data, size_t len,
                           IEEE80211::RadiotapParsedFields& rpf);

        /**
         * @brief Processes incoming raw IEEE 802.11 action frame
         *
         * @param data Raw data
         * @param len Data length
         * @param rssi Received signal strength indicator (in dBm)
         */
        void processIEEE80211RawAction(const uint8_t* data, size_t len, int rssi);

        /**
         * @brief Processes incoming raw IEEE 802.11 acknowledgement
         *
         * @param data Raw data
         * @param len Data length
         * @param rssi Received signal strength indicator (in dBm)
         */
        void processIEEE80211RawAck(const uint8_t* data, size_t len, int rssi);
    };
} // namespace SPSP::LocalLayers::ESPNOW
