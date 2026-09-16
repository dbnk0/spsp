/**
 * @file espnow_adapter.cpp
 * @author Dávid Benko (davidbenko@davidbenko.dev)
 * @brief ESP-NOW adapter for Linux platform
 *
 * @copyright Copyright (c) 2024
 *
 */

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "spsp/espnow_adapter.hpp"
#include "spsp/espnow_packet_ieee80211.hpp"
#include "spsp/logger.hpp"
#include "spsp/mac.hpp"
#include "spsp/mac_setup.hpp"

using namespace std::chrono_literals;
using namespace SPSP::LocalLayers::ESPNOW::IEEE80211;

// Log tag
static const char* SPSP_LOG_TAG = "SPSP/Local/ESPNOW/Adapter";

namespace SPSP::LocalLayers::ESPNOW
{
    Adapter::RawSocket::RawSocket()
    {
        fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd == -1) {
            throw AdapterError(std::string("Socket: ") + strerror(errno));
        }
    }

    Adapter::RawSocket::~RawSocket()
    {
        close(fd);
    }

    Adapter::EventFD::EventFD()
    {
        fd = eventfd(0, EFD_NONBLOCK);
        if (fd < 0) {
            throw AdapterError(std::string("Eventfd: ") + strerror(errno));
        }
    }

    Adapter::EventFD::~EventFD()
    {
        close(fd);
    }

    Adapter::Adapter(const std::string& ifname)
    {
        int ret;

        ifreq ifinfo = {};
        strncpy(ifinfo.ifr_name, ifname.c_str(), IFNAMSIZ);

        // Get interface index
        ret = ioctl(m_sock.fd, SIOCGIFINDEX, &ifinfo);
        if (ret < 0) {
            throw AdapterError(std::string("Get interface index: ") + strerror(errno));
        }

        sockaddr_ll bindAddr = {};
        bindAddr.sll_family = PF_PACKET;
        bindAddr.sll_protocol = htons(ETH_P_ALL);
        bindAddr.sll_ifindex = ifinfo.ifr_ifindex;

        // Bind to interface
        ret = bind(m_sock.fd, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr));
        if (ret < 0) {
            throw AdapterError(std::string("Bind: ") + strerror(errno));
        }

        // Get interface MAC
        ret = ioctl(m_sock.fd, SIOCGIFHWADDR, &ifinfo);
        if (ret < 0) {
            throw AdapterError(std::string("Get MAC: ") + strerror(errno));
        }

        // Use that MAC
        SPSP::setLocalMAC(reinterpret_cast<uint8_t*>(ifinfo.ifr_addr.sa_data));
        m_localAddr = LocalAddrT::local();

        // Create filter
        this->attachSocketFilter();

        // Initialize epoll
        m_epollFd = epoll_create1(0);
        if (m_epollFd < 0) {
            throw AdapterError(std::string("Epoll create: ") + strerror(errno));
        }

        epoll_event epollEvent;
        epollEvent.events = EPOLLIN;
        epollEvent.data.fd = m_sock.fd;
        epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_sock.fd, &epollEvent);

        epoll_event eventFdEvent;
        eventFdEvent.events = EPOLLIN;
        eventFdEvent.data.fd = m_eventFd.fd;
        epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_eventFd.fd, &eventFdEvent);

        // Create handler thread
        m_thread = std::thread(&Adapter::handlerThread, this);
    }

    Adapter::~Adapter()
    {
        // Notify handler to stop
        uint64_t v = 1;
        if (write(m_eventFd.fd, &v, sizeof(v)) < 0) {
            SPSP_LOGE("Handler thread join notification failed. "
                      "You may need to force process termination. "
                      "Cause: %s", strerror(errno));
        }

        // Wait for handler
        m_thread.join();
    }

    void Adapter::attachSocketFilter()
    {
        int ret;

        // Get local MAC address
        uint8_t macBytes[MAC_LEN];
        m_localAddr.toMAC(macBytes);
        uint32_t macPart1 = macBytes[0] << 8 | macBytes[1];
        uint32_t macPart2 = macBytes[2] << 24 | macBytes[3] << 16
                          | macBytes[4] << 8 | macBytes[5];

        // Code of BPF filter for ESP-NOW 802.11 packets created by `tcpdump -dd`
        // Filters action frames with destination of local MAC or broadcast
        // or acknowledgements for local MAC.
        sock_filter bpfFilterCode[] = {
            { 0x30, 0, 0, 0x00000003 },
            { 0x64, 0, 0, 0x00000008 },
            { 0x07, 0, 0, 0x00000000 },
            { 0x30, 0, 0, 0x00000002 },
            { 0x4C, 0, 0, 0x00000000 },
            { 0x07, 0, 0, 0x00000000 },
            { 0x50, 0, 0, 0x00000000 },
            { 0x54, 0, 0, 0x000000FC },
            { 0x15, 0, 29, 0x000000D0 },
            { 0x50, 0, 0, 0x00000000 },
            { 0x45, 27, 0, 0x00000004 },
            { 0x45, 0, 9, 0x00000008 },
            { 0x50, 0, 0, 0x00000001 },
            { 0x45, 0, 7, 0x00000001 },
            { 0x40, 0, 0, 0x00000012 },
            { 0x15, 0, 2, macPart2 },
            { 0x48, 0, 0, 0x00000010 },
            { 0x15, 10, 20, macPart1 },
            { 0x15, 0, 19, 0xFFFFFFFF },
            { 0x48, 0, 0, 0x00000010 },
            { 0x15, 7, 17, 0x0000FFFF },
            { 0x40, 0, 0, 0x00000006 },
            { 0x15, 0, 2, macPart2 },
            { 0x48, 0, 0, 0x00000004 },
            { 0x15, 3, 13, macPart1 },
            { 0x15, 0, 12, 0xFFFFFFFF },
            { 0x48, 0, 0, 0x00000004 },
            { 0x15, 0, 10, 0x0000FFFF },
            { 0x40, 0, 0, 0x00000018 },
            { 0x15, 0, 8, 0x7F18FE34 },
            { 0x50, 0, 0, 0x00000020 },
            { 0x15, 0, 6, 0x000000DD },
            { 0x40, 0, 0, 0x00000021 },
            { 0x54, 0, 0, 0x00FFFFFF },
            { 0x15, 0, 3, 0x0018FE34 },
            { 0x50, 0, 0, 0x00000025 },
            { 0x15, 0, 1, 0x00000004 },
            { 0x06, 0, 0, 0x00040000 },
            { 0x06, 0, 0, 0x00000000 },
        };

        sock_fprog bpfFprog = {
            .len = sizeof(bpfFilterCode) / sizeof(bpfFilterCode[0]),
            .filter = bpfFilterCode,
        };

        // Set filter
        ret = setsockopt(m_sock.fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpfFprog, sizeof(bpfFprog));
        if (ret < 0) {
            throw AdapterError(std::string("Attach filter: ") + strerror(errno));
        }
    }

    void Adapter::send(const LocalAddrT& dst, const std::string& data)
    {
        uint8_t buf[MAX_PACKET_SIZE] = {};
        auto packet = reinterpret_cast<ActionFrameWithRadiotap*>(buf);
        size_t len = sizeof(ActionFrameWithRadiotap) + data.length();

        // Populate defaults
        *packet = ActionFrameWithRadiotap{};

        // Populate fields
        dst.toMAC(packet->action.dst);
        m_localAddr.toMAC(packet->action.src);
        packet->action.content.setPayloadLen(data.length());

        // Copy payload
        memcpy(packet->action.content.payload, data.c_str(), data.length());

        SPSP_LOGD("Send: sending %zu bytes on 802.11", len);

        // Write to send buffer
        if (write(m_sock.fd, buf, len) < 0) {
            throw AdapterError(std::string("Send: ") + strerror(errno));
        }

        // Mark packet as delivered successfully
        // TODO: check delivery status
        // I'm not aware of reasonable method for querying delivery status
        // (whether acknowledgement frame for this action frame has been
        // received).
        // Waiting for ACK with timeout is inefficient, because it blocks
        // the interface for too long when many frames are lost.
        // For now, I'll stick to unconfirmed delivery, as Linux post is
        // primarily meant for bridge nodes and there's no logic for
        // retransmissions anyway.
        // Reference for future self:
        // https://www.kernel.org/doc/html/v6.8/networking/mac80211-injection.html
        if (this->getSendCb() != nullptr) {
            std::thread t(this->getSendCb(), dst, true);
            t.detach();
        }
    }

    void Adapter::handlerThread()
    {
        constexpr size_t EVENTS_LEN = 1;
        constexpr uint32_t SOCKET_FATAL_EVENTS = EPOLLERR | EPOLLHUP | EPOLLRDHUP;
        epoll_event events[EVENTS_LEN];

        // Buffer for incoming packets
        uint8_t buf[MAX_PACKET_SIZE];

        while (true) {
            int ret = epoll_wait(m_epollFd, events, EVENTS_LEN, -1) ;
            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                } else {
                    SPSP_LOGE("Receive error: %s", strerror(errno));
                    m_fatalError = true;
                    return;
                }
            }

            if (ret == 0) {
                continue;
            }

            const auto& event = events[0];

            if (event.data.fd == m_eventFd.fd) {
                // Destructor signal
                return;
            }

            if (event.data.fd != m_sock.fd) {
                SPSP_LOGW("Receive event for unknown file descriptor %d",
                          event.data.fd);
                continue;
            }

            if (event.events & SOCKET_FATAL_EVENTS) {
                // EPOLLERR and EPOLLHUP are reported even when not requested.
                // If ignored, epoll_wait() returns the same event immediately
                // forever, causing a busy loop after the monitor interface is
                // removed or reconfigured.
                SPSP_LOGE("Receive socket failed (epoll events: 0x%x)",
                          event.events);
                m_fatalError = true;
                return;
            }

            if (!(event.events & EPOLLIN)) {
                SPSP_LOGW("Receive socket has unsupported epoll events: 0x%x",
                          event.events);
                continue;
            }

            // Received data
            ssize_t len = read(m_sock.fd, buf, MAX_PACKET_SIZE);

            if (len < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }

                SPSP_LOGE("Receive read: %s", strerror(errno));
                m_fatalError = true;
                return;
            }

            if (len == 0) {
                SPSP_LOGE("Receive socket closed");
                m_fatalError = true;
                return;
            }

            this->processIEEE80211RawPacket(buf, static_cast<size_t>(len));
        }
    }

    void Adapter::processIEEE80211RawPacket(const uint8_t* data, size_t len)
    {
        // Parse radiotap
        RadiotapParsedFields rpf = {};
        if (!this->parseRadiotap(data, len, rpf)) {
            SPSP_LOGD("Receive raw: radiotap is invalid");
            return;
        }

        // Skip radiotap header
        data += rpf.len;
        len -= rpf.len;

        // Treat as generic frame
        const auto frame = reinterpret_cast<const GenericFrame*>(data);

        switch (frame->type) {
        case FRAME_TYPE_ACTION:
            this->processIEEE80211RawAction(data, len, rpf.rssi);
            break;
        default:
            SPSP_LOGD("Receive raw: received unknown frame type: 0x%x",
                      frame->type);
            break;
        }
    }

    bool Adapter::parseRadiotap(const uint8_t* data, size_t len,
                                RadiotapParsedFields& rpf)
    {
        size_t reqSize = sizeof(Radiotap);

        // Check length for base of radiotap
        if (len < reqSize) {
            SPSP_LOGD("Receive raw: radiotap is bigger than available "
                      "(required: %zu bytes, available: %zu bytes)",
                      reqSize, len);
            return false;
        }

        // TODO: maybe rewrite all of this to FSM
        const auto rt = reinterpret_cast<const Radiotap*>(data);

        if (rt->present & RADIOTAP_PRESENT_TSFT) reqSize += sizeof(RadiotapTSFT);
        if (rt->present & RADIOTAP_PRESENT_FLAGS) reqSize += sizeof(RadiotapFlags);
        if (rt->present & RADIOTAP_PRESENT_RATE) reqSize += sizeof(RadiotapRate);
        if (rt->present & RADIOTAP_PRESENT_CHANNEL) reqSize += sizeof(RadiotapChannel);
        if (rt->present & RADIOTAP_PRESENT_FHSS) reqSize += sizeof(RadiotapFHSS);
        if (rt->present & RADIOTAP_PRESENT_ANT_SIGNAL) reqSize += sizeof(RadiotapAntSignal);

        // Check length for base of radiotap and present fields
        if (len < reqSize) {
            SPSP_LOGD("Receive raw: radiotap with fields is bigger than "
                      "available (required: %" PRIu16 " bytes, available: "
                      "%zu bytes)", rt->len, len);
            return false;
        }

        // Set correct full length (including non-parsed fields)
        rpf.len = rt->len;

        // Skip extentions of `present` field
        auto curPresent = &(rt->present);
        for (; *curPresent & RADIOTAP_PRESENT_EXT; curPresent++) {
            reqSize += sizeof(RadiotapExtention);

            if (rt->len < reqSize) {
                SPSP_LOGD("Receive raw: radiotap with present extensions "
                          "is bigger than available (required: %zu bytes, "
                          "available: %" PRIu16 " bytes)", reqSize, rt->len);
                return false;
            }
        }

        // Continue with processing
        data = reinterpret_cast<const uint8_t*>(++curPresent);

        // Parse fields
        if (rt->present & RADIOTAP_PRESENT_TSFT) {
            data += sizeof(RadiotapTSFT);
        }
        if (rt->present & RADIOTAP_PRESENT_FLAGS) {
            data += sizeof(RadiotapFlags);
        }
        if (rt->present & RADIOTAP_PRESENT_RATE) {
            data += sizeof(RadiotapRate);
        }
        if (rt->present & RADIOTAP_PRESENT_CHANNEL) {
            const auto channel = reinterpret_cast<const RadiotapChannel*>(data);
            rpf.freq = channel->freq;
            data += sizeof(RadiotapChannel);
        }
        if (rt->present & RADIOTAP_PRESENT_FHSS) {
            data += sizeof(RadiotapFHSS);
        }
        if (rt->present & RADIOTAP_PRESENT_ANT_SIGNAL) {
            const auto rssi = reinterpret_cast<const RadiotapAntSignal*>(data);
            rpf.rssi = *rssi;
            data += sizeof(RadiotapAntSignal);
        }

        return true;
    }

    void Adapter::processIEEE80211RawAction(const uint8_t* data, size_t len, int rssi)
    {
        // Check action frame size
        if (len < sizeof(ActionFrame)) {
            SPSP_LOGD("Receive raw action: packet has invalid size");
            return;
        }

        // Process action frame
        const auto action = reinterpret_cast<const ActionFrame*>(data);

        // Check length of payload
        const size_t payloadLen = action->content.getPayloadLen();
        if (len < sizeof(ActionFrame) + payloadLen) {
            SPSP_LOGD("Receive raw action: packet with payload has invalid size");
            return;
        }

        auto cb = this->getRecvCb();
        if (cb == nullptr) {
            return;
        }

        // Create new thread for receive handler
        // Otherwise creates deadlock, because receive callback tries to send
        // response, but ESP-NOW's internal mutex is still held by this
        // unfinished callback.
        std::string payload((char*) action->content.payload, payloadLen);
        std::thread t(cb, action->src, payload, rssi);

        // Run independently
        t.detach();
    }
} // namespace SPSP::LocalLayers::ESPNOW
