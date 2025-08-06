#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "../addr/ip.h"

#pragma pack(push, 1)
struct Ipv4Hdr final
{

    uint8_t version_ : 4,
        ihl_ : 4;
    uint8_t dscp_ : 6,
        ecn_ : 2;
    uint16_t total_length_;
    uint16_t identification_;
    uint16_t flags_ : 3,
        fragment_offset_ : 13;
    uint8_t time_to_live_;
    uint8_t protocol_;
    uint16_t header_checksum_;
    Ip sip_;
    Ip dip_;

    Ip sip() { return ntohl(sip_); }
    Ip dip() { return ntohl(dip_); }
    uint16_t total_length() { return ntohs(total_length_); }
    uint8_t protocol() { return protocol_; }

    // Type(protocol)
    enum : uint8_t
    {
        Icmp = 1,
        Igmp = 2,
        Tcp = 6,
        Udp = 17,
        Encap = 41,
        Ospf = 89,
        Sctp = 132
    };
};
typedef Ipv4Hdr *PIpv4Hdr;
typedef Ipv4Hdr Ipv4Header;
#pragma pack(pop)
