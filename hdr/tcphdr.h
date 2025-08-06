#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct Tcp4Hdr final
{
    uint16_t sport_;
    uint16_t dport_;
    uint32_t sequence_number_;
    uint32_t acknowledgement_number_;
    uint8_t data_offset_ : 4,
        reserved_ : 4;
    uint8_t cwr_ : 1,
        ece_ : 1,
        urg_ : 1,
        ack_ : 1,
        psh_ : 1,
        rst_ : 1,
        syn_ : 1,
        fin_ : 1;
    uint16_t window_;
    uint16_t checksum_;
    uint16_t urgent_pointer_;

    uint16_t sport() { return ntohs(sport_); }
    uint16_t dport() { return ntohs(dport_); }
};
typedef Tcp4Hdr *PTcp4Hdr;
#pragma pack(pop)
