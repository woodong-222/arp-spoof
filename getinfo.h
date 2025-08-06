#pragma once

#include <cstdio>
#include <pcap.h>
#include <time.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "hdr/ethhdr.h"
#include "hdr/arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

Ip getIp(const char *ifname);
Mac SearchMac(pcap_t *pcap, Mac interface_mac, Ip my_ip, Ip search_ip);
