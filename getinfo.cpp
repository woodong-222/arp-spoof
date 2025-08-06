#include "getinfo.h"

Ip getIp(const char *ifname)
{
	struct ifreq ifr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("*Error: failed to create socket\n");
		return EXIT_FAILURE;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
	{
		printf("*Error: get interface IP address\n");
		close(sockfd);
		return EXIT_FAILURE;
	}

	close(sockfd);

	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	return Ip(ntohl(sin->sin_addr.s_addr));
}

Mac SearchMac(pcap_t *pcap, Mac interface_mac, Ip my_ip, Ip search_ip)
{
	printf("Search IP: %s\n", std::string(search_ip).c_str());

	// ARP Request 패킷
	EthArpPacket request_packet;

	request_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	request_packet.eth_.smac_ = interface_mac;
	request_packet.eth_.type_ = htons(EthHdr::Arp);

	request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	request_packet.arp_.pro_ = htons(EthHdr::Ip4);
	request_packet.arp_.hln_ = Mac::Size;
	request_packet.arp_.pln_ = Ip::Size;
	request_packet.arp_.op_ = htons(ArpHdr::Request);
	request_packet.arp_.smac_ = interface_mac;
	request_packet.arp_.sip_ = htonl(my_ip);
	request_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	request_packet.arp_.tip_ = htonl(search_ip);

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&request_packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "*Error: Failed to ARP request\n");
		return Mac::nullMac();
	}

	struct pcap_pkthdr *header;
	const u_char *packet_data;

	time_t start_time = time(nullptr);

	while (time(nullptr) - start_time < 5)
	{

		res = pcap_next_ex(pcap, &header, &packet_data);

		EthArpPacket *received_packet = (EthArpPacket *)packet_data;

		Ip sender_ip = ntohl(received_packet->arp_.sip_);
		if (sender_ip == search_ip)
		{
			Mac search_mac = received_packet->arp_.smac_;
			printf("Found MAC for %s: %s\n", std::string(search_ip).c_str(), std::string(search_mac).c_str());
			return search_mac;
		}
	}
	printf("Error: No ARP reply\n");
	return Mac::nullMac();
}
