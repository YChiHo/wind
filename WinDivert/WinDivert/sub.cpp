#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"
#pragma comment(lib, "Ws2_32.lib")
//#pragma comment(lib, "WinDivert.lib")
#define MAXBUF  0xFFFF

/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;
typedef struct
{
	WINDIVERT_IPV6HDR ipv6;
	WINDIVERT_TCPHDR tcp;
} TCPV6PACKET, *PTCPV6PACKET;
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_ICMPHDR icmp;
	UINT8 data[];
} ICMPPACKET, *PICMPPACKET;
typedef struct
{
	WINDIVERT_IPV6HDR ipv6;
	WINDIVERT_ICMPV6HDR icmpv6;
	UINT8 data[];
} ICMPV6PACKET, *PICMPV6PACKET;

/*
* Prototypes.
*/
static void PacketIpInit(PWINDIVERT_IPHDR packet);
static void PacketIpTcpInit(PTCPPACKET packet);
static void PacketIpIcmpInit(PICMPPACKET packet);
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet);
static void PacketIpv6TcpInit(PTCPV6PACKET packet);
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet);

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;

	TCPPACKET reset0;
	PTCPPACKET reset = &reset0;
	//UINT8 dnr0[sizeof(ICMPPACKET) + 0x0F * sizeof(UINT32) + 8 + 1];
	//PICMPPACKET dnr = (PICMPPACKET)dnr0;

	//TCPV6PACKET resetv6_0;
	//PTCPV6PACKET resetv6 = &resetv6_0;
	//UINT8 dnrv6_0[sizeof(ICMPV6PACKET) + sizeof(WINDIVERT_IPV6HDR) +
	//	sizeof(WINDIVERT_TCPHDR)];
	//PICMPV6PACKET dnrv6 = (PICMPV6PACKET)dnrv6_0;

	// Check arguments.
	switch (argc)
	{
	case 2:
		break;
	case 3:
		priority = (INT16)atoi(argv[2]);
		break;
	default:
		fprintf(stderr, "usage: %s windivert-filter [priority]\n",
			argv[0]);
		fprintf(stderr, "examples:\n");
		fprintf(stderr, "\t%s true\n", argv[0]);
		fprintf(stderr, "\t%s \"outbound and tcp.DstPort == 80\" 1000\n",
			argv[0]);
		fprintf(stderr, "\t%s \"inbound and tcp.Syn\" -4000\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// Initialize all packets.
	PacketIpTcpInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;
	PacketIpIcmpInit(dnr);
	dnr->icmp.Type = 3;         // Destination not reachable.
	dnr->icmp.Code = 3;         // Port not reachable.
	PacketIpv6TcpInit(resetv6);
	resetv6->tcp.Rst = 1;
	resetv6->tcp.Ack = 1;
	PacketIpv6Icmpv6Init(dnrv6);
	dnrv6->ipv6.Length = htons(sizeof(WINDIVERT_ICMPV6HDR) + 4 +
		sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_TCPHDR));
	dnrv6->icmpv6.Type = 1;     // Destination not reachable.
	dnrv6->icmpv6.Code = 4;     // Port not reachable.

								// Get console for pretty colors.
	console = GetStdHandle(STD_OUTPUT_HANDLE);

	// Divert traffic matching the filter:
	handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop:
	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		// Print info about the matching packet.
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,	&udp_header, NULL, &payload_len);
		if (ip_header == NULL && ipv6_header == NULL)
		{
			continue;
		}

		// Dump packet info: 
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		fputs("BLOCK ", stdout);
		SetConsoleTextAttribute(console,
			FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		if (ip_header != NULL)
		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		}
		if (ipv6_header != NULL)
		{
			UINT16 *src_addr = (UINT16 *)&ipv6_header->SrcAddr;
			UINT16 *dst_addr = (UINT16 *)&ipv6_header->DstAddr;
			fputs("ipv6.SrcAddr=", stdout);
			for (i = 0; i < 8; i++)
			{
				printf("%x%c", ntohs(src_addr[i]), (i == 7 ? ' ' : ':'));
			}
			fputs(" ipv6.DstAddr=", stdout);
			for (i = 0; i < 8; i++)
			{
				printf("%x%c", ntohs(dst_addr[i]), (i == 7 ? ' ' : ':'));
			}
			putchar(' ');
		}
		if (icmp_header != NULL)
		{
			printf("icmp.Type=%u icmp.Code=%u ",
				icmp_header->Type, icmp_header->Code);
			// Simply drop ICMP
		}
		if (icmpv6_header != NULL)
		{
			printf("icmpv6.Type=%u icmpv6.Code=%u ",
				icmpv6_header->Type, icmpv6_header->Code);
			// Simply drop ICMPv6
		}
		if (tcp_header != NULL)
		{
			printf("tcp.SrcPort=%u tcp.DstPort=%u tcp.Flags=",
				ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort));
			if (tcp_header->Fin)
			{
				fputs("[FIN]", stdout);
			}
			if (tcp_header->Rst)
			{
				fputs("[RST]", stdout);
			}
			if (tcp_header->Urg)
			{
				fputs("[URG]", stdout);
			}
			if (tcp_header->Syn)
			{
				fputs("[SYN]", stdout);
			}
			if (tcp_header->Psh)
			{
				fputs("[PSH]", stdout);
			}
			if (tcp_header->Ack)
			{
				fputs("[ACK]", stdout);
			}
			putchar(' ');


			if (ip_header != NULL)
			{
				reset->ip.SrcAddr = ip_header->DstAddr;
				reset->ip.DstAddr = ip_header->SrcAddr;
				reset->tcp.SrcPort = tcp_header->DstPort;
				reset->tcp.DstPort = tcp_header->SrcPort;
				reset->tcp.SeqNum =	(tcp_header->Ack ? tcp_header->AckNum : 0);
				reset->tcp.AckNum =	(tcp_header->Syn ? htonl(ntohl(tcp_header->SeqNum) + 1) : htonl(ntohl(tcp_header->SeqNum) + payload_len));

				WinDivertHelperCalcChecksums((PVOID)reset, sizeof(TCPPACKET), 0);

				memcpy(&send_addr, &recv_addr, sizeof(send_addr));
				send_addr.Direction = !recv_addr.Direction;
				if (!WinDivertSend(handle, (PVOID)reset, sizeof(TCPPACKET),	&send_addr, NULL))	{
					fprintf(stderr, "warning: failed to send TCP reset (%d)\n",
						GetLastError());
				}
			}

		}
		
		putchar('\n');
	}
}
/*
* Initialize a PACKET.
*/
static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));
	packet->Version = 4;
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->Id = ntohs(0xDEAD);
	packet->TTL = 64;
}
static void PacketIpTcpInit(PTCPPACKET packet)
{
	memset(packet, 0, sizeof(TCPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Length = htons(sizeof(TCPPACKET));
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}
static void PacketIpIcmpInit(PICMPPACKET packet)
{
	memset(packet, 0, sizeof(ICMPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Protocol = IPPROTO_ICMP;
}
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
	packet->Version = 6;
	packet->HopLimit = 64;
}
static void PacketIpv6TcpInit(PTCPV6PACKET packet)
{
	memset(packet, 0, sizeof(TCPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
	packet->ipv6.NextHdr = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)
{
	memset(packet, 0, sizeof(ICMPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}