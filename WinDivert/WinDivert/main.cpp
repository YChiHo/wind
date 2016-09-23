#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"
#include<WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define MAXBUF  0xFFFF
using namespace std;

typedef struct{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;
typedef struct{
	WINDIVERT_IPHDR ip;
	WINDIVERT_ICMPHDR icmp;
	UINT8 data[];
} ICMPPACKET, *PICMPPACKET;
typedef struct {
	WINDIVERT_IPHDR ip;
	WINDIVERT_UDPHDR udp;
} UDPPACKET, *PUDPPACKET; 
char *target = "10.100.111.71"; //원래받는사람
char *dest = "10.100.111.117";  //내가보내주고싶은사람
int __cdecl main(int argc, char **argv) {
	argv[1] = "outbound and ip.DstAddr == 10.100.111.71";
	HANDLE handle, console;
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
	UINT payload_len = 0;
	char *payload;
	payload = (char *)malloc(payload_len);
	TCPPACKET reset0;
	PTCPPACKET reset = &reset0;

	inet_pton(AF_INET, target, &reset->ip.DstAddr);
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, 1000, 0);  // WinDivertOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
	if (handle == INVALID_HANDLE_VALUE) {
		if (GetLastError() == ERROR_INVALID_PARAMETER) {
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n", GetLastError());
		exit(EXIT_FAILURE);
	}							// 예외
	// MAIN LOOP
	while (1) {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len)) {
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, (PVOID *)payload, &payload_len);
		if (ip_header != NULL && ip_header->DstAddr == reset->ip.DstAddr) {
			inet_pton(AF_INET, dest, &ip_header->DstAddr);
			ip_header->Checksum = WinDivertHelperCalcChecksums((PVOID)packet, sizeof(TCPPACKET), 0);
			//show
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3], dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			//show
			if (!WinDivertSend(handle, (PVOID)packet, packet_len, &send_addr, NULL))
				fprintf(stderr, "warning: failed to send reset (%d)\n", GetLastError());
		}
	}
}
