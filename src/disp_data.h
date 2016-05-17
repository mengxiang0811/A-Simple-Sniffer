#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdint.h>

struct pcap_record
{
	uint16_t offset;
};

struct interface_item
{
	char ifname[10];
	char ifdesc[50];
};

struct arp_header
{
	uint16_t ar_hrd;      /* Format of hardware address.  */
	uint16_t ar_pro;      /* Format of protocol address.  */
	uint8_t ar_hln;       /* Length of hardware address.  */
	uint8_t ar_pln;       /* Length of protocol address.  */
	uint16_t ar_op;       /* ARP opcode (command).  */
	unsigned char ar_srcmac[6];   /* Sender hardware address.  */
	uint32_t ar_srcip;      /* Sender IP address.  */
	unsigned char ar_dstmac[6];   /* Target hardware address.  */
	uint32_t ar_dstip;      /* Target IP address.  */
}__attribute((packed));

struct disp_record
{
	uint32_t id;
	uint32_t filter_id;
	char time[30];
	char srcmac[20];
	char dstmac[20];
	char srcip[20];
	char dstip[20];
	char protocol[10];
	uint16_t length;
};

struct disp_frame
{
	char title[10];
	char length[20];
};

struct disp_ether
{
	char title[100];
	char dst_mac[50];
	char src_mac[50];
	char protocol[30];
};

struct disp_arp
{
	char title[100];
	char ar_hrd[50];
	char ar_pro[50];
	char ar_hln[50];
	char ar_pln[50];
	char ar_op[50];
	char src_mac[100];
	char src_ip[100];
	char dst_mac[100];
	char dst_ip[100];
};

struct disp_ip
{
	char title[100];
	char version[30];
	char headlen[30];
	char tos[30];
	char tot_len[30];
	char id[30];
	char df[30];
	char mf[30];
	char offset[30];
	char ttl[30];
	char checksum[30];
	char protocol[30];
	char src_ip[30];
	char dst_ip[30];
};

struct disp_tcp
{
	char title[100];
	char source[50];
	char dest[50];
	char seq[50];
	char ack_seq[50];
	char tcp_len[50];
	char urg[30];
	char ack[30];
	char psh[30];
	char rst[30];
	char syn[30];
	char fin[30];
	char win[30];
	char check[30];
};

struct disp_udp
{
	char title[100];
	char source[30];
	char dest[30];
	char length[30];
	char check[30];
};

struct disp_data
{
	char title[30];
	char data[1024];
};
#endif
