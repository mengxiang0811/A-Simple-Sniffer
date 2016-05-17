#ifndef PCAP_MANAGER_H
#define PCAP_MANAGER_H

#define GTK_ENABLE_BROKEN

#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/icmp.h>
#include <netinet/igmp.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

#include "global.h"
#include "disp_data.h"


extern uint32_t offset;
extern int tot_packet;

extern FILE *out;
extern FILE *rec_out;
 
extern FILE *rec_in;
extern FILE *in;

extern pthread_mutex_t frame_item_mtx;
extern struct disp_record frame_item[MAX_ITEM];                           

extern char pcap_packet_buf[BUFSIZE];
extern struct pcap_pkthdr pcaphdr;
extern uint32_t rec_id;
extern uint16_t proto_type;
extern struct disp_frame frame_buf;
extern struct disp_ether ether_buf;
extern struct disp_ip ip_buf;
extern struct disp_tcp tcp_buf;
extern struct disp_udp udp_buf;
extern struct disp_data data_buf;
extern struct disp_arp arp_buf;
extern gchar *str;

extern int packet_size;
extern int app_len;

extern const char pfh[24];

void init_file();
void write_to_pcap(uint8_t *data,const struct pcap_pkthdr *pcap_header);

void read_record(uint32_t id);

void pcap_parser(uint8_t *packet_content,struct pcap_pkthdr *pcap_header);
#endif
