#define GTK_ENABLE_BROKEN

#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
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


#include "pcap_manager.h"

extern struct timeval capture_start_time;
extern int capture_pre_packet;

extern int ifnum;

extern int capture_state;
extern char filter_str[FILTER_LEN];
extern char filter_str2[FILTER_LEN];
extern char ifname[50];

extern int tot_packet;
extern int ip_packet;
extern int tcp_packet;
extern int udp_packet;
extern int arp_packet;
extern int icmp_packet;
extern int igmp_packet;

extern struct interface_item ifitem[24];
extern struct disp_record frame_item[MAX_ITEM];

extern pthread_mutex_t capture_state_mtx;
extern pthread_mutex_t frame_item_mtx;
extern pthread_mutex_t packet_stat_mtx;
extern pthread_mutex_t handle_mtx;

extern pcap_t *pcap_handle;
extern pcap_if_t *alldevs;
extern pcap_if_t *dev;
extern GtkWidget *clist;

extern  char pcap_errbuf[PCAP_ERRBUF_SIZE];

void init_pcap();
float time_diff(struct timeval start,struct timeval end);
void capture_packet();
void packet_process(unsigned char *argument, \
		const struct pcap_pkthdr* pcap_header, \
		const unsigned char *packet_content);
void record_packet(uint8_t *packet);

void *capture(void *arg);
void *clist_refresh(void *arg);
