#ifndef MENU_FUNC_H
#define MENU_FUNC_H

#define GTK_ENABLE_BROKEN
#include <gnome.h>
#include <pthread.h>
#include <stdint.h>

#include "global.h"
#include "capture.h"

extern GtkWidget *app;
extern GtkWidget *clist;
extern GtkWidget *tree;
extern GtkWidget *item[5];
extern GtkWidget *hex_text;
extern GtkWidget *char_text;
extern GtkWidget *scrolled_win;
extern GnomeUIInfo capture_menu[];

extern int tot_packet;
extern int capture_pre_packet;
extern int ip_packet;
extern int tcp_packet;
extern int udp_packet;
extern int arp_packet;
extern int icmp_packet;
extern int igmp_packet;

extern pthread_mutex_t capture_state_mtx;
extern pthread_mutex_t packet_stat_mtx;
extern int capture_state;
extern char filter_str[FILTER_LEN];
extern char ifname[50];

#if 0
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

extern int packet_size;                                                   
extern int app_len;         
#endif

void capture_start();

void capture_stop();

void program_exit();

void ifselect();

void capture_filter();

void display_statistics();

void display_contents();

void about();

void selection_made( GtkWidget *clist,
		gint row,
		gint column,
		GdkEventButton *event,
		gpointer data );

#endif
