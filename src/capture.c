#include "capture.h"

void init_pcap()
{
	ifnum = 0;
	capture_state = 0;

	memset(filter_str,0,sizeof(filter_str));
	memset(filter_str2,0,sizeof(filter_str2));
	memset(ifitem,0,sizeof(struct interface_item) * 24);

	strcpy(filter_str,"");
	memset(ifname,0,sizeof(ifname));

	if (pcap_findalldevs(&alldevs,pcap_errbuf) == -1)
	{
		fprintf(stderr,"find interface failed!\n");
		exit(1);
	}

	pthread_mutex_lock(&frame_item_mtx);
	for (dev = alldevs; dev != NULL; dev = dev->next)
	{
		strcpy(ifitem[ifnum].ifname,dev->name);
		if (dev->description) {
			strcpy(ifitem[ifnum].ifdesc,dev->description);
		}
		ifnum++;
	}
	pthread_mutex_unlock(&frame_item_mtx);

	pcap_freealldevs(alldevs);
}

float time_diff(struct timeval start,struct timeval end)
{
	return ((((end.tv_sec * ITEM + end.tv_usec) - (start.tv_sec * ITEM + start.tv_usec)) * 1.0 )/ ITEM); 
}

void arp_stat(unsigned char *argument, \
		const struct pcap_pkthdr* pcap_header, \
		const unsigned char *packet_content)
{
	struct in_addr src,dst;
	struct arp_header *arp;

	arp = (struct arp_header *)(packet_content + MAC_HDRLEN);
	
	src.s_addr = arp->ar_srcip;
	dst.s_addr = arp->ar_dstip;
	
	pthread_mutex_lock(&frame_item_mtx);
	sprintf(frame_item[tot_packet].srcip,"%s",inet_ntoa(src));
	sprintf(frame_item[tot_packet].dstip,"%s",inet_ntoa(dst));
	sprintf(frame_item[tot_packet].protocol,"%s","ARP");
	pthread_mutex_unlock(&frame_item_mtx);
}

void ipv4_stat(unsigned char *argument, \
		const struct pcap_pkthdr* pcap_header, \
		const unsigned char *packet_content)
{
	struct in_addr src,dst;
	struct iphdr *ip;
	ip = (struct iphdr *)(packet_content + MAC_HDRLEN);

	src.s_addr = ip->saddr;
	dst.s_addr = ip->daddr;

	pthread_mutex_lock(&frame_item_mtx);
	sprintf(frame_item[tot_packet].srcip,"%s",inet_ntoa(src));
	sprintf(frame_item[tot_packet].dstip,"%s",inet_ntoa(dst));

	switch(ip->protocol)
	{
		case IPPROTO_TCP:
			sprintf(frame_item[tot_packet].protocol,"%s","TCP");
			tcp_packet++;
			break;
		case IPPROTO_UDP:
			sprintf(frame_item[tot_packet].protocol,"%s","UDP");
			udp_packet++;
			break;
		case IPPROTO_ICMP:
			sprintf(frame_item[tot_packet].protocol,"%s","ICMP");
			icmp_packet++;
			break;
		case IPPROTO_IGMP:
			sprintf(frame_item[tot_packet].protocol,"%s","IGMP");
			igmp_packet++;
			break;
		default:
			sprintf(frame_item[tot_packet].protocol,"%s","OTHER");
			break;
	}
	pthread_mutex_unlock(&frame_item_mtx);
}

void packet_process(unsigned char *argument, \
		const struct pcap_pkthdr* pcap_header, \
		const unsigned char *packet_content)
{
	struct ethhdr *ethptr;
	unsigned char *mac;
	float sec = 0.0;
	ethptr = (struct ethhdr *)packet_content;

	if (tot_packet == 0)
	{
		capture_start_time = pcap_header->ts;
	}

	pthread_mutex_lock(&capture_state_mtx);
	if (capture_state == 1)
	{
		pthread_mutex_lock(&frame_item_mtx);

		//sprintf(frame_item[tot_packet].id,"%u",(tot_packet + 1));
		frame_item[tot_packet].id = (tot_packet + 1);
		frame_item[tot_packet].length = pcap_header->caplen;
		sec = time_diff(capture_start_time,pcap_header->ts);
		sprintf(frame_item[tot_packet].time,"%.6f",sec);

		mac= (unsigned char *)ethptr->h_source;
		sprintf(frame_item[tot_packet].srcmac,"%02x:%02x:%02x:%02x:%02x:%02x",*mac,*(mac + 1),*(mac + 2),*(mac + 3),*(mac + 4),*(mac + 5));
		mac= (unsigned char *)ethptr->h_dest;
		sprintf(frame_item[tot_packet].dstmac,"%02x:%02x:%02x:%02x:%02x:%02x",*mac,*(mac + 1),*(mac + 2),*(mac + 3),*(mac + 4),*(mac + 5));

		pthread_mutex_unlock(&frame_item_mtx);

		write_to_pcap((uint8_t *)packet_content,pcap_header);

		pthread_mutex_lock(&packet_stat_mtx);

		switch(ntohs((uint16_t)ethptr->h_proto)) {
			case 0x0800:
				ip_packet++;
				ipv4_stat(argument,pcap_header,packet_content);
				break;
			case 0x0806:
				arp_packet++;
				arp_stat(argument,pcap_header,packet_content);
				break;
			default:
				break;
		}
		tot_packet++;
		pthread_mutex_unlock(&packet_stat_mtx);
	}
	pthread_mutex_unlock(&capture_state_mtx);
}

void capture_packet()
{
	//pcap_handle =pcap_open_live(ifname,BUFSIZE,1,-1,pcap_errbuf);
	pcap_handle = pcap_open_offline("/home/albert/桌面/pcap/1.pcap",pcap_errbuf);

	if (pcap_handle == NULL)
	{
		fprintf(stderr,"open error :%s\n",pcap_errbuf);
		exit(1);
	}

	if (filter_str != NULL && filter_str[0] != '\0') {
		struct bpf_program filter;

		if (pcap_compile(pcap_handle, &filter, filter_str, 1, 0) < 0) {
			printf("pcap_compile: %s", pcap_errbuf);
			exit(1);
		}

		if (pcap_setfilter(pcap_handle, &filter) < 0) {
			printf("pcap_setfilter: %s", pcap_errbuf);
			exit(1);
		}

		pcap_freecode(&filter);
	}
}

void *capture(void *arg)
{
	while (1)
	{
		if (pcap_handle) {
			pcap_loop(pcap_handle,100,packet_process,NULL);
		}
		else {
			sleep(1);
		}
	}
}

void *clist_refresh(void *arg)
{
	while (1) {
		uint16_t packet_num;
		uint16_t i = 0;
		uint8_t j = 0;
		gchar *record_buf[8];

		pthread_mutex_lock(&packet_stat_mtx);
		packet_num = tot_packet - capture_pre_packet;

		for (i = 0; i < packet_num; i++) {
#if 0
			for (j = 0; j < 8; j++) {
				memset(record_buf[j],0,sizeof(record_buf[j]));
			}

			sprintf(record_buf[0],"%u",frame_item[i + capture_pre_packet].id);
			sprintf(record_buf[1],"%s",frame_item[i + capture_pre_packet].time);
			sprintf(record_buf[2],"%s",frame_item[i + capture_pre_packet].srcmac);
			sprintf(record_buf[3],"%s",frame_item[i + capture_pre_packet].dstmac);
			sprintf(record_buf[4],"%s",frame_item[i + capture_pre_packet].srcip);
			sprintf(record_buf[5],"%s",frame_item[i + capture_pre_packet].dstip);
			sprintf(record_buf[6],"%s",frame_item[i + capture_pre_packet].protocol);
			sprintf(record_buf[7],"%u",frame_item[i + capture_pre_packet].length);
#endif
			gchar id[20];
			gchar len[20];

			memset(id,0,sizeof(id));
			memset(len,0,sizeof(len));
			sprintf(id,"%u",frame_item[i + capture_pre_packet].id);
			sprintf(len,"%u",frame_item[i + capture_pre_packet].length);
			record_buf[0] = id;
			record_buf[1] = frame_item[i + capture_pre_packet].time;
			record_buf[2] = frame_item[i + capture_pre_packet].srcmac;
			record_buf[3] = frame_item[i + capture_pre_packet].dstmac;
			record_buf[4] = frame_item[i + capture_pre_packet].srcip;
			record_buf[5] = frame_item[i + capture_pre_packet].dstip;
			record_buf[6] = frame_item[i + capture_pre_packet].protocol;
			record_buf[7] = len;

			gtk_clist_append((GtkCList *) clist, record_buf);
		}

		capture_pre_packet = tot_packet;
		pthread_mutex_unlock(&packet_stat_mtx);
		sleep(2);
	}
}
