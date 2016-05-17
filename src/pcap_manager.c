#include "pcap_manager.h"

void init_file()
{
	offset = 0;
	
	if (out) {
		fclose(out);
		out = NULL;
	}

	if (rec_out) {
		fclose(rec_out);
		rec_out = NULL;
	}

	if (access(PCAPTMP,0) == 1)
	{
		remove(PCAPTMP);
	}

	if (rec_in) {
		fclose(rec_in);
		rec_in = NULL;
	}

	if (in) {
		fclose(in);
		in = NULL;
	}

	if (access(RECTMP,0) == 1){
		remove(RECTMP);
	}

	out = fopen(PCAPTMP, "w+");

	if (out == NULL)
	{
		fprintf(stderr,"error: %s\n",strerror(errno));
		exit(1);
	}

	rec_out = fopen(RECTMP,"w+");

	if (rec_out == NULL)
	{
		fprintf(stderr,"error: %s\n",strerror(errno));
		exit(1);
	}

	offset += sizeof(pfh);

	fwrite(pfh,sizeof(pfh),1,out);
	fclose(out);
	fclose(rec_out);
	out = NULL;
	rec_out = NULL;
}

void write_to_pcap(uint8_t *data,const struct pcap_pkthdr *pcap_header)
{
	struct pcap_record pcap_rec;

	out = fopen(PCAPTMP, "a+");
	rec_out = fopen(RECTMP,"a+");

	pcap_rec.offset = offset;

	offset += pcap_header->caplen + sizeof(struct pcap_pkthdr);
	fwrite(&pcap_rec,sizeof(struct pcap_record),1,rec_out);
	fflush(rec_out);
	fclose(rec_out);

	rec_out = NULL;

	fwrite(pcap_header,sizeof(struct pcap_pkthdr),1,out);
	fwrite(data,pcap_header->caplen,1,out);
	fflush(out);
	fclose(out);
	out = NULL;
}

void read_record(uint32_t recid)
{
	uint16_t i = 0;
	struct pcap_record record;

	rec_id = recid;

	rec_in = fopen(RECTMP,"r+");
	fseek(rec_in,sizeof(struct pcap_record) * recid,SEEK_SET);
	fread(&record,sizeof(record),1,rec_in);
	fclose(rec_in);
	rec_in = NULL;

	in = fopen(PCAPTMP,"r+");
	fseek(in,0L,SEEK_SET);
	fseek(in,record.offset,SEEK_SET);
	fread(&pcaphdr,sizeof(pcaphdr),1,in);
	
	packet_size = pcaphdr.caplen;
	memset(pcap_packet_buf,0,sizeof(pcap_packet_buf));
	fread(pcap_packet_buf,pcaphdr.caplen,1,in);
	fclose(in);
	in = NULL;
}

void tcp_parse(const unsigned char *packet_content,uint16_t tot_len,uint16_t iphdrlen)
{
	struct tcphdr *tcp;
	uint16_t len = 0;
	char tmp[5];
	char *applayer;

	tcp = (struct tcphdr *)(packet_content + MAC_HDRLEN + iphdrlen);

	sprintf(tcp_buf.title,"Transmission Control Protocol, Src port: %d, Dst port: %d",ntohs(tcp->source),ntohs(tcp->dest));
	sprintf(tcp_buf.source,"Source port: %d",ntohs(tcp->source));
	sprintf(tcp_buf.dest,"Destination port: %d",ntohs(tcp->dest));
	sprintf(tcp_buf.seq,"Sequence number: %u",ntohl(tcp->seq));
	sprintf(tcp_buf.ack_seq,"Acknowledgement number: %u",ntohl(tcp->ack_seq));
	sprintf(tcp_buf.tcp_len,"Tcp header length: %d",tcp->doff << 2);
	sprintf(tcp_buf.urg,"Urgent: %d",tcp->urg);
	sprintf(tcp_buf.ack,"Acknowledgement: %d",tcp->ack);
	sprintf(tcp_buf.psh,"Push: %d",tcp->psh);
	sprintf(tcp_buf.rst,"reset: %d",tcp->rst);
	sprintf(tcp_buf.syn,"Syn: %d",tcp->syn);
	sprintf(tcp_buf.fin,"Fin: %d",tcp->fin);
	sprintf(tcp_buf.win,"Window size value: %d",ntohs(tcp->window));
	sprintf(tcp_buf.check,"Checksum: 0x%04x",ntohs(tcp->check));

	app_len = tot_len - iphdrlen - (tcp->doff << 2);

	if (app_len != 0)
	{
		applayer = (unsigned char *)tcp + (tcp->doff << 2);

		sprintf(data_buf.title,"Data(%d bytes)",app_len);
		for (len = 0; len < app_len; len++)
		{
			memset(tmp,0,sizeof(tmp));
			sprintf(tmp,"%02x",applayer[len]);
			if (len < 16) {
				strcat(data_buf.data,tmp);
			}
			else if (len == 16){
				strcat(data_buf.data,"...");
			}
		}
	}
}

void udp_parse(const unsigned char *packet_content,uint16_t iphdrlen) {
	struct udphdr *udp;
	uint16_t len = 0;
	char tmp[5];
	unsigned char *applayer;

	udp = (struct udphdr *)(packet_content + MAC_HDRLEN + iphdrlen);

	sprintf(udp_buf.title,"User Datagram Protocol, Src port: %d, Dst port: %d",ntohs(udp->source),ntohs(udp->dest));
	sprintf(udp_buf.source,"Source port: %d",ntohs(udp->source));
	sprintf(udp_buf.dest,"Destination port: %d",ntohs(udp->dest));
	sprintf(udp_buf.length,"Length: %d",ntohs(udp->len));
	sprintf(udp_buf.check,"CheckSum: 0x%04x",ntohs(udp->check));

	app_len = ntohs(udp->len) - 8;

	if (app_len != 0)
	{
		applayer = (unsigned char *)udp + 8;

		sprintf(data_buf.title,"Data(%d bytes)",app_len);
		for (len = 0; len < app_len; len++)
		{
			memset(tmp,0,sizeof(tmp));
			sprintf(tmp,"%02x",applayer[len]);
			if (len < 16) {
				strcat(data_buf.data,tmp);
			}
			else if (len == 16){
				strcat(data_buf.data,"...");
			}
			else
				continue;
		}
	}
}

void icmp_parse(const unsigned char *packet_content,uint16_t iphdrlen)
{
}

void igmp_parse(const unsigned char *packet_content,uint16_t iphdrlen)
{
}

void arp_parse(const struct pcap_pkthdr* pcap_header, \
		const unsigned char *packet_content)
{
	struct in_addr src,dst;
	struct arp_header *arp;
	unsigned char *mac;

	arp = (struct arp_header *)(packet_content + MAC_HDRLEN);
	
	pthread_mutex_lock(&frame_item_mtx);
	sprintf(arp_buf.title,"%s","Address Resolution Protocol");
	sprintf(arp_buf.ar_hrd,"Hardware type:  Ethernet (0x%04x)",ntohs(arp->ar_hrd));

	switch (ntohs(arp->ar_pro))
	{
		case 0x0800:
			sprintf(arp_buf.ar_pro,"%s","Protocol type:  IP (0x0800)");
			break;
		case 0x0806:
			sprintf(arp_buf.ar_pro,"%s","Protocol type:  ARP (0x0806)");
			break;
		default:
			sprintf(arp_buf.ar_pro,"Protocol type:  Unknown (0x%04x)",ntohs(arp->ar_pro));
			break;
	}	

	sprintf(arp_buf.ar_hln,"Hardware size:  %d",arp->ar_hln);
	sprintf(arp_buf.ar_pln,"Protocol size:  %d",arp->ar_pln);
	sprintf(arp_buf.ar_op,"Opcode:  0x%04x",ntohs(arp->ar_op));
	mac = arp->ar_srcmac;
	sprintf(arp_buf.src_mac,"Sender MAC address:  %02x:%02x:%02x:%02x:%02x:%02x",*mac, *(mac + 1), *(mac + 2), *(mac + 3), *(mac + 4), *(mac + 5));
	mac = arp->ar_dstmac;
	sprintf(arp_buf.dst_mac,"Target MAC address:  %02x:%02x:%02x:%02x:%02x:%02x",*mac, *(mac + 1), *(mac + 2), *(mac + 3), *(mac + 4), *(mac + 5));
	
	sprintf(arp_buf.src_ip,"Sender IP address:  %s",frame_item[rec_id].srcip);
	sprintf(arp_buf.dst_ip,"Target IP address:  %s",frame_item[rec_id].dstip);

	pthread_mutex_unlock(&frame_item_mtx);
}

void ipv4_parse(const struct pcap_pkthdr* pcap_header, \
		const unsigned char *packet_content)
{
	struct in_addr src,dst;
	struct iphdr *ip;
	ip = (struct iphdr *)(packet_content + MAC_HDRLEN);

	pthread_mutex_lock(&frame_item_mtx);
	sprintf(ip_buf.title,"Internet Protocol Version %d, Src: %s, Dst: %s",ip->version,frame_item[rec_id].srcip,frame_item[rec_id].dstip);
	sprintf(ip_buf.src_ip,"Source:  %s",frame_item[rec_id].srcip);
	sprintf(ip_buf.dst_ip,"Destination:  %s",frame_item[rec_id].dstip);
	pthread_mutex_unlock(&frame_item_mtx);

	sprintf(ip_buf.version,"Version:  %d",ip->version);
	sprintf(ip_buf.headlen,"Header length:  %d bytes",ip->ihl * 4);
	sprintf(ip_buf.tos,"Type of service:  %d",ip->tos);
	sprintf(ip_buf.tot_len,"Total length:  %d bytes",ntohs(ip->tot_len));
	sprintf(ip_buf.id,"Identification:  0x%04x",ntohs(ip->id));
	sprintf(ip_buf.df,"DF:  %d",(ntohs(ip->frag_off) & IP_DF) >> 14);
	sprintf(ip_buf.mf,"MF:  %d",(ntohs(ip->frag_off) & IP_MF) >> 13);
	sprintf(ip_buf.offset,"Fragment offset:  %d",(ntohs(ip->frag_off) & 0x1fff) * 8);
	sprintf(ip_buf.ttl,"Time to live:  %d",ip->ttl);
	sprintf(ip_buf.checksum,"Header checksum:  0x%04x",ntohs(ip->check));

	switch (ip->protocol) {
		case IPPROTO_TCP:
			proto_type = IPPROTO_TCP;
			sprintf(ip_buf.protocol,"Protocol:  TCP (6)");
			//tcp_parse(argument,pcap_header,packet_content);
			tcp_parse(packet_content,ntohs(ip->tot_len),(ip->ihl << 2));
			break;
		case IPPROTO_UDP:
			proto_type = IPPROTO_UDP;
			sprintf(ip_buf.protocol,"Protocol:  UDP (17)");
			udp_parse(packet_content,(ip->ihl << 2));
			break;
		case IPPROTO_ICMP:
			proto_type = IPPROTO_ICMP;
			sprintf(ip_buf.protocol,"Protocol:  ICMP (1)");
			icmp_parse(packet_content,ip->ihl * 4);
			break;
		case IPPROTO_IGMP:
			proto_type = IPPROTO_IGMP;
			sprintf(ip_buf.protocol,"Protocol:  IGMP (%d)",ip->protocol);
			igmp_parse(packet_content,ip->ihl * 4);
			break;
		default:
			sprintf(ip_buf.protocol,"Protocol:  Other (%d)",ip->protocol);
			break;
	}
}


void pcap_parser(uint8_t *packet_content,struct pcap_pkthdr *pcap_header)
{
	proto_type = UNKNOWN;

	struct ethhdr *ethptr;
	unsigned char *mac;
	ethptr = (struct ethhdr *)packet_content;

	memset(&frame_buf,0,sizeof(struct disp_frame));
	memset(&ether_buf,0,sizeof(struct disp_ether));
	memset(&ip_buf,0,sizeof(struct disp_ip));
	memset(&tcp_buf,0,sizeof(struct disp_tcp));
	memset(&udp_buf,0,sizeof(struct disp_udp));
	memset(&data_buf,0,sizeof(struct disp_data));
	memset(&arp_buf,0,sizeof(struct disp_arp));

	sprintf(frame_buf.title,"%s","Frame");
	sprintf(frame_buf.length,"Frame length = %d",pcap_header->caplen);

	pthread_mutex_lock(&frame_item_mtx);
	sprintf(ether_buf.title,"Ethernet II, Src:  (%s), Dst:  (%s)",frame_item[rec_id].srcmac,frame_item[rec_id].dstmac);
	pthread_mutex_unlock(&frame_item_mtx);

	mac= (unsigned char *)ethptr->h_source;
	sprintf(ether_buf.src_mac,"Source:  %02x:%02x:%02x:%02x:%02x:%02x",*mac,*(mac + 1),*(mac + 2),*(mac + 3),*(mac + 4),*(mac + 5));
	mac= (unsigned char *)ethptr->h_dest;
	sprintf(ether_buf.dst_mac,"Destination:  %02x:%02x:%02x:%02x:%02x:%02x",*mac,*(mac + 1),*(mac + 2),*(mac + 3),*(mac + 4),*(mac + 5));

	switch(ntohs((uint16_t)ethptr->h_proto)) {
		case 0x0800:
			strcat(ether_buf.protocol,"Type:  IP(0x0800)");
			ipv4_parse(pcap_header,packet_content);
			break;
		case 0x0806:
			proto_type = ARP;
			strcat(ether_buf.protocol,"Type:  ARP(0x0806)");
			arp_parse(pcap_header,packet_content);
			break;
		default:
			sprintf(ether_buf.protocol,"%s%04x","Type: other ",ntohs((uint16_t)ethptr->h_proto));
			break;
	}
}

void display_hexinfo(unsigned char *msg,GtkWidget *window)
{
	uint16_t len = packet_size;
	//uint16_t len = strlen(msg);
	uint8_t line = 0;
	uint16_t i = 0;

	char tmp[5];
	char result[200];

	memset(tmp,0,sizeof(tmp));
	memset(result,0,sizeof(result));

	sprintf(result,"%03x0\t",line);

	gtk_text_freeze(GTK_TEXT(window));
	guint text_len = gtk_text_get_length(GTK_TEXT(window));
	gtk_text_backward_delete(GTK_TEXT(window),text_len);

	for (i = 0;i < len;i++)
	{
		if ((i != 0) && (i % 16 == 0))
		{
			line++;
			strcat(result,"\n");
			gtk_text_insert(GTK_TEXT(window),NULL,&window->style->black,NULL,result,-1);
			memset(result,0,sizeof(result));
			sprintf(result,"%03x0\t",line);
		}
		else if ((i != 0) && (i % 8 == 0))
		{
			strcat(result," ");
		}

		memset(tmp,0,sizeof(tmp));
		sprintf(tmp,"%02x ",msg[i]);
		strcat(result,tmp);
	}

	gtk_text_insert(GTK_TEXT(window),NULL,&window->style->black,NULL,result,-1);

	gtk_text_thaw(GTK_TEXT(window));
}

void display_cinfo(char *msg,GtkWidget *window)
{
	uint16_t len = packet_size; 
	//uint16_t len = strlen(msg);
	uint8_t line = 0;
	uint16_t i = 0;

	char result[200];
	char tmp[3];

	memset(result,0,sizeof(result));

	gtk_text_freeze(GTK_TEXT(window));
	guint text_len = gtk_text_get_length(GTK_TEXT(window));
	gtk_text_backward_delete(GTK_TEXT(window),text_len);

	for (i = 0;i < len;i++)
	{
		if ((i != 0 && i % 16 == 0))
		{
			strcat(result,"\n");
			gtk_text_insert(GTK_TEXT(window),NULL,&window->style->black,NULL,result,-1);
			memset(result,0,sizeof(result));
		}
		else if ((i != 0) && (i % 8 == 0))
		{
			strcat(result," ");
		}

		if (isprint(msg[i]))
		{
			memset(tmp,0,sizeof(tmp));
			sprintf(tmp,"%c",msg[i]);
			strcat(result,tmp);
		}
		else
		{
			strcat(result,".");
		}

	}
	gtk_text_insert(GTK_TEXT(window),NULL,&window->style->black,NULL,result,-1);

	gtk_text_thaw(GTK_TEXT(window));
}
