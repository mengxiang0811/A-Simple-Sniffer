#include "menu_func.h"

void dialog_ok(GnomeDialog *dialog,gint id,gpointer data)
{
	gnome_dialog_close(dialog);
}

void capture_start(GtkWidget *widget,gpointer data)
{
	GtkWidget *isenable;
	uint8_t i = 0;
	guint text_len = 0;

	pthread_mutex_lock(&capture_state_mtx);
	if (capture_state == 0)
		capture_state = 1;
	pthread_mutex_unlock(&capture_state_mtx);

	init_file();
	capture_packet();

	pthread_mutex_lock(&packet_stat_mtx);
	tot_packet = 0;
	ip_packet = 0;
	tcp_packet = 0;
	udp_packet = 0;
	arp_packet = 0;
	icmp_packet = 0;
	igmp_packet = 0;
	capture_pre_packet = 0;
	pthread_mutex_unlock(&packet_stat_mtx);

	isenable = capture_menu[0].widget;
	gtk_widget_set_sensitive(isenable,FALSE);
	isenable = capture_menu[1].widget;
	gtk_widget_set_sensitive(isenable,TRUE);
	gtk_clist_clear((GtkCList *)clist);

	for (i = 0;i < 5;i++)
	{
		if (item[i]) {
			gtk_tree_item_remove_subtree((GtkTreeItem *)item[i]);
			gtk_container_remove (GTK_CONTAINER(tree), item[i]);
			item[i] = NULL;
		}
	}

	gtk_text_freeze(GTK_TEXT(hex_text));
	text_len = gtk_text_get_length(GTK_TEXT(hex_text));
	gtk_text_backward_delete(GTK_TEXT(hex_text),text_len);
	gtk_text_thaw(GTK_TEXT(hex_text));

	gtk_text_freeze(GTK_TEXT(hex_text));
	text_len = gtk_text_get_length(GTK_TEXT(hex_text));
	gtk_text_backward_delete(GTK_TEXT(hex_text),text_len);
	gtk_text_thaw(GTK_TEXT(hex_text));
}

void capture_stop(GtkWidget *widget,gpointer data)
{
	GtkWidget *isenable;
	pthread_mutex_lock(&capture_state_mtx);
	if (capture_state == 1)
		capture_state = 0;
	pthread_mutex_unlock(&capture_state_mtx);

	isenable = capture_menu[0].widget;
	gtk_widget_set_sensitive(isenable,TRUE);
	isenable = capture_menu[1].widget;
	gtk_widget_set_sensitive(isenable,FALSE);
}

void program_exit(GtkWidget *widget,gpointer data)
{
	gtk_main_quit();
}

void get_ifcard_str(GtkWidget *widget,gpointer data)
{
	strcpy(ifname,gtk_entry_get_text(GTK_ENTRY(widget)));
}

void get_filter_str(GtkWidget *widget,gpointer data)
{
	strcpy(filter_str,gtk_entry_get_text(GTK_ENTRY((GtkWidget*)data)));
}

void ifselect(GtkWidget *widget,gpointer data)
{
	gint i = 0;
	GtkWidget *dialog;
	GtkWidget *_hbox;
	GtkWidget *label;
	GList *glist=NULL;
	GtkWidget *ifCombo;
	dialog = gnome_dialog_new(_("Choose a interface to capture"),_("OK"),NULL,NULL);
	
	_hbox = gtk_hbox_new(FALSE,0);
	label = gtk_label_new("Choose an interface: ");
	ifCombo = gtk_combo_new();

	for (i = 0; i < ifnum; i++)
	{
		glist = g_list_append(glist, ifitem[i].ifname);
	}
	gtk_combo_set_popdown_strings( GTK_COMBO(ifCombo), glist);
	
	gtk_box_pack_start(GTK_BOX(_hbox),label,FALSE,FALSE,5); 
	gtk_box_pack_start(GTK_BOX(_hbox),ifCombo,FALSE,FALSE,5); 
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),_hbox,TRUE,TRUE,0);

	gtk_signal_connect(GTK_OBJECT(GTK_COMBO(ifCombo)->entry), "activate",
			GTK_SIGNAL_FUNC (get_ifcard_str),NULL);
	gtk_widget_show(ifCombo);
	gtk_widget_show(label);
	gtk_widget_show(_hbox);

	gtk_signal_connect(GTK_OBJECT(dialog),"clicked",GTK_SIGNAL_FUNC(dialog_ok),&dialog);
	gtk_window_set_modal(GTK_WINDOW(dialog),TRUE);
	gtk_widget_show(dialog);
	gnome_dialog_set_parent(GNOME_DIALOG(dialog),GTK_WINDOW(app));
}

void capture_filter()
{
	GtkWidget *dialog;
	GtkWidget *_hbox, *filter_label, *filter_entry, *filter_button;

	dialog = gnome_dialog_new(_("FilterString"),_("OK"),NULL,NULL);

	_hbox = gtk_hbox_new(FALSE,0);
	gtk_container_set_border_width(GTK_CONTAINER(_hbox), 5);
	filter_label = gtk_label_new("Filter String: ");
	filter_entry = gtk_entry_new();                                       
	filter_button = gtk_button_new_with_label("Save");                  

	gtk_box_pack_start(GTK_BOX(_hbox),filter_label,FALSE,FALSE,5);         
	gtk_box_pack_start(GTK_BOX(_hbox),filter_entry,TRUE,TRUE,6);
	gtk_box_pack_start(GTK_BOX(_hbox),filter_button,FALSE,FALSE,5);   
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),_hbox,TRUE,TRUE,0);
	
	g_signal_connect(GTK_OBJECT(filter_button),"clicked",GTK_SIGNAL_FUNC(get_filter_str),filter_entry);
	gtk_signal_connect(GTK_OBJECT(dialog),"clicked",GTK_SIGNAL_FUNC(dialog_ok),&dialog);
	gtk_window_set_modal(GTK_WINDOW(dialog),TRUE);
	
	gtk_widget_show(filter_label);
	gtk_widget_show(filter_entry);
	gtk_widget_show(filter_button);
	gtk_widget_show(_hbox);
	gtk_widget_show(dialog);
	gnome_dialog_set_parent(GNOME_DIALOG(dialog),GTK_WINDOW(app));
}

void display_statistics()
{
	gchar display[50];

	GtkWidget *dialog;
	GtkWidget *totlabel, *iplabel, *tcplabel, *udplabel, *arplabel, *icmplabel, *igmplabel;
	dialog = gnome_dialog_new(_("Statistics of the packets"),_("OK"),NULL,NULL);

	pthread_mutex_lock(&packet_stat_mtx);

	memset(display,0,sizeof(display));
	sprintf(display,"Total packets: %d",tot_packet);
	totlabel = gtk_label_new(display);

	memset(display,0,sizeof(display));
	sprintf(display,"IP packets: %d",ip_packet);
	iplabel = gtk_label_new(display);

	memset(display,0,sizeof(display));
	sprintf(display,"TCP packets: %d",tcp_packet);
	tcplabel = gtk_label_new(display);

	memset(display,0,sizeof(display));
	sprintf(display,"UDP packets: %d",udp_packet);
	udplabel = gtk_label_new(display);

	memset(display,0,sizeof(display));
	sprintf(display,"ARP packets: %d",arp_packet);
	arplabel = gtk_label_new(display);

	memset(display,0,sizeof(display));
	sprintf(display,"ICMP packets: %d",icmp_packet);
	icmplabel = gtk_label_new(display);

	memset(display,0,sizeof(display));
	sprintf(display,"IGMP packets: %d",igmp_packet);
	igmplabel = gtk_label_new(display);

	pthread_mutex_unlock(&packet_stat_mtx);

	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),totlabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),iplabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),tcplabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),udplabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),arplabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),icmplabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),igmplabel,TRUE,TRUE,0);

	gtk_widget_show(totlabel);
	gtk_widget_show(iplabel);
	gtk_widget_show(tcplabel);
	gtk_widget_show(udplabel);
	gtk_widget_show(arplabel);
	gtk_widget_show(icmplabel);
	gtk_widget_show(igmplabel);

	gtk_signal_connect(GTK_OBJECT(dialog),"clicked",GTK_SIGNAL_FUNC(dialog_ok),&dialog);
	gtk_window_set_modal(GTK_WINDOW(dialog),TRUE);
	gtk_widget_show(dialog);
	gnome_dialog_set_parent(GNOME_DIALOG(dialog),GTK_WINDOW(app));
}

void display_contents()
{ 
#if 0
	display_hexinfo((unsigned char *)str,hex_text);
	display_cinfo((unsigned char *)str,char_text);
#endif
	display_hexinfo((unsigned char *)pcap_packet_buf,hex_text);
	display_cinfo((unsigned char *)pcap_packet_buf,char_text);
}

void about()
{
	GtkWidget *dialog;
	GtkWidget *contentlabel,*versionlabel,*authorlabel,*copyrightlabel;
	dialog = gnome_dialog_new(_("About the program"),_("OK"),NULL,NULL);
	contentlabel = gtk_label_new(_("Linux sniffer"));
	copyrightlabel = gtk_label_new(_("Copyright 2011-10-06"));
	authorlabel = gtk_label_new(_("付乔宾"));
	versionlabel = gtk_label_new(_("Version：1.0"));

	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),contentlabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),versionlabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),copyrightlabel,TRUE,TRUE,0);
	gtk_box_pack_start(GTK_BOX(GNOME_DIALOG(dialog)->vbox),authorlabel,TRUE,TRUE,0);

	gtk_widget_show(contentlabel);
	gtk_widget_show(versionlabel);
	gtk_widget_show(copyrightlabel);
	gtk_widget_show(authorlabel);

	gtk_signal_connect(GTK_OBJECT(dialog),"clicked",GTK_SIGNAL_FUNC(dialog_ok),&dialog);
	gtk_window_set_modal(GTK_WINDOW(dialog),TRUE);
	gtk_widget_show(dialog);
	gnome_dialog_set_parent(GNOME_DIALOG(dialog),GTK_WINDOW(app));
}

void append_frame_tree()
{
	GtkWidget *subtree;
	item[0] = gtk_tree_item_new_with_label(frame_buf.title);
	gtk_tree_append(GTK_TREE(tree),item[0]);
	subtree = gtk_tree_new();

	gtk_tree_set_selection_mode (GTK_TREE(subtree),GTK_SELECTION_SINGLE);
	gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);   
	gtk_tree_item_set_subtree (GTK_TREE_ITEM(item[0]), subtree);      

	GtkWidget *subitem;                                           
	subitem = gtk_tree_item_new_with_label (frame_buf.length);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);                         
	gtk_widget_show (item[0]);
}

void append_ether_tree()
{
	GtkWidget *subtree;
	gint i = 0;

	item[1] = gtk_tree_item_new_with_label(ether_buf.title);
	gtk_tree_append(GTK_TREE(tree),item[1]);
	subtree = gtk_tree_new();

	gtk_tree_set_selection_mode (GTK_TREE(subtree),GTK_SELECTION_SINGLE);
	gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);   
	gtk_tree_item_set_subtree (GTK_TREE_ITEM(item[1]), subtree);      

	GtkWidget *subitem;                                           
	subitem = gtk_tree_item_new_with_label (ether_buf.dst_mac);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ether_buf.src_mac);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ether_buf.protocol);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	gtk_widget_show (item[1]);
}

void append_arp_tree()
{
	GtkWidget *subtree;
	item[2] = gtk_tree_item_new_with_label(arp_buf.title);
	gtk_tree_append(GTK_TREE(tree),item[2]);
	subtree = gtk_tree_new();

	gtk_tree_set_selection_mode (GTK_TREE(subtree),GTK_SELECTION_SINGLE);
	gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);   
	gtk_tree_item_set_subtree (GTK_TREE_ITEM(item[2]), subtree);      

	GtkWidget *subitem;                                           
	subitem = gtk_tree_item_new_with_label (arp_buf.ar_hrd);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	subitem = gtk_tree_item_new_with_label (arp_buf.ar_pro);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	subitem = gtk_tree_item_new_with_label (arp_buf.ar_hln);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	subitem = gtk_tree_item_new_with_label (arp_buf.ar_pln);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	subitem = gtk_tree_item_new_with_label (arp_buf.ar_op); 
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	subitem = gtk_tree_item_new_with_label (arp_buf.src_mac); 
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	subitem = gtk_tree_item_new_with_label (arp_buf.src_ip); 
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	subitem = gtk_tree_item_new_with_label (arp_buf.dst_mac); 
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	subitem = gtk_tree_item_new_with_label (arp_buf.dst_ip); 
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);

	gtk_widget_show (item[2]);
}

void append_ip_tree()
{
	GtkWidget *subtree;
	gint i = 0;

	item[2] = gtk_tree_item_new_with_label(ip_buf.title);
	gtk_tree_append(GTK_TREE(tree),item[2]);
	subtree = gtk_tree_new();

	gtk_tree_set_selection_mode (GTK_TREE(subtree),GTK_SELECTION_SINGLE);
	gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);   
	gtk_tree_item_set_subtree (GTK_TREE_ITEM(item[2]), subtree);      

	GtkWidget *subitem;                                           
	subitem = gtk_tree_item_new_with_label (ip_buf.version);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.headlen);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.tos);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.tot_len);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.id);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.df);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.mf);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.offset);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.ttl);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.checksum);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.protocol);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.src_ip);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (ip_buf.dst_ip);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	gtk_widget_show (item[2]);
}

void append_tcp_tree()
{
	GtkWidget *subtree;
	gint i = 0;

	item[3] = gtk_tree_item_new_with_label(tcp_buf.title);
	gtk_tree_append(GTK_TREE(tree),item[3]);
	subtree = gtk_tree_new();

	gtk_tree_set_selection_mode (GTK_TREE(subtree),GTK_SELECTION_SINGLE);
	gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);   
	gtk_tree_item_set_subtree (GTK_TREE_ITEM(item[3]), subtree);      

	GtkWidget *subitem;                                           
	subitem = gtk_tree_item_new_with_label (tcp_buf.source);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.dest);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.seq);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.ack_seq);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.tcp_len);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.urg);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.ack);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.psh);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.rst);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.syn);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.fin);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.win);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (tcp_buf.check);
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	gtk_widget_show (item[3]);
}

void append_udp_tree()
{
	GtkWidget *subtree;
	gint i = 0;

	item[3] = gtk_tree_item_new_with_label(udp_buf.title);
	gtk_tree_append(GTK_TREE(tree),item[3]);
	subtree = gtk_tree_new();

	gtk_tree_set_selection_mode (GTK_TREE(subtree),GTK_SELECTION_SINGLE);
	gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);   
	gtk_tree_item_set_subtree (GTK_TREE_ITEM(item[3]), subtree);      

	GtkWidget *subitem;                                           
	subitem = gtk_tree_item_new_with_label (udp_buf.source);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (udp_buf.dest);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (udp_buf.length);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  

	subitem = gtk_tree_item_new_with_label (udp_buf.check);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);  
	gtk_widget_show (item[3]);
}

void append_data_tree()
{
	GtkWidget *subtree;
	item[4] = gtk_tree_item_new_with_label(data_buf.title);
	gtk_tree_append(GTK_TREE(tree),item[4]);
	subtree = gtk_tree_new();

	gtk_tree_set_selection_mode (GTK_TREE(subtree),GTK_SELECTION_SINGLE);
	gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);   
	gtk_tree_item_set_subtree (GTK_TREE_ITEM(item[4]), subtree);      

	GtkWidget *subitem;                                           
	subitem = gtk_tree_item_new_with_label (data_buf.data);           
	gtk_tree_append (GTK_TREE(subtree), subitem);                 
	gtk_widget_show (subitem);                                    
	gtk_widget_show (item[4]);
}

void selection_made( GtkWidget *clist,
		gint row,
		gint column,
		GdkEventButton *event,
		gpointer data )
{
	gchar *text;
	gint i = 0;
	/* 取得存储在被选中的行和列的单元格上的文本
	 * 当鼠标点击时,我们用text参数接收一个指针
	 */
	gtk_clist_get_text(GTK_CLIST(clist), row, column, &text);
#if 0
	/*打印一些关于选中了哪一行的信息 */
	g_print("You selected row %d. More specifically you clicked in "
			"column %d, and the text in this cell is %s\n\n",
			row, column, text);
#endif

	//tree = gtk_tree_new();

	for (i = 0;i < 5;i++)
	{
		if (item[i]) {
			gtk_tree_item_remove_subtree((GtkTreeItem *)item[i]);
			gtk_container_remove (GTK_CONTAINER(tree), item[i]);
			item[i] = NULL;
		}
	}

#if 0
	tree = gtk_tree_new();
	gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW(scrolled_win),tree);
	gtk_tree_set_selection_mode (GTK_TREE(tree),GTK_SELECTION_MULTIPLE);    
#endif

	read_record(row);
	pcap_parser((uint8_t *)pcap_packet_buf,&pcaphdr);

	append_frame_tree();
	append_ether_tree();

	switch (proto_type)
	{
		case IPPROTO_TCP:
			{
				append_ip_tree();
				append_tcp_tree();
				if (app_len != 0)
				{
					append_data_tree();
					app_len = 0;
				}
			}
			break;
		case IPPROTO_UDP:
			{
				append_ip_tree();
				append_udp_tree();
				if (app_len != 0)
				{
					append_data_tree();
					app_len = 0;
				}
			}
			break;
		case ARP:
			{
				append_arp_tree();
			}
			break;
		default:
			break;
	}
	display_contents();

	return;
}
