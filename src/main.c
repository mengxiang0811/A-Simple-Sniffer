#define GTK_ENABLE_BROKEN

#include <gnome.h>
#include <sys/time.h>

#include "menu_func.h"
#include "capture.h"
#include "disp_data.h"

int indx;

struct timeval capture_start_time;
int capture_pre_packet = 0;

int ifnum = 0;

int capture_state = 0;

int tot_packet = 0;
int ip_packet = 0;
int tcp_packet = 0;
int udp_packet = 0;
int arp_packet = 0;
int icmp_packet = 0;
int igmp_packet = 0;

char filter_str[FILTER_LEN];
char filter_str2[FILTER_LEN];
char ifname[50];

struct interface_item ifitem[24];
struct disp_record frame_item[MAX_ITEM];

char pcap_packet_buf[BUFSIZE];
struct pcap_pkthdr pcaphdr;
uint32_t rec_id;
uint16_t proto_type;
struct disp_frame frame_buf;
struct disp_ether ether_buf;
struct disp_ip ip_buf;
struct disp_tcp tcp_buf;
struct disp_udp udp_buf;
struct disp_data data_buf;
struct disp_arp arp_buf;
int packet_size;
int app_len;

pthread_mutex_t capture_state_mtx;
pthread_mutex_t frame_item_mtx;
pthread_mutex_t packet_stat_mtx;
pthread_mutex_t handle_mtx;

pcap_t *pcap_handle;
pcap_if_t *alldevs;
pcap_if_t *dev;
char pcap_errbuf[PCAP_ERRBUF_SIZE];

uint32_t offset = 0;

gchar *header[5] = { "Frame", "Ethernet", "IP", "TCP", "UDP" };
gchar *titles[8] = { "No.", "Time", "SrcMac", "DstMac", "Source", "Destination", "Protocol", "Length" };
gchar *str = "hello world.This is a table test program!Network attack and protection";

FILE *out = NULL;
FILE *rec_out = NULL;

FILE *rec_in = NULL;
FILE *in = NULL;

GtkWidget *app;

GtkWidget *filter_label;
GtkWidget *filter_entry;
GtkWidget *filter_button;

GtkWidget *vbox;
GtkWidget *hbox;
GtkWidget *text_hbox;
GtkWidget *vpaned;
GtkWidget *subvpaned;

GtkWidget *clist;
GtkWidget *record_scrolled_window;

GtkWidget *tree;
GtkWidget *item[5];
GtkWidget *scrolled_win;

GtkWidget *table;
GtkWidget *hex_text;
GtkWidget *char_text;
GtkWidget *info_scrolled_window;

GdkFont *fixed_font;

const char pfh[24] = {
	0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

pthread_t capture_thread;
pthread_t refresh_thread;

GnomeUIInfo capture_menu[] = {
	GNOMEUIINFO_ITEM_NONE( "Start", "Capture start", capture_start ),
	GNOMEUIINFO_ITEM_NONE( "Stop", "Capture stop", capture_stop ),
	GNOMEUIINFO_ITEM_NONE( "Exit", "Application exit", program_exit ),
	GNOMEUIINFO_END
};

GnomeUIInfo option_message_menu[] = {
	{ GNOME_APP_UI_ITEM, "Interface", "Menu Hint", GTK_SIGNAL_FUNC(ifselect), NULL, NULL, 0, NULL, 0, 0, NULL },
	{ GNOME_APP_UI_ITEM, "Capture Filters", "Menu Hint", GTK_SIGNAL_FUNC(capture_filter), NULL, NULL, 0, NULL, 0, 0, NULL },
	GNOMEUIINFO_END
};

GnomeUIInfo statistics_message_menu[] = {
	{ GNOME_APP_UI_ITEM, "Statistics", "Menu Hint", GTK_SIGNAL_FUNC(display_statistics), NULL, NULL, 0, NULL, 0, 0, NULL },
	GNOMEUIINFO_END
};

GnomeUIInfo help_menu[]={
	{ GNOME_APP_UI_ITEM, "About", "Menu Hint", GTK_SIGNAL_FUNC(about), NULL, NULL, 0, NULL, 0, 0, NULL },
	GNOMEUIINFO_END
};

/*生成顶层菜单*/
GnomeUIInfo menubar[]={
	GNOMEUIINFO_SUBTREE( "Capture", capture_menu ),
	GNOMEUIINFO_SUBTREE( "Options", option_message_menu ),
	GNOMEUIINFO_SUBTREE( "Statistics", statistics_message_menu ),
	GNOMEUIINFO_SUBTREE( "Help", help_menu ),
	GNOMEUIINFO_END
};

void init_once()
{
	GtkWidget *isenable;

	pthread_mutex_init(&capture_state_mtx,NULL);
	pthread_mutex_init(&frame_item_mtx,NULL);
	pthread_mutex_init(&packet_stat_mtx,NULL);
	pthread_mutex_init(&handle_mtx,NULL);

	isenable = capture_menu[1].widget;
	gtk_widget_set_sensitive(isenable,FALSE);
}

int main(int argc,char *argv[])
{
	gint i = 0;
#if 0
	gchar *packet[2][8] = {
		{ "1","0.000000","0a:eb:9f:aa:bb:cc","ff:ff:ff:ff:ff:ff","10.24.0.9","10.24.0.255","NBNS","92" },
		{ "2","0.408651","00:16:96:14:74:eb","00:16:96:14:74:eb","10.24.0.3","255.255.255.255","UDP","63" },
	};
#endif



	init_file();
	gtk_set_locale();
	gnome_init("Simple Sniffer","1.0",argc,argv);

	app = gnome_app_new("Simple Sniffer","Linux 嗅探器");
	gtk_signal_connect(GTK_OBJECT(app),"delete_event",GTK_SIGNAL_FUNC(gtk_main_quit),NULL);

	gnome_app_create_menus(GNOME_APP(app),menubar);
	gtk_window_set_default_size((GtkWindow *)app,1000,500);

	init_once();
	init_pcap();

	vbox = gtk_vbox_new(FALSE,0);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
	gnome_app_set_contents(GNOME_APP(app),vbox);

	filter_label = gtk_label_new("FilterString: ");
	filter_entry = gtk_entry_new();
	filter_button = gtk_button_new_with_label("Filter");

	hbox = gtk_hbox_new(FALSE,0);
	gtk_box_pack_start(GTK_BOX(vbox),hbox,FALSE,FALSE,5);
	gtk_box_pack_start(GTK_BOX(hbox),filter_label,FALSE,FALSE,5);
	gtk_box_pack_start(GTK_BOX(hbox),filter_entry,TRUE,TRUE,6);
	gtk_box_pack_start(GTK_BOX(hbox),filter_button,FALSE,FALSE,5);

	vpaned = gtk_vpaned_new ();
	subvpaned = gtk_vpaned_new ();

	//gtk_paned_set_handle_size(GTK_PANED(vpaned),10);
	gtk_paned_set_gutter_size(GTK_PANED(vpaned),30);
	gtk_paned_set_gutter_size(GTK_PANED(subvpaned),15);


	record_scrolled_window = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (record_scrolled_window),
			GTK_POLICY_AUTOMATIC,
			GTK_POLICY_ALWAYS);
	clist = gtk_clist_new_with_titles( 8, titles);
	gtk_clist_set_shadow_type (GTK_CLIST(clist), GTK_SHADOW_OUT);

	gtk_signal_connect(GTK_OBJECT(clist), "select_row", GTK_SIGNAL_FUNC(selection_made), NULL);

	gtk_clist_set_column_width (GTK_CLIST(clist), 0, 50);
	gtk_clist_set_column_width (GTK_CLIST(clist), 1, 100);
	gtk_clist_set_column_width (GTK_CLIST(clist), 2, 100);
	gtk_clist_set_column_width (GTK_CLIST(clist), 3, 100);
	gtk_clist_set_column_width (GTK_CLIST(clist), 4, 100);
	gtk_clist_set_column_width (GTK_CLIST(clist), 5, 100);
	gtk_clist_set_column_width (GTK_CLIST(clist), 6, 100);
	gtk_clist_set_column_width (GTK_CLIST(clist), 7, 50);

#if 0
	table = gtk_table_new (1, 2, TRUE);
	gtk_table_set_row_spacing(GTK_TABLE (table), 0, 2);
	gtk_table_set_col_spacing(GTK_TABLE (table), 0, 2);
#endif

	hex_text = gtk_text_new(NULL,NULL);
	gtk_text_set_editable(GTK_TEXT(hex_text),FALSE);
	gtk_text_set_word_wrap(GTK_TEXT(hex_text),TRUE);
	//gtk_table_attach(GTK_TABLE(table),hex_text,0,1,0,1,GTK_EXPAND|GTK_SHRINK|GTK_FILL,GTK_EXPAND|GTK_SHRINK|GTK_FILL,0,0);

	char_text = gtk_text_new(NULL,NULL);
	gtk_text_set_editable(GTK_TEXT(char_text),FALSE);
	gtk_text_set_word_wrap(GTK_TEXT(char_text),TRUE);
	//gtk_table_attach(GTK_TABLE(table),char_text,1,2,0,1,GTK_EXPAND|GTK_SHRINK|GTK_FILL,GTK_EXPAND|GTK_SHRINK|GTK_FILL,0,0);

	text_hbox = gtk_hbox_new(FALSE,0);
	gtk_box_pack_start(GTK_BOX(text_hbox),hex_text,TRUE,TRUE,5);
	gtk_box_pack_start(GTK_BOX(text_hbox),char_text,TRUE,TRUE,5);

#if 1
	info_scrolled_window = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (info_scrolled_window),
			GTK_POLICY_AUTOMATIC,
			GTK_POLICY_ALWAYS);
	gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW(info_scrolled_window),text_hbox);
	gtk_widget_show(info_scrolled_window);
#endif
	//gtk_table_attach(GTK_TABLE(table),info_scrolled_window,2,3,0,1,GTK_FILL,GTK_EXPAND|GTK_SHRINK|GTK_FILL,0,0);
	//gtk_widget_realize(hex_text);

	//gtk_container_add(GTK_CONTAINER(info_scrolled_window), table);

#if 0
	GtkWidget *tmptext;
	tmptext = gtk_text_new(NULL,NULL);
	gtk_text_set_editable(GTK_TEXT(tmptext),FALSE);
	gtk_text_set_word_wrap(GTK_TEXT(tmptext),TRUE);
	gtk_paned_add1(GTK_PANED(subvpaned),tmptext);
#endif

	scrolled_win = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_win),
			GTK_POLICY_AUTOMATIC,
			GTK_POLICY_AUTOMATIC);
	tree = gtk_tree_new();
	gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW(scrolled_win),tree);
	gtk_tree_set_selection_mode (GTK_TREE(tree),GTK_SELECTION_MULTIPLE);

	for (i = 0; i < 5; i++)
	{
		item[i] = NULL;
	}
#if 0
	for (i = 0; i < 5; i++)
	{
		GtkWidget *subtree;
		gint j;
		item[i] = gtk_tree_item_new_with_label (header[i]);
		gtk_tree_append (GTK_TREE(tree), item[i]);
		subtree = gtk_tree_new();

		//g_print ("-> item %s->%p, subtree %p\n", header[i], item,subtree);

		gtk_tree_set_selection_mode (GTK_TREE(subtree),GTK_SELECTION_SINGLE);
		gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);
		gtk_tree_item_set_subtree (GTK_TREE_ITEM(item[i]), subtree);

		for (j = 0; j < 5; j++){
			GtkWidget *subitem;
			subitem = gtk_tree_item_new_with_label (header[j]);
			//g_print ("-> -> item %s->%p\n", header[j], subitem);
			gtk_tree_append (GTK_TREE(subtree), subitem);
			gtk_widget_show (subitem);
		}
	}
#endif

	gtk_paned_add1(GTK_PANED(subvpaned),scrolled_win);
	gtk_paned_add2(GTK_PANED(subvpaned),info_scrolled_window);

	gtk_container_add(GTK_CONTAINER(record_scrolled_window), clist);

	gtk_paned_add1(GTK_PANED(vpaned),record_scrolled_window);
	gtk_paned_add2(GTK_PANED(vpaned),subvpaned);

	gtk_box_pack_start(GTK_BOX(vbox),vpaned,TRUE,TRUE,5);

	pthread_create(&capture_thread,NULL,capture,NULL);
	pthread_create(&refresh_thread,NULL,clist_refresh,NULL);

	g_signal_connect(GTK_OBJECT(app),"destroy",GTK_SIGNAL_FUNC(gtk_main_quit),NULL);

	gtk_widget_realize(hex_text);
	gtk_widget_realize(char_text);

	gtk_widget_show_all(app);
	gtk_main();

	pthread_join(capture_thread,NULL);
	pthread_join(refresh_thread,NULL);

	return 0;
}
