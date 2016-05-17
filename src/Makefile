main:
	gcc -o main global.h disp_data.h pcap_manager.h pcap_manager.c capture.h capture.c menu_func.h menu_func.c main.c `pkg-config --cflags --libs gtk+-2.0 libgnome-2.0 libgnomeui-2.0` -lpthread -lpcap -g
clean:
	@rm main
