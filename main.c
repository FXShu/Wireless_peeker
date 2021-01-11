#include "wireless_peek.h"
#include "common.h"
#include "crypto.h"
#include "l2_packet.h"

#include "./src/interaction/peek_ctrl.h"

int debug_level;

void usage(){
	printf("MITM usage:\n"
		"MITM -i<interface name> -t<device_type> [-d<debug level>]...\n"
		"  -h = show this help\n"
		"  -d <level> = increase debugging verbosity\n"
		"  -i = interface name\n"
		"  -t <device_type(wireless/ethernet)> set the device type\n");
}

static void mitm_eloop_terminate(int sig, void *signal_ctx) {
	eloop_terminate();
}

int main(int argc, char **argv){

	struct wireless_peek this;

	char packet_path[64];
	char main_iface[64];
	char dictionary_path[64];
	int c;
	struct mitm_ctrl *ctrl;

	for(;;){
		c=getopt(argc, argv,"i:hd:w:p:");
		if(c < 0)break;
		switch(c){
		case 'd':
			debug_level = atoi(optarg);
		break;
		case 'h':
			usage();
			return 0;
		break;
		case 'i':
			strncpy(main_iface, optarg, 64);
		break;
		case 'w':
			strncpy(packet_path, optarg, 64);
		break;
		case 'p':
			strncpy(dictionary_path, optarg, 64);
		break;
		default:
	       		usage();
			return 0;
		}
	}
	eloop_init();

	memset(&this, 0, sizeof(struct wireless_peek));
	if (wireless_peek_init(&this, main_iface, dictionary_path, packet_path))
		goto exit;
	eloop_run();
exit:
	wireless_peek_deinit(&this);
	return -1;
}
