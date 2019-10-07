#include "MITM_cli.h"

#define MITM_CTRL_DIR "/tmp/MITM/"
#define MITM_CLI_DIR ""

int debug_level;

static void mitm_client_terminate(int sig, void *signal_ctx) {
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *)signal_ctx;
	eloop_terminate();
	free(ctrl);
	log_printf(MSG_INFO, "thanks for using mitm_cli");
}
static int mitm_client_connect(const char *ctrl_path, const char *cli_path) {
	struct mitm_ctrl *ctrl = mitm_ctrl_open2(ctrl_path, cli_path);
	if (!ctrl) return -1;
	return 0;
}

static int mitm_client_reconnect() {

}

static void register_command_sock(){
	
}

static void usage(void) {
	log_printf(MSG_INFO, "mitm_ctrl v1.0\n"
		       	     "usage: mitm_ctrl [-p<path>] [-G<keep alive interval>]\n");
}

static void register_keep_alive(void *eloop_data, void *user_ctx) {
	char reply[COMMAND_BUFFER_LEN];

	struct mitm_ctrl *ctrl = (struct mitm_ctrl *)user_ctx; 
	mitm_ctrl_request(ctrl, MITM_KEEP_ALIVE_REQUSET, sizeof(MITM_KEEP_ALIVE_REQUSET),
			reply, COMMAND_BUFFER_LEN, NULL);

	if (!strncmp(reply, MITM_KEEP_ALIVE_REPLY, sizeof(MITM_KEEP_ALIVE_REPLY))) 
		return;
	else {
		/* mitm_reconnet(); */
		log_printf(MSG_INFO, "Disconnect with MITM binary\n");
	}

}
int main(int argc, char **argv) {
	char c;

	struct mitm_ctrl *ctrl;
	char *mitm_ctrl_path;
	int keep_alive_interval;
	/* used to communicate with UI(web, cli...) */
	char *ctrl_ifname = NULL;
	/* if true, use terminal to control MITM binary */
	int interaction;


	for (;;) {
		c = getopt(argc, argv, "hp:G:i:");
		if (c < 0) break;
		switch(c) {
		case 'h':
			usage();
			return 0;
			break;
		case 'p':
			mitm_ctrl_path = strdup(optarg);
			break;
		case 'G':
			keep_alive_interval = atoi(optarg);
			break;
		case 'i':
			ctrl_ifname = strdup(optarg);
			break;
		}
	}

	interaction = (!ctrl_ifname);

	if (eloop_init())  
		return -1;

	ctrl = mitm_ctrl_open2((mitm_ctrl_path ? mitm_ctrl_path : MITM_CTRL_DIR), MITM_CLI_DIR);
	if (ctrl) 
		return -ENOMEM;
	eloop_register_timeout(keep_alive_interval, 0, register_keep_alive, NULL, NULL);
	eloop_register_signal_terminate(mitm_client_terminate, ctrl);
	eloop_run();
/*	for(;;) {
			
	}*/
}
