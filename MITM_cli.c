#include "./src/utils/common.h"
#include "MITM_cli.h"

struct mitm_ctrl *ctrl;

static int mitm_client_connect(const char *ctrl_path, const char *cli_path) {
	ctrl = mitm_ctrl_open2(ctrl_path, cli_path);
	if (!ctrl) return -1;
	return 0;
}

static int mitm_client_reconnect() {

}

static void register_command_sock(){
	
}

static void usage(void) {
	log_printf(MSG_INFO, "mitm_ctrl v1.0\n"
		       	     "usage: mitm_ctrl [-p<path>] [-G<keep alive interval>]\n")
}

static void register_keep_alive(void *eloop_data, void *user_ctx) {
	char reply[COMMAND_BUFFER_LEN];

//	struct MITM_MSG *msg = (struct MITM_MSG *)user_ctx; 
	mitm_ctrl_request(ctrl, MITM_KEEP_ALIVE_REQUSET, sizeof(MITM_KEEP_ALIVE_REQUSET),
			reply, COMMAND_BUFFER_LEN, NULL);

	if (!strncmp(reply, MITM_KEEP_ALIVE_REPLY, sizeof(MITM_KEEP_ALIVE_REPLY))) 
		return;
	else
		/* mitm_reconnet(); */

}
int main(int argc, char **argv) {
	char c;

	int keep_alive_interval;

	ctrl = malloc(sizeof(struct mitm_ctrl));

	for (;;) {
		c = getopt(argc, argv, "hp:G:");
		if (c < 0) break;
		switch(c) {
		case h:
			usage();
			return 0;
			break;
		case p:
			ctrl->dest = optarg;
			break;
		case G:
			keep_alive_interval = atoi(optarg);
			break;
		}
	}

	eloop_init();
	eloop_register_timeout(keep_alive_interval, 0, register_keep_alive, NULL, NULL);
	eloop_run();
	int sockfd;
}
