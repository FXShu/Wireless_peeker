#include "MITM_cli.h"

#ifndef MITM_CTRL_DIR
#define MITM_CTRL_DIR "/tmp/MITM"
#endif /* MITM_CTRL_DIR */

#ifndef MITM_CLI_DIR
#define MITM_CLI_DIR "/tmp/MITM"
#endif /* MITM_CLI_DIR */

#define SIGSTATE 100 /*This signal is triggered when MITM state change. */

int debug_level;

static void mitm_client_terminate(int sig, void *signal_ctx) {
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *)signal_ctx;
	struct mitm_ctrl fuckyou;
	eloop_terminate();
	unlink(ctrl->local.sun_path);
	free(ctrl);
	log_printf(MSG_INFO, "thanks for using mitm_cli");
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

//	int interval = *(int *)user_ctx;
	char reply[COMMAND_BUFFER_LEN];
	size_t len = COMMAND_BUFFER_LEN;
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *)eloop_data; 
	mitm_ctrl_request(ctrl, MITM_KEEP_ALIVE_REQUSET, sizeof(MITM_KEEP_ALIVE_REQUSET),
			reply, &len, NULL);

	log_printf(MSG_DEBUG, "get a command:%s", reply);

	if (!strncmp(reply, MITM_KEEP_ALIVE_REPLY, sizeof(MITM_KEEP_ALIVE_REPLY))) {
		log_printf(MSG_DEBUG, "[keep alive]get the server answer");
		eloop_register_timeout(5, 0, register_keep_alive, ctrl, NULL);
		return;
	}
	else {
		/* mitm_reconnet(); */
		log_printf(MSG_INFO, "Disconnect with MITM binary\n");
		eloop_register_timeout(5, 0, register_keep_alive, ctrl, NULL);
	}
	return;

}

static void hello() {
	log_printf(MSG_INFO, 
			"-----------------------------------------------------------------------\n"
			"| Welcome to MITM Comman Line.                                        |\n"
			"| This program is used to show how the Man-IN-THE-MIDDLE work.        |\n"
			"| Please notice that if you execute this process                      |\n"
			"| to peer otherone's network taffic is illegal.                       |\n"
			"----------------------------------------------------------------------");
}

static void get_ap_list(struct mitm_ctrl *ctrl) {
	char reply[COMMAND_BUFFER_LEN];
	size_t len = COMMAND_BUFFER_LEN;
	log_printf(MSG_DEBUG, "send get_ap_list request to server");
	mitm_ctrl_request(ctrl, MITM_GET_AP_LIST_REQUEST, sizeof(MITM_GET_AP_LIST_REQUEST),
			reply, &len, NULL);
	return;
}

void handle_user_input(int sock, void *eloop_ctx, void *sock_ctx) {
	char buffer[BUFFER_LEN];
	memset(buffer, 0, BUFFER_LEN);
	struct mitm_ctrl *ctrl = (struct mitm_ctrl *)sock_ctx;
	fgets(buffer, BUFFER_LEN, stdin);
	log_printf(MSG_DEBUG, "contect of buffer is %s", buffer);
	if (!strcmp(buffer, "10\n")) {
		get_ap_list(ctrl);
	}
}

void print_options(int sig, void *signal_ctx) {
	struct MITM_info *info = (struct MITM_info *)signal_ctx;
	log_printf(MSG_INFO, "MITM state in %s state, please choose below action.");
	for (int i = 0; i < mitm_get_action_num(); i++) {
		if (msg_handler[i].header < info->state && msg_handler[i].tail > info->state) {
			log_printf(MSG_INFO, "[%d]%s", msg_handler[i].number, 
					msg_handler[i].prompt);
		}
	}
}

int main(int argc, char **argv) {
	int c;
	struct mitm_ctrl *ctrl;
	char *mitm_ctrl_path;
	int ask_mitm_state_interval = 1;
	/* used to communicate with UI(web, cli...) */
	char *ctrl_ifname = NULL;
	/* if true, use terminal to control MITM binary */
	struct MITM_info info;
	for (;;) {
		c = getopt(argc, argv, "hp:G:i:d:");
		if (c < 0) break;
		switch(c) {
		case 'h':
			usage();
			return 0;
		case 'p':
			mitm_ctrl_path = strdup(optarg);
			break;
		case 'i':
			ctrl_ifname = strdup(optarg);
			break;
		case 'd':
			debug_level = atoi(optarg);
			break;
		default:
			usage();
			return 0;
		}
	}

	if (eloop_init())  
		return -1;

	ctrl = mitm_ctrl_open2((MITM_CTRL_PATH), MITM_CLI_DIR, &info);
	if (!ctrl) { 
		log_printf(MSG_ERROR, "init control interface client failed");
		return -ENOMEM;
	}
	
	RESET_CURSOR();
	CLEAR_SCREEN();
	hello();
	eloop_register_signal(SIGSTATE, print_optins, &info);
//	eloop_register_timeout(ask_mitm_state_interval, 0, get_mitm_state, 
//			ctrl, &ask_mitm_state_interval);
	eloop_register_signal_terminate(mitm_client_terminate, ctrl);
	eloop_register_read_sock(0, handle_user_input, NULL, ctrl);
	eloop_run();			
}
