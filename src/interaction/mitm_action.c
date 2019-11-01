#include "mitm_action.h"

static char ** parse_command(char *line, int *count) {
	       char **options;
        if (!line)
                return NULL;
        char *option = strchr(line, '?');
        if (!option)
                return NULL;
        else {
                option = option + 1;
                char delim = '&';
                int i = 0;
                options = malloc(sizeof(char*));
                for(char *tmp = strtok(option, &delim); tmp; tmp = strtok(NULL, &delim)) {
                        options = realloc(options,i+1 * sizeof(char *));
                        options[i] = malloc(sizeof(tmp));
                        strcpy(options[i], tmp);
                        printf("%s\n", options[i]);
                        i++;
                }
                *count = i;
        }
        return options;
}

static int MITM_read_ap_search(struct MITM* MITM) {
	MITM->state = MITM_state_ap_search;
}

void mitm_ctrl_connect_request_action (void *action_data, void *usr_data, char *options) {}

void mitm_ctrl_connect_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_ctrl_disconnect_request_action (void *action_data, void *usr_data, char *options) {}

void mitm_ctrl_disconnect_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_get_ap_list_request_action (void *action_data, void *usr_data, char *options) {
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *)action_data;
	struct MITM *MITM = (struct MITM *)usr_data;

	char ap_list[1024];
	int ret;
	struct access_point_info *tmp;
	
	sprintf(ap_list, MITM_GET_AP_LIST_REPLY);
	strcpy(ap_list, strdup("ap_list"));
	dl_list_for_each(tmp, &MITM->ap_list, struct access_point_info, ap_node) {
		char buf[50];
		sprintf(buf, "{\"SSID\":\"%s\",\"BSSID\":\"" MACSTR "\"},", tmp->SSID,
			       	MAC2STR(tmp->BSSID));
		strncat(ap_list, buf, strlen(buf));
	}
	char *ch = strrchr(ap_list, ',');
	if (ch) 
		*ch = ']';

	printf("%s\n", ap_list);
	ret = sendto(recv_info->sock_fd, ap_list, strlen(ap_list), recv_info->send_flags,
		       	(const struct sockaddr *)&recv_info->recv_from, recv_info->length);
	if (ret < 0) 
		log_printf(MSG_WARNING, "[%s] sendto failed, err:%s", __func__, strerror(errno));
}

void mitm_get_ap_list_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_set_victim_request_action (void *action_data, void *usr_data, char *options) {}

void mitm_set_victim_reply_action (void *action_data, void *usr_data, char *options) {}

// The request command should like `MITM-SET-AP-REQUEST?state=ap_search`.
void mitm_set_status_request_action (void *action_data, void *usr_data, char *line) {
	struct mitm_recv_info *recv_info = (struct mtim_recv_info *)action_data;
	struct MITM *MITM = (struct MITM*)usr_data;
	int number_of_command;
	int index, ret;
	char **options = parse_command(line, &number_of_command);
	for(index = 0; index < number_of_command; index++) {
		if(!strncmp(options[index],"state", sizeof("state")))
			break;
	}
	if (index == number_of_command) 
		goto state_request_reject;
	char *state = strrchr(options[index], '=');
	if (!state) 
		goto state_request_reject;
	state = state + 1;
	switch(MITM->state) {
	case MITM_state_idle:
		if (!strcmp(state, "ap_search")) {
			MITM_read_ap_search(MITM);
		} else if(!strcmp(state, "sniffer") && (MITM->dev_type == ethernet)){
			MITM->state = MITM_state_sniffer;
		} else {
			log_printf(MSG_WARNING, "Unexpected state %s in idle state", state);
			goto state_request_reject;
		}
		break;
	case MITM_state_ap_search:
		if (strcmp(state, "crash_password")) {
			log_printf(MSG_WARNING, "Unexpected state %s in ap search state", state);
			goto state_request_reject;
		}
		MITM->state = MITM_state_crash_password;
		break;
	case MITM_state_ready:
		if (!strcmp(state, "sniffer")) {
			MITM->state = MITM_state_sniffer;
		} else {
			log_printf(MSG_WARNING, "Unexpected state %s in ready state", state);
		}
	case MITM_state_sniffer:
		if (strcmp(state, "crash_PTK")) {
			log_printf(MSG_WARNING, "Unexpected state %s in sniffer state", state);
			goto state_request_reject;
		}
		MITM->state = MITM_state_crash_PTK;
		break;
	case MITM_state_crash_PTK:
		if (strcmp(state, "spoofing")) {
			log_printf(MSG_WARNING, "Unexpected state %s in crash state", state);
			goto state_request_reject;
		}
		MITM->state = MITM_state_spoofing;
		break;
	case MITM_state_spoofing:
		if (!strcmp(state, "ap_search")) {
			MITM->state = MITM_state_ap_search;
		} else if (!strcmp(state, "idle")) {
			MITM->state = MITM_state_idle;
		} else {
			log_printf(MSG_WARNING, "Unexpected state %s in spoof state", state);
			goto state_request_reject;
		}
		break;
	}
	for (int i = 0; i < number_of_command; i++)
		free(options[i]);
	free(options);

	ret = sendto(recv_info->sock_fd, MITM_SET_STATUS_REPLY, sizeof(MITM_SET_STATUS_REPLY), 
			recv_info->send_flags, (const struct sockaddr *)&recv_info->recv_from,
			recv_info->length);
	if (ret < 0) {
		log_printf(MSG_WARNING, "[CTRL] sendto failed, err:%s", strerror(errno));
	}
	return;
state_request_reject:
	for (int i = 0; i < number_of_command; i++)
		free(options[i]);
	free(options);
	log_printf(MSG_WARNING, "[CTRL]state change request reject, unsupport format");
}

void mitm_set_status_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_set_ap_request_action (void *action_data, void *usr_data, char *line) {
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *)action_data;
	struct MITM *MITM = (struct MITM*) usr_data;
	int index, ret, match = 0, number_of_options;
	char **options = parse_command(line, &number_of_options);
	for (index = 0; index < number_of_options; index++) {
		if (!strncmp(options[index], "ap", sizeof("ap"))) {
			break;
		}
	}
	if (index == number_of_options) 
		goto ap_request_reject;
	char *ap_SSID = strrchr(options[index], '=');
	if (!ap_SSID)
		goto ap_request_reject;
	ap_SSID = ap_SSID + 1;
	struct access_point_info *tmp;
	dl_list_for_each(tmp, &MITM->ap_list, struct access_point_info, ap_node) {
		if(!strcmp(tmp->SSID, ap_SSID)) {
			for (int i = 0; i < ETH_ALEN; i++) {
				MITM->dev_info.ap_BSSID[i] = tmp->BSSID[i];
				MITM->state = MITM_state_crash_password;
				match = 1;
			}
			break;
		} 
	}
	char *feedback = match ? MITM_COMMAND_OK : "Secpify AP not found";
	/* if the request command is right ,is it necessary to send the feedback? */
	ret = sendto(recv_info->sock_fd, feedback, sizeof(feedback), recv_info->send_flags, 
			(const struct sockaddr *)&recv_info->recv_from, recv_info->length);
	if (ret < 0)
		log_printf(MSG_WARNING, "[CTRL]sendto caller failed, err:%s", strerror(errno));
	for (index = 0; index < number_of_options; index++) {
		free(options[index]);
	}
	free(options);
ap_request_reject:
	for (index = 0; index < number_of_options; index++) {
		free(options[index]);
	}
	free(options);
	log_printf(MSG_WARNING, "[CTRL]ap set request reject, unsupport format");
	/* Should I send something feedback to let caller know the format is wrong? */
}

void mitm_get_status_request_action (void *action_data, void *usr_data, char *options) {}

void mitm_get_status_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_status_change_action (void *action_data, void *usr_data, char *options) {}

void mitm_start_attack_request_action (void *action_data, void *usr_data, char *options) {}

void mitm_start_attack_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_keep_alive_request_action (void *action_data, void *usr_data, char *options) {
	int ret;
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *)action_data;
	log_printf(MSG_DEBUG, "[%s]:get a keep alive request from client", __func__);
	recv_info->send_flags = 0;
	ret = sendto(recv_info->sock_fd, MITM_KEEP_ALIVE_REPLY, sizeof(MITM_KEEP_ALIVE_REPLY), 
			recv_info->send_flags, (const struct sockaddr *)&recv_info->recv_from,
		       	recv_info->length);
	if (ret < 0) {
		log_printf(MSG_WARNING, "[%s] sendto failed, err:%s", __func__, strerror(errno));
	}
}

void mitm_keep_alive_reply_action (void *action_data, void *usr_data, char *options) {
	log_printf(MSG_DEBUG, "[keep alive] server return keep alive packet");
}
