#include "mitm_action.h"

void mitm_ctrl_connect_request_action (void *action_data, void *usr_data) {}
void mitm_ctrl_connect_reply_action (void *action_data, void *usr_data) {}
void mitm_ctrl_disconnect_request_action (void *action_data, void *usr_data) {}
void mitm_ctrl_disconnect_reply_action (void *action_data, void *usr_data) {}
void mitm_keep_alive_request_action (void *action_data, void *usr_data) {}
void mitm_get_ap_list_request_action (void *action_data, void *usr_data) {}
void mitm_get_ap_list_reply_action (void *action_data, void *usr_data) {}
void mitm_set_victim_request_action (void *action_data, void *usr_data) {}
void mitm_set_victim_reply_action (void *action_data, void *usr_data) {}
void mitm_get_status_request (void *action_data, void *usr_data) {}
void mitm_get_status_reply (void *action_data, void *usr_data) {}
void mitm_status_change (void *action_data, void *usr_data) {}
void mitm_start_attack_request (void *action_data, void *usr_data) {}
void mitm_start_attack_reply (void *action_data, void *usr_data) {}
void mitm_keep_alive_request_action (void *action_data, void *usr_data) {
	struct mitm_recv_info *recv_info = (struct mitm_recv_info *)action_data;
	ret = sendto(recv_info.sock_fd, MITM_KEEP_ALIVE_REPLY, sizeof(MITM_KEEP_ALIVE_REPLY), 
			recv_info.send_flags, recv_info.recv_from, recv_info.length);
	if (ret) {
		log_printf(MSG_DEBUG, "%s:failed, err:%s", __func__, strerror(errno));
	}
}

void mitm_keep_alive_reply_action (void *action_data, void *usr_data) {
	log_printf(MSG_DEBUG, "[keep alive] server return keep alive packet");
}
