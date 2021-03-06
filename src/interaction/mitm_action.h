#ifndef MITM_ACTION_H
#define MITM_ACTION_H
#include "common.h"
#include "command.h"

void mitm_ctrl_connect_request_action (void *action_data, void *usr_data, char *options);

void mitm_ctrl_connect_reply_action (void *action_data, void *usr_data, char *options);

void mitm_ctrl_disconnect_request_action (void *action_data, void *usr_data, char *options);

void mitm_ctrl_disconnect_reply_action (void *action_data, void *usr_data, char *options);

void mitm_keep_alive_request_action (void *action_data, void *usr_data, char *options);

void mitm_get_ap_list_request_action (void *action_data, void *usr_data, char *options);

void mitm_get_ap_list_reply_action (void *action_data, void *usr_data, char *options);

void mitm_set_victim_request_action (void *action_data, void *usr_data, char *options);

void mitm_set_victim_reply_action (void *action_data, void *usr_data, char *options);

void mitm_get_victim_request_action (void *action_data, void *usr_data, char *options);

void mitm_get_victim_reply_action (void *action_data, void *usr_data, char *options);

void mitm_get_dictionary_request_action(void *action_data, void *usr_data, char *options);

void mitm_get_dictionary_reply_action(void *action_data, void *usr_data, char *options);

void mitm_set_ap_request_action (void *action_data, void *usr_data, char *options);

void mitm_set_ap_reply_action(void *action_data, void *usr_data, char *options);

void mitm_get_status_request_action (void *action_data, void *usr_data, char *options);

void mitm_get_status_reply_action (void *action_data, void *usr_data, char *options);

void mitm_status_change_action (void *action_data, void *usr_data, char *options);

void mitm_start_attack_request_action (void *action_data, void *usr_data, char *options);

void mitm_start_attack_reply_action (void *action_data, void *usr_data, char *options);

void mitm_keep_alive_request_action (void *action_data, void *usr_data, char *options);

void mitm_keep_alive_reply_action (void *action_data, void *usr_data, char *options);
#endif /* MITM_ACTION_H */

