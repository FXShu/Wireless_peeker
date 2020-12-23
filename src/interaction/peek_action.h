#ifndef __PEEK_ACTION_H__
#define __PEEK_ACTION_H__

#include "common.h"
#include "command.h"

void peek_ctrl_connect_request_action (void *action_data, void *usr_data, char *options);

void peek_ctrl_connect_reply_action (void *action_data, void *usr_data, char *options);

void peek_ctrl_disconnect_request_action (void *action_data, void *usr_data, char *options);

void peek_ctrl_disconnect_reply_action (void *action_data, void *usr_data, char *options);

void peek_keep_alive_request_action (void *action_data, void *usr_data, char *options);

void peek_get_ap_list_request_action (void *action_data, void *usr_data, char *options);

void peek_get_ap_list_reply_action (void *action_data, void *usr_data, char *options);

void peek_set_victim_request_action (void *action_data, void *usr_data, char *options);

void peek_set_victim_reply_action (void *action_data, void *usr_data, char *options);

void peek_get_victim_request_action (void *action_data, void *usr_data, char *options);

void peek_get_victim_reply_action (void *action_data, void *usr_data, char *options);

void peek_get_dictionary_request_action(void *action_data, void *usr_data, char *options);

void peek_get_dictionary_reply_action(void *action_data, void *usr_data, char *options);

void peek_set_ap_request_action (void *action_data, void *usr_data, char *options);

void peek_set_ap_reply_action(void *action_data, void *usr_data, char *options);

void peek_get_status_request_action (void *action_data, void *usr_data, char *options);

void peek_get_status_reply_action (void *action_data, void *usr_data, char *options);

void peek_status_change_action (void *action_data, void *usr_data, char *options);

void peek_start_attack_request_action (void *action_data, void *usr_data, char *options);

void peek_start_attack_reply_action (void *action_data, void *usr_data, char *options);

void peek_keep_alive_request_action (void *action_data, void *usr_data, char *options);

void peek_keep_alive_reply_action (void *action_data, void *usr_data, char *options);
#endif /* __PEEK_ACTION_H__ */

