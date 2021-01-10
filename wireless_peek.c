#include <string.h>
#include "common.h"
#include "wireless_peek.h"

int wireless_peek_init(struct wireless_peek *this, char *iface, char *dict, char *database) {
	if (!this || !iface || !dict || !database) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
		return -1;
	}

	this->status.loots = fopen(database, "w+");
	if (this->status.loots) {
		log_printf(MSG_ERROR, "[%s]: establish database fail, error %s\n",
			__func__, strerror(errno));
		return -1;
	}
	this->config.usr_dev = strdup(iface);
	this->config.dict_path = strdup(dict);
	if (!this->config.usr_dev || !this->config.dict_path) {
		log_printf(MSG_ERROR, "[%s]: out of memory\n", __func__);
		return -1;
	}

	this->state = wireless_peek_state_idle;
	dl_list_init(&this->ap_list);
	/* TODO: create monitor interface */
	this->l2_packet = l2_packet_init(this->config.monitor_dev, ETH_P_ALL,
					 handle_four_way_shakehand, this, 1);
	if (!this->l2_packet)
		return -1;
	this->state = wireless_peek_state_ap_search;
	return 0;
}

int wireless_peek_deinit(struct wireless_peek *this) {
	if (this->status.loots)
		fclose(this->status.loots);
	if (this->config.dict_path)
		free(this->config.dict_path);
	if (this->config.usr_dev)
		free(this->config.usr_dev);
	l2_packet_deinit(this->l2_packet);
}
