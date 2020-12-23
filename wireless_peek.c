#include "include.h"
#include "wireless_peek.h"

int wireless_peek_init(struct wireless_peek *this, char *iface, char *dict, char *database) {
	if (!this || !iface || !dict || !database) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
		return -1;
	}

	this->pcapng_path = fopen(database, "w+");
	if (this->pcapng_path) {
		log_printf(MSG_ERROR, "[%s]: establish database fail, error %s\n",
			__func__, strerror(errno));
		return -1;
	}
	this->usr_dev = strdup(iface);
	this->dict_path = strdup(dict);
	if (!this->usr_dev || !this->dict_path) {
		log_printf(MSG_ERROR, "[%s]: out of memory\n", __func__);
		return -1;
	}

	this->state = wireless_peek_state_idle;
	dl_list_init(&this->ap_list);
	/* TODO: create monitor interface */
	this->l2_packet = l2_packet_init(this->monitor_dev, ETH_P_ALL,
					 handle_four_way_shakehand, this, 1);
	if (!this->l2_packet)
		return -1;
	this->state = wireless_peek_state_ap_search;
	return 0;
}

int wireless_peek_deinit(struct wireless_peek *this) {
	if (this->pcapng_path)
		fclose(this->pcapng_path);
	if (this->dict_path)
		free(this->dict_path);
	if (this->usr_dev)
		free(this->usr_dev);
	l2_packet_deinit(this->l2_packet);
}
