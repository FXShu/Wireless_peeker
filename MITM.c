#include"MITM.h"

int MITM_init(struct MITM *MITM) {
	int exitcode;
	MITM->state = MITM_state_idle;
	dl_list_init(&MITM->ap_list);
	if (!MITM->dict_path) {
		log_printf(MSG_ERROR, "No dictionary path specify.");
		return -1;
	}
	switch (MITM->dev_type) {
	case ethernet :
		break;
	case wireless :
		MITM->l2_packet = l2_packet_init(MITM->monitor_dev, ETH_P_ALL,
						 handle_four_way_shakehand, MITM, 1);
		MITM->state = MITM_state_ap_search;
		break;
	}
#if 0
	if(getifinfo(&(MITM->if_buf), MITM->errbuf)) {
		log_printf(MSG_ERROR, "getifinfo failed");
		return -1;
	}
	if(!checkdevice(MITM->if_buf, MITM->usr_dev)) {
		log_printf(MSG_ERROR, "checkdevice failed\n");
		return -1;
	}
#endif
	return 0;
}

int MITM_deinit(struct MITM *MITM) {
	free(MITM->dict_path);
	l2_packet_deinit(MITM->l2_packet);
	free(MITM);
}
