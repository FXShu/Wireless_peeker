#include "ieee80211_data.h"
#include "l2_packet.h"
#include "../../MITM.h"

struct access_point_info{
	struct dl_list ap_node;
	char *SSID;
	int channel;
	char *country;
	u8 BSSID[ETH_ALEN];
	/***
	 * support rate
	 * Traffic indication
	 * RSN information
	 * vendor specific
	 * HT capabilities
	 * HT information
	 * extended capabilies
	 * vendor specific
	 ***/
};

static int parse_llc_header(u8* buf, size_t len, 
		uint32_t *offset, struct WPA2_handshake_packet *packet) {
	if (*offset > len) return -1;

	packet->llc_hdr = *(struct llc_header*)(buf + *offset);
	packet->llc_hdr.type = ntohs(packet->llc_hdr.type);
	*offset += sizeof(struct llc_header);
	return 0;
}

static int parse_auth_data(u8 *buf, size_t len,
		uint32_t *offset, struct WPA2_handshake_packet *packet) {
	
	packet->auth_data = *(struct ieee_8021x_authentication*) (buf + *offset);
	*offset += sizeof(struct ieee_8021x_authentication);
	if (*offset > len) return -1;

	packet->auth_data.data = (buf + *offset);
	packet->auth_data.len = ntohs(packet->auth_data.len);
	print_handshake_packet(packet);
	return 0;
}

void handle_four_way_shakehand(void *ctx, const uint8_t *src_addr, const uint8_t *buf, size_t len) {
	
	struct MITM *MITM = (struct MITM *)ctx; 

	uint32_t offset;
	uint16_t type;
	void *packet;
	char* mac_s;
	mac_s = malloc(20);

	offset = ((struct ieee80211_radiotap_header *)buf)->it_len;

	if (offset > len) return;

	type = parse_subtype(ntohs(*(uint32_t *)(buf + offset)));

	switch (type) {
		case IEEE80211_BEACON :;
			struct ieee80211_hdr_3addr frame;
			frame = *(struct ieee80211_hdr_3addr *)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);

			struct beacon_fix_params fix_param;
			fix_param = *((struct beacon_fix_params *)(buf + offset));
			offset += sizeof(struct beacon_fix_params);

			struct access_point_info *ap_info;
			ap_info = malloc(sizeof(struct access_point_info));
			//ap_info->BSSID = mactostring(mac_s, frame.addr2);
			copy_mac_address(frame.addr2, ap_info->BSSID);
			int i = 0;
			for (;offset + 2 < len ;) {
				enum beacon_param tag_name = *(buf + (offset++));
				uint8_t tag_len = *(buf + (offset++));
				switch(tag_name) {
				case BEACON_SSID :
					ap_info->SSID = strndup(buf + offset, tag_len);
					break;
				case BEACON_COUNTRY_INFO :
					ap_info->country = strndup(buf + offset, tag_len);
					break;
				case BEACON_DS :
					ap_info->channel = atoi(strndup(buf + offset, tag_len));
				}
				offset += tag_len;
			}

			struct access_point_info *tmp;
			dl_list_for_each(tmp, &MITM->ap_list, struct access_point_info, ap_node) {
				if (!strcmp(tmp->SSID, ap_info->SSID)) {
					log_printf(MSG_DEBUG, "find a same ap information");
					tmp->country = ap_info->country;
					tmp->channel = ap_info->channel;
					/* maybe call the strcpy() is a good ideal? */
					free(ap_info);
					goto printf_ap;
				}
			}
			log_printf(MSG_DEBUG, "add new ap to ap_list");
			dl_list_add_tail(&MITM->ap_list, &ap_info->ap_node);
printf_ap:
			dl_list_for_each(tmp, &MITM->ap_list, struct access_point_info, ap_node) {
				log_printf(MSG_DEBUG, "[access point] SSID:%s, BSSID" MACSTR, tmp->SSID, MAC2STR(tmp->BSSID));
			}	
		break;

		case IEEE80211_DATA : {
			packet = malloc(sizeof(struct WPA2_handshake_packet));
			struct WPA2_handshake_packet *tmp = (struct WPA2_handshake_packet *)packet;
		       	tmp->type = type;	
			tmp->ieee80211_data = (struct ieee80211_hdr_3addr *)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);

			parse_llc_header(buf, len, &offset, packet);

			if (tmp->llc_hdr.type == 0x888e) 
				parse_auth_data(buf, len, &offset, packet);


		break;}
		
		case IEEE80211_QOS_DATA :{
			packet = malloc(sizeof(struct WPA2_handshake_packet));
			struct WPA2_handshake_packet *tmp = (struct WPA2_handshake_packet *)packet;
			tmp->type = type;
			tmp->ieee80211_data = (struct ieee80211_qos_hdr *)(buf + offset);
			offset += sizeof(struct ieee80211_qos_hdr);
			
			parse_llc_header(buf, len , &offset, packet);

			if (tmp->llc_hdr.type == 0x888e)
				parse_auth_data(buf, len, &offset, packet);
		
		break;}

		default:
			return;
	}
	free(mac_s);
	free(packet);
	return;
}
