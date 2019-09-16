#include "ieee80211_data.h"
#include "l2_packet.h"

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

	offset = ((struct ieee80211_radiotap_header *)buf)->it_len;

	if (offset > len) return;

	type = parse_subtype(ntohs(*(uint32_t *)(buf + offset)));

	switch (type) {
		case IEEE80211_BEACON :; 
			struct beacon_packet *tmp = (struct beacon_packet *)packet;
			tmp->type =type;
			tmp->frame = *(struct ieee80211_hdr_3addr *)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);

			tmp->body.fix_param = *((struct beacon_fix_params *)(buf + offset));
			offset += sizeof(struct beacon_fix_params);

			struct node ap_info;
			for (;offset + 2 < len ;) {
				tmp->body.tag_param->tag_name = *(buf + (offset++));
				tmp->body.tag_param->tag_len  = *(buf + (offset++));
				tmp->body.tag_param->data     = (buf + offset);
				offset += tmp->body.tag_param->tag_len;
				if(tmp->body.tag_param->tag_name == BEACON_SSID) {
					//key = BSSID
					ap_info.key = tmp->body.tag_param->data;
					//value = MAC address
					ap_info.value = tmp->frame->addr1;

					MITM->ap_list->insert(&MITM->ap_list, &ap_info);
				}
				tmp->body.tag_param = tmp->body.tag_param->next;
			}

		break;

		case IEEE80211_DATA : {
			struct WPA2_handshake_packet *tmp = (struct WPA2_handshake_packet *)packet;
		       	tmp->type = type;	
			tmp->ieee80211_data = (struct ieee80211_hdr_3addr *)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);

			parse_llc_header(buf, len, &offset, packet);

			if (tmp->llc_hdr.type == 0x888e) 
				parse_auth_data(buf, len, &offset, packet);


		break;}
		
		case IEEE80211_QOS_DATA :;
			struct WPA2_handshake_packet *packet;
			packet->type = type;
			packet->ieee80211_data = (struct ieee80211_qos_hdr *)(buf + offset);
			offset += sizeof(struct ieee80211_qos_hdr);
			
			parse_llc_header(buf, len , &offset, packet);

			if (packet->llc_hdr.type == 0x888e)
				parse_auth_data(buf, len, &offset, packet);
		
		break;

		default:
			return;
	}
/*	if (offset > len) return;

	packet->llc_hdr = *(struct llc_header*)(buf + offset);
	packet->llc_hdr.type = ntohs(packet->llc_hdr.type);
	offset += sizeof(struct llc_header);

	if (offset > len) return;

	if (packet->llc_hdr.type == 0x888e) {
		packet->auth_data = *(struct ieee_8021x_authentication *) (buf + offset);
		offset += sizeof(struct ieee_8021x_authentication);

		if (offset > len) return;

		packet->auth_data.data = (buf + offset);
		packet->auth_data.len = ntohs(packet->auth_data.len);
		print_handshake_packet(packet)
	}

*/	//free(packet);
	return;
}
