#include "ieee80211_data.h"
#include "l2_packet.h"

void handle_four_way_shakehand(void *ctx, const uint8_t *src_addr, const uint8_t *buf, size_t len) {
	uint32_t offset;
	uint16_t type;
	//struct WPA2_handshake_packet packet;
	//struct beacon beacon_packet;
	void *packet;
	//packet.radiotap_hdr = *(struct ieee80211_radiotap_header *) buf;
	//offset = packet.radiotap_hdr.it_len;

	offset = ((struct ieee80211_radiotap_header *)buf)->it_len;

	if (offset > len) return;

	//packet.type = parse_subtype(ntohs(*(uint32_t *)(buf + offset)));

	type = parse_subtype(ntohs(*(uint32_t *)(buf + offset)));

	switch (type) {
		case IEEE80211_BEACON : 
			packet = malloc(sizeof(struct beacon_packet));
			if (!packet) return;
			packet->frame = (struct ieee80211_hdr_3addr *)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);

			packet->body.fix_param = *((struct beacon_fix_params *)(buf + offset));
			offset += sizeof(struct beacon_fix_params);

			packet->body.tag_param->tag_name = *(buf + (offset++));
			packet->body.tag_param->tag_len  = *(buf + (offset++));
			packet->body.tag_param->data     = (buf + offset);
			offset += packet->body.tag_param->tag_len;
			packet->body.tag_param->head = packet->body.tag_param;

			for (offset < len ) {
				packet->body.tag_param->next->tag_name = *(buf + (offset++));
				packet->body.tag_param->next->tag_len  = *(buf + (offset++));
				packet->body.tag_param->next->data     = (buf + offset);
				offset += packet->body.tag_param->next->tag_len;
				packet->body.tag_param = packet->body.tag_param->next;
			}

		case IEEE80211_DATA :
			packet = malloc(sizeof(struct WPA2_handshake_packet));
			if (!packet) return; 
			// maybe printf something to warning user malloc is failed.
			//packet.ieee80211_data = malloc(sizeof(struct ieee80211_hdr_3addr));
			packet->ieee80211_data = (struct ieee80211_hdr_3addr *)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);
			break;
		case IEEE80211_QOS_DATA :
			packet = malloc(sizeof(struct WPA2_handshake_packet));
			if (!packet) return;
			packet->ieee80211_data = (struct ieee80211_qos_hdr *)(buf + offset);
			offset += sizeof(struct ieee80211_qos_hdr);
			break;
		default:
			return;
	}

	if (offset > len) return;

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
		print_handshake_packet(packet);
	}
	free(packet);
	return;
}
