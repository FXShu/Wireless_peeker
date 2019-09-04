#include "ieee80211_data.h"
#include "l2_packet.h"

void handle_four_way_shakehand(void *ctx, const uint8_t *src_addr, const uint8_t *buf, size_t len) {
	uint32_t offset;
	struct WPA2_handshake_packet packet;
	packet.radiotap_hdr = *(struct ieee80211_radiotap_header *) buf;
	offset = packet.radiotap_hdr.it_len;

	if (offset > len) return;

	packet.type = parse_subtype(ntohs(*(uint32_t *)(buf + offset)));

	switch (packet.type) {
		case IEEE80211_DATA :
			//packet.ieee80211_data = malloc(sizeof(struct ieee80211_hdr_3addr));
			packet.ieee80211_data = (struct ieee80211_hdr_3addr *)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);
			break;
		case IEEE80211_QOS_DATA :
			packet.ieee80211_data = (struct ieee80211_qos_hdr *)(buf + offset);
			offset += sizeof(struct ieee80211_qos_hdr);
			break;
		default:
			return;
	}

	if (offset > len) return;

	packet.llc_hdr = *(struct llc_header*)(buf + offset);
	packet.llc_hdr.type = ntohs(packet.llc_hdr.type);
	offset += sizeof(struct llc_header);

	if (offset > len) return;

	if (packet.llc_hdr.type == 0x888e) {
		packet.auth_data = *(struct ieee_8021x_authentication *) (buf + offset);
		offset += sizeof(struct ieee_8021x_authentication);

		if (offset > len) return;

		packet.auth_data.data = (buf + offset);
		packet.auth_data.len = ntohs(packet.auth_data.len);
		print_handshake_packet(packet);
	}
	return;
}
