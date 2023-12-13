#include "common.h"
#include "crypto/crypto.h"
#include <stdio.h>

int debug_level = MSG_EXCESSIVE;

void usage(){
	printf("decryptor usage:\n"
		"decryptor -f<file_path> -w<file_path> [-d<debug level>]...\n"
		"  -h = show this help\n"
		"  -d <level> = increase debugging verbosity\n"
		"  -f = path of encrypted packet capture file\n"
		"  -w = path of the file that decrypted packet writing\n");
}

static int dismember_ieee80211_packet(u8 *buffer, int buffer_len,
		u8 *radiotap, int *radiotap_len,
		u8 *ieee80211_header, int *ieee80211_header_len,
		u8 *payload, int *payload_len) {
	u16 fc, stype;
	int addr4 = 0, qos = 0;
	int hdr_len;
	if (!radiotap || !ieee80211_header || !payload) {
		log_printf(MSG_WARNING, "%s: invalid parameter", __func__);
		return -1;
	}
	struct ieee80211_radiotap_header *radiotap_header =
		(struct ieee80211_radiotap_header *)buffer;
	memcpy(radiotap, buffer, radiotap_header->it_len);
	*radiotap_len = radiotap_header->it_len;
	buffer += radiotap_header->it_len;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)buffer;
	fc = ntohs(hdr->frame_control);
	stype = WLAN_PARSE_SUBTYPE(fc);
	if (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS) == (WLAN_FC_TODS | WLAN_FC_FROMDS)) {
		addr4 = 1;
	}
	if (WLAN_PARSE_TYPE(fc) == IEEE80211_DATA_TYPE) {
		if (WLAN_PARSE_SUBTYPE(fc) == IEEE80211_QOS_DATA) {
			qos = 1;
		}
	} else {
		/* management / control frame is plain */
	}
	hdr_len = sizeof(struct ieee80211_hdr_3addr) +
		addr4 * ETH_ALEN + qos * 2 + 8 /* CCMP header */;
	memcpy(ieee80211_header, buffer, hdr_len);
	buffer += hdr_len;
	*ieee80211_header_len = hdr_len;

	log_printf(MSG_DEBUG, "%s: buffer_len %d, radiotap_header_len %d, hdr_len %d",
			__func__, buffer_len, radiotap_header->it_len, hdr_len);
	if (buffer_len < radiotap_header->it_len + hdr_len) {
		log_printf(MSG_INFO, "%s: incomplete IEEE802.11 packet captured, drop it", __func__);
		return -1;
	}

	*payload_len = buffer_len - radiotap_header->it_len - hdr_len;
	memcpy(payload, buffer, *payload_len);
	lamont_hdump(MSG_EXCESSIVE, "radiotap", radiotap, *radiotap_len);
	lamont_hdump(MSG_EXCESSIVE, "IEEE802.11 MAC", ieee80211_header, *ieee80211_header_len);
	lamont_hdump(MSG_EXCESSIVE, "payload", payload, *payload_len);
	return 0;
}

static int is_target_encrypted_packet(struct ieee80211_hdr *hdr, u8 *target) {
	u16 fc;

	fc = ntohs(hdr->frame_control);
	if (!(fc & WLAN_FC_PROTECTED)) {
		return -1;
	}
	if (!memcmp(target, hdr->addr1, ETH_ALEN) ||
	    !memcmp(target, hdr->addr2, ETH_ALEN) ||
	    !memcmp(target, hdr->addr3, ETH_ALEN)) {
		return 0;
	}
	if (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS) == (WLAN_FC_TODS | WLAN_FC_FROMDS)) {
		return memcmp(target, hdr->addr4, ETH_ALEN);
	}
	return -1;
}

static int decrypt_packet_file(FILE *input, FILE *output, u8 *target, u8 *tk) {
	assert(input != NULL && output != NULL);
	struct pcapng_packet_header pcapng_header;
	u8 buffer[MTU];
	int buffer_len = ARRAY_SIZE(buffer);
	u8 radiotap[256];
	int radiotap_len = ARRAY_SIZE(radiotap);
	u8 ieee80211_header[256];
	int ieee80211_header_len = ARRAY_SIZE(ieee80211_header);
	u8 payload[MTU];
	int payload_len = ARRAY_SIZE(payload);
	u8 packet[MTU];
	int packet_len = 0;

	if (pop_packet_from_file(input, &pcapng_header, buffer, &buffer_len)) {
		log_printf(MSG_WARNING,
				"%s: pop packet from file failed, stop decrypting", __func__);
		return -1;
	} else {
		log_printf(MSG_DEBUG,
				"%s: pop packet from file\n\tpacket_size = %d",
				__func__, buffer_len);
	}
	if (dismember_ieee80211_packet(buffer, buffer_len, radiotap,
				&radiotap_len, ieee80211_header,
				&ieee80211_header_len, payload, &payload_len)) {
		log_printf(MSG_DEBUG, "%s: dismember packet failed, stop decrypting", __func__);
		return -1;
	}
	memset(packet, 0, ARRAY_SIZE(packet));
	memcpy(packet, radiotap, radiotap_len);
	packet_len += radiotap_len;
	memcpy(packet + packet_len, ieee80211_header, ieee80211_header_len);
	packet_len += ieee80211_header_len;
	if (!is_target_encrypted_packet((struct ieee80211_hdr *)ieee80211_header, target)) {
		size_t plain_len;
		u8 *plain = ccmp_decrypt(tk, (struct ieee80211_hdr_3addr *)ieee80211_header,
				payload, payload_len, &plain_len);
		memcpy(packet + packet_len, plain, plain_len);
		packet_len += plain_len;
		/* Because the length of the decoded data may be different from the encrypted data,
		 * overwrite the length in the pcapng header."*/
		pcapng_header.incl_len = packet_len;
		pcapng_header.orig_len = packet_len;
	} else {
		memcpy(packet + packet_len, payload, payload_len);
		packet_len += payload_len;
	}
	return write_packet_to_file_with_header(output, packet, packet_len, &pcapng_header);
}

int main(int argc, char **argv) {
	size_t plain_length;
	u8 tk[16] = {0};
	int c;
	FILE *input, *output;
	for(;;){
		c=getopt(argc, argv,"f:d:hw:");
		if(c < 0)break;
		switch(c){
		case 'd':
			debug_level = atoi(optarg);
		break;
		case 'h':
			usage();
			return 0;
		break;
		case 'f':
			input = fopen(optarg, "r");
		break;
		case 'w':
			output = fopen(optarg, "w+");
		break;
		default:
			usage();
			return 0;
		}
	}
#if 0
	u8 data[62] = {
			0x10, 0x80, 0xa5, 0xce, 0x23, 0x10, 0x3b, 0x47,
			0xd4, 0xf3, 0x26, 0xe5, 0xbd, 0xbd, 0x43, 0x1a,
			0xdd, 0x58, 0xd5, 0xfb, 0xa8, 0x77, 0x93, 0x26,
			0xbf, 0xc6, 0x7b, 0x9c, 0x3b, 0x55, 0x5e, 0x9b,
			0xad, 0x98, 0xe1, 0xd2, 0x6d, 0xe6, 0x9e, 0x34,
			0x71, 0x0b, 0x81, 0x0f, 0x95, 0x60, 0xb7, 0x91,
			0x6e, 0xea, 0x0e, 0xd8, 0xb3, 0xeb, 0xa1, 0x18,
			0xc1, 0x14, 0xb6, 0x90, 0x8f, 0x6d
	};
	u8 radiotap[60] = {
			0x00, 0x00, 0x3c, 0x00, 0x6b, 0x08, 0x80, 0x40,
			0x6a, 0x94, 0x32, 0x83, 0x1e, 0x02, 0x00, 0x00,
			0x00, 0x00, 0x3c, 0x14, 0x40, 0x01, 0xb2, 0x91,
			0x00, 0x00, 0xfc, 0xc3, 0xfe, 0x00, 0x73, 0x2b,
			0x00, 0x00, 0x82, 0x10, 0x01, 0x7f, 0x00, 0x03,
			0x7f, 0x00, 0x10, 0x00, 0x8b, 0x03, 0x00, 0x04,
			0xfd, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xbe, 0x73, 0xce, 0xfe
	};
	u8 mac_header[40] = {
			0x88, 0x43 ,0x2c ,0x00 ,0x00 ,0x90 ,0xe8 ,0x10,
			0x00, 0x50 ,0x46 ,0x90 ,0xe8 ,0x00 ,0x00 ,0x63,
			0x00, 0x90 ,0xe8 ,0x04 ,0x04 ,0x01 ,0x20 ,0x63,
			0x28, 0xd2 ,0x44 ,0xcc ,0x6a ,0xaa ,0x00 ,0x00,
			0x33, 0x76 ,0x00 ,0x20 ,0x25 ,0x00 ,0x00 ,0x00
	};

	u8 *plain = ccmp_decrypt(tk, mac_header, data, ARRAY_SIZE(data), &plain_length);
	//assert(plain != NULL);
	if (plain == NULL) {
		return -1;
	}
	
	lamont_hdump(MSG_INFO, "plain", plain, plain_length);
	FILE *fp = fopen("/home/markshu/tmp/controller-based-roaming/long_break/decrypted.pcap",
				"w+");
	assert(fp != NULL);
	u8 buffer[1024];
	int offset = 0;
	memset(buffer, 0, ARRAY_SIZE(buffer));
	memcpy(buffer, radiotap, ARRAY_SIZE(radiotap));
	offset += ARRAY_SIZE(radiotap);
	memcpy(buffer + offset, mac_header, ARRAY_SIZE(mac_header));
	offset += ARRAY_SIZE(mac_header);
	memcpy(buffer + offset, plain, plain_length);
	offset += plain_length;
	struct os_reltime date;
	os_get_reltime(&date);

	write_header(fp, DLT_IEEE802_11_RADIO, 0, MTU);
	write_packet_to_file(fp, buffer, offset, 0, date);
#else
	u8 target[ETH_ALEN] = {0x00, 0x90, 0xe8, 0x10, 0x00, 0x50};
	if (!input) {
		log_printf(MSG_ERROR, "The encrypted packet file is not existed");
		exit(EXIT_FAILURE);
	}
	if (!output) {
		log_printf(MSG_ERROR, "The decrypted packet file can't open");
		exit(EXIT_FAILURE);
	}

	if (check_file_integrity(input)) {
		exit(EXIT_FAILURE);
	}
	write_header(output, DLT_IEEE802_11_RADIO, 0, MTU);

	decrypt_packet_file(input, output, target, tk);
	decrypt_packet_file(input, output, target, tk);
	decrypt_packet_file(input, output, target, tk);
	decrypt_packet_file(input, output, target, tk);
	decrypt_packet_file(input, output, target, tk);
	decrypt_packet_file(input, output, target, tk);
	decrypt_packet_file(input, output, target, tk);
#endif

}
