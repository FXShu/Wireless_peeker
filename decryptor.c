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

	/* extract radiotap from buffer and populate the radiotap buffer */
	struct ieee80211_radiotap_header *radiotap_header =
		(struct ieee80211_radiotap_header *)buffer;
	memcpy(radiotap, buffer, radiotap_header->it_len);
	*radiotap_len = radiotap_header->it_len;
	buffer += radiotap_header->it_len;

	/* extract 80211 header from buffer and populate the 80211 header buffer */
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)buffer;
	fc = ntohs(hdr->frame_control);
	stype = WLAN_PARSE_SUBTYPE(fc);
	if (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS) == (WLAN_FC_TODS | WLAN_FC_FROMDS)) {
		addr4 = 1;
	}
	if (WLAN_PARSE_TYPE(fc) == IEEE80211_DATA_TYPE &&
			WLAN_PARSE_SUBTYPE(fc) == IEEE80211_QOS_DATA) {
		qos = 1;
	}
	hdr_len = sizeof(struct ieee80211_hdr_3addr) +
		addr4 * ETH_ALEN + qos * 2 + 8 /* CCMP header */;
	memcpy(ieee80211_header, buffer, hdr_len);
	*ieee80211_header_len = hdr_len;
	buffer += hdr_len;

	/* extract payload from buffer and populate the payload buffer */
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

static int decrypt_packet_file(FILE *input, FILE *output, u8 *target, u8 *tk, int is_pcapng) {
	assert(input != NULL && output != NULL);
	struct pcap_packet_header pcap_header;
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
	int is_encrypted = 0;

	/* pop the next packet from pcap file */
	if (is_pcapng) {
		struct enhanced_packet_header pcapng_header;
		if (pop_packet_from_file_pcapng(input, &pcapng_header, buffer, &buffer_len)) {
			log_printf(MSG_WARNING,
					"%s: pop packet from file failed, stop decrypting", __func__);
			return -1;
		} else {
			
			log_printf(MSG_DEBUG,
					"%s: pop packet from file\n\tpacket_size = %d",
					__func__, buffer_len);
			convert_pcapng_packet_header_to_pcap(&pcapng_header, &pcap_header);
		}
	} else {
		if (pop_packet_from_file_pcap(input, &pcap_header, buffer, &buffer_len)) {
			log_printf(MSG_WARNING,
					"%s: pop packet from file failed, stop decrypting", __func__);
			return -1;
		} else {
			log_printf(MSG_DEBUG,
					"%s: pop packet from file\n\tpacket_size = %d",
					__func__, buffer_len);
		}
	}

	/* dismember the raw data to radiotap, 80211 header and payload */
	if (dismember_ieee80211_packet(buffer, buffer_len, radiotap,
				&radiotap_len, ieee80211_header,
				&ieee80211_header_len, payload, &payload_len)) {
		log_printf(MSG_DEBUG, "%s: dismember packet failed, stop decrypting", __func__);
		return -1;
	}

	/* In order to let wireshark can decode decrypted data, reset the data protected flag
	 * and remove the CCMP header */
	if (!is_target_encrypted_packet((struct ieee80211_hdr *)ieee80211_header, target)) {
		struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)ieee80211_header;
		u16 fc;
		fc = ntohs(hdr->frame_control);
		fc &= ~ WLAN_FC_PROTECTED;
		hdr->frame_control = htons(fc);
		ieee80211_header_len -= 8 /* CCMP_HEADER */;
		is_encrypted = 1;
	} 

	log_printf(MSG_DEBUG, "packet is %s", is_encrypted? "encrypted":"non encrypted");
	/* populate packet by radiotap, 80211 header and payload */
	memset(packet, 0, ARRAY_SIZE(packet));
	memcpy(packet, radiotap, radiotap_len);
	packet_len += radiotap_len;
	memcpy(packet + packet_len, ieee80211_header, ieee80211_header_len);
	packet_len += ieee80211_header_len;
	if (is_encrypted) {
		size_t plain_len;
		u8 *plain = ccmp_decrypt(tk, (struct ieee80211_hdr_3addr *)ieee80211_header,
				payload, payload_len, &plain_len);
		memcpy(packet + packet_len, plain, plain_len);
		packet_len += plain_len;
		/* Because the length of the decoded data may be different from the encrypted data,
		 * overwrite the length in the pcapng header."*/
		pcap_header.incl_len = packet_len;
		pcap_header.orig_len = packet_len;
		if (plain)
			free(plain);
	} else {
		memcpy(packet + packet_len, payload, payload_len);
		packet_len += payload_len;
	}
	return write_packet_to_pcap_file_with_header(output, packet, packet_len, &pcap_header);
}

int main(int argc, char **argv) {
	size_t plain_length;
	u8 tk[16] = {0xd9, 0xc7, 0x78, 0x06, 0x8e, 0x19, 0x20, 0xc0, 0x54, 0x51, 0x40, 0x20, 0x49, 0x74, 0x52, 0x7f};
	int c;
	FILE *input, *output;
	int is_pcapng = 0, is_little_endian = 0;
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
#if 1
	u8 target[ETH_ALEN] = {0x00, 0x90, 0xe8, 0x8a, 0x87, 0x4d};
#else
	u8 target[ETH_ALEN] = {0x00, 0x90, 0xe8, 0x10, 0x00, 0x70};
#endif
	if (!input) {
		log_printf(MSG_ERROR, "The encrypted packet file is not existed");
		exit(EXIT_FAILURE);
	}
	if (!output) {
		log_printf(MSG_ERROR, "The decrypted packet file can't open");
		exit(EXIT_FAILURE);
	}

	if (check_file_integrity_pcap(input, &is_little_endian)) {
		if (check_file_integrity_pcapng(input, &is_little_endian)) {
			exit(EXIT_FAILURE);
		} else {
			is_pcapng = 1;
		}
	}
	write_header_pcap(output, DLT_IEEE802_11_RADIO, 0, MTU);

	while(!feof(input)) {
		decrypt_packet_file(input, output, target, tk, is_pcapng);
	}
	exit(EXIT_SUCCESS);
}
