#include "pcapng.h"
#include <stdint.h>

static inline void add_option (u8 *buffer, int *offset, u16 code, char *info) {
    MITM_PUT_LE16(buffer + *offset, code);
    *offset += 2;
    MITM_PUT_LE16(buffer + *offset, strlen(info));
    *offset += 2;
    strcpy(buffer + *offset, info);
    *offset += strlen(info) + FILL_IN(info);
}

void convert_pcapng_packet_header_to_pcap(struct enhanced_packet_header *pcapng,
		struct pcap_packet_header *pcap) {
	int64_t timestamp;
	if (!pcapng || !pcap) {
		log_printf(MSG_WARNING, "%s: invalid parameter");
		return;
	}
	pcap->incl_len = pcapng->captured_packet_length;
	pcap->orig_len = pcapng->original_packet_length;

	timestamp = (((int64_t) pcapng->timestamp_high) << 32) + pcapng->timestamp_low;
	pcap->ts_sec = timestamp / 1000000;
	pcap->ts_usec = timestamp % 1000000;
}

int write_header_pcap(FILE *fp, int linktype, int thiszone, int snaplen) {
	struct pcap_global_header header;
	header.magic_number = PCAP_MAGIC;
	header.version_major = PCAP_VERSION_MAJOR;
	header.version_minor = PCAP_VERSION_MINOR;
	header.this_zone = thiszone;
	header.sigfigs = 0;
	header.snaplen = snaplen;
	header.network = linktype;
	return fwrite(&header, sizeof(header), 1, fp);
}
int write_packet_to_pcap_file(FILE *fp, u8 *packet, u32 len, u32 id, struct os_reltime tv) {
  struct pcap_packet_header header;
  header.ts_sec = (u32)tv.sec;
  header.ts_usec = (u32)tv.usec;
  header.incl_len = len;
  header.orig_len = len;

  return write_packet_to_pcap_file_with_header(fp, packet, len, &header);
}


int write_packet_to_pcap_file_with_header(FILE *fp, u8 *packet,
		u32 len, struct pcap_packet_header *header) {
  /* write header */
  if (fwrite(header, sizeof(struct pcap_packet_header), 1, fp) != 1)
    return -1;
  /* write data */
  if (fwrite(packet, len, 1, fp) != 1)
    return -1;
  return 0;
}

int check_file_integrity_pcap(FILE *fp, int *is_little_endian) {
	struct pcap_global_header header;
	size_t size;
	assert(NULL != fp);

	rewind(fp);
	size = fread(&header, 1, sizeof(header), fp);
	if (size < sizeof(header)) {
		log_printf(MSG_WARNING, "%s: truncated file detected", __func__);
		return -1;
	}

	if (header.magic_number != PCAP_MAGIC) {
		if (header.magic_number != ntohl(PCAP_MAGIC)) {
			log_printf(MSG_WARNING, "%s: corrupted file detected", __func__);
			return -1;
		} else {
			*is_little_endian = 1;
		}
	}
	*is_little_endian = 0;
	return 0;
}

int pop_packet_from_file_pcap(FILE *fp, struct pcap_packet_header *header,
		u8 *buffer, int *buffer_len) {
	size_t size;

	if (*buffer_len < MTU) {
		log_printf(MSG_WARNING, "%s: require the length of buffer large then %d",
				__func__, MTU);
		return -1;
	}
	if (!header) {
		log_printf(MSG_WARNING, "%s: invalid parameter", __func__);
		return -1;
	}
	if (!fp || feof(fp)) {
		log_printf(MSG_WARNING, "%s: file is not existed or EOF detected", __func__);
		return -1;
	}
	size = fread(header, 1, sizeof(*header), fp);
	if (size < sizeof(*header)) {
		log_printf(MSG_WARNING, "%s: incomplete packet header detected", __func__);
		return -1;
	}

	if (header->incl_len <= 0) {
		log_printf(MSG_WARNING, "%s: size of packet is less then 0", __func__);
		return -1;
	}
	*buffer_len = fread(buffer, 1, header->incl_len, fp);
	if (*buffer_len < header->incl_len) {
		log_printf(MSG_WARNING, "%s: incomplete packet detected", __func__);
		return -1;
	}
	return 0;
}

int check_file_integrity_pcapng(FILE *fp, int* is_little_endian) {
	rewind(fp);
	struct pcapng_section_header header;

	assert(NULL != fp);
	size_t size = fread(&header, 1, sizeof(header), fp);
	if (size < sizeof(header)) {
		log_printf(MSG_WARNING, "%s: truncated file deteted", __func__);
		return -1;
	}

	if (header.magic != PCAPNG_MAGIC) {
		if (header.magic != ntohl(PCAPNG_MAGIC)) {
			log_printf(MSG_WARNING, "%s: corrupted file detected", __func__);
			return -1;
		} else {
			*is_little_endian = 1;
		}
	}
	*is_little_endian = 0;
	/* skip other information in pcapng header */
	if (fseek(fp, header.total_length, SEEK_SET)) {
		log_printf(MSG_WARNING, "%s: offset file steam failed, error %s",
				__func__, strerror(errno));
		return -1;
	}
	return 0;
}

int pop_packet_from_file_pcapng(FILE *fp, struct enhanced_packet_header *header,
		u8 *buffer, int *buffer_len) {
	size_t size;

	if (*buffer_len < MTU) {
		log_printf(MSG_WARNING, "%s: require the length of buffer large then %d",
				__func__, MTU);
		return -1;
	}
	if (!header) {
		log_printf(MSG_WARNING, "%s: invalid parameter", __func__);
		return -1;
	}
	if (!fp || feof(fp)) {
		log_printf(MSG_WARNING, "%s: file is not existed or EOF detected", __func__);
		return -1;
	}
	size = fread(header, 1, sizeof(*header), fp);
	if (size < sizeof(*header)) {
		log_printf(MSG_WARNING, "%s: incomplete packet header detected", __func__);
		return -1;
	}

	/* we only care the packet block */
	if (header->block_type != ENHANCED_BLOCK_TYPE) {
		/* skip the content of other block */

		fseek(fp, header->total_length - sizeof(*header), SEEK_CUR);
		return -1;
	}
	if (header->captured_packet_length <= 0) {
		log_printf(MSG_WARNING, "%s: size of packet is less then 0", __func__);
		return -1;
	}
	*buffer_len = fread(buffer, 1, header->captured_packet_length, fp);
	if (*buffer_len < header->captured_packet_length) {
		log_printf(MSG_WARNING, "%s: incomplete packet detected", __func__);
		return -1;
	} else {
		fseek(fp, 4, SEEK_CUR);
	}
	return 0;
}
