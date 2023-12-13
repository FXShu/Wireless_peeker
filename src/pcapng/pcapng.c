#include "pcapng.h"

static inline void add_option (u8 *buffer, int *offset, u16 code, char *info) {
    MITM_PUT_LE16(buffer + *offset, code);
    *offset += 2;
    MITM_PUT_LE16(buffer + *offset, strlen(info));
    *offset += 2;
    strcpy(buffer + *offset, info);
    *offset += strlen(info) + FILL_IN(info);
}
int write_header(FILE *fp, int linktype, int thiszone, int snaplen) {
	struct pcapng_global_header header;
	header.magic_number = TCPDUMP_MAGIC;
	header.version_major = PCAP_VERSION_MAJOR;
	header.version_minor = PCAP_VERSION_MINOR;
	header.this_zone = thiszone;
	header.sigfigs = 0;
	header.snaplen = snaplen;
	header.network = linktype;
	return fwrite(&header, sizeof(header), 1, fp);
}
int write_packet_to_file(FILE *fp, u8 *packet, u32 len, u32 id, struct os_reltime tv) {
  struct pcapng_packet_header header;
  header.ts_sec = (u32)tv.sec;
  header.ts_usec = (u32)tv.usec;
  header.incl_len = len;
  header.orig_len = len;

  return write_packet_to_file_with_header(fp, packet, len, &header);
}


int write_packet_to_file_with_header(FILE *fp, u8 *packet,
		u32 len, struct pcapng_packet_header *header) {
  /* write header */
  if (fwrite(header, sizeof(struct pcapng_packet_header), 1, fp) != 1)
    return -1;
  /* write data */
  if (fwrite(packet, len, 1, fp) != 1)
    return -1;
  return 0;
}
int pop_packet_from_file(FILE *fp, struct pcapng_packet_header *header, u8 *buffer, int *buffer_len) {
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

int check_file_integrity(FILE *fp) {
	struct pcapng_global_header header;
	size_t size;
	assert(NULL != fp && !feof(fp));

	size = fread(&header, 1, sizeof(header), fp);
	if (size < sizeof(header)) {
		log_printf(MSG_WARNING, "%s: truncated file detected", __func__);
		return -1;
	}

	if (header.magic_number != TCPDUMP_MAGIC) {
		log_printf(MSG_WARNING, "%s: corrupted file detected", __func__);
		return -1;
	}
	return 0;
}
