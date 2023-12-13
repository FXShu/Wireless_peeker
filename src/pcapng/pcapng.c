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

  /* write header */
  if (fwrite(&header, sizeof(struct pcapng_packet_header), 1, fp) != 1)
    return -1;
  /* write data */
  if (fwrite(packet, len, 1, fp) != 1)
    return -1;
  return 0;
}
