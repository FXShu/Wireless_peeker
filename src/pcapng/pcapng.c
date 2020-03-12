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
  struct pcapng_section_header section;
  section.block_type = ANSII_CHECK;
  section.magic = TCPDUMP_MAGIC;
  section.version_major = PCAP_VERSION_MAJOR;
  section.version_minor = PCAP_VERSION_MINOR;
  section.section_length = -1; /* Unknow length of section. */
  char *os, *hw;
  /* Section Options. */
  do {
    hw = os_get_hw_info();
    os = os_get_os_info();
    int pay_load_len = 4 + strlen(hw) + FILL_IN(hw) + 4 + strlen(os) + FILL_IN(os) +
                       4 + strlen(USER_APP_INFOMATION) + FILL_IN(USER_APP_INFOMATION) + 4;
    char *section_payload = malloc(pay_load_len);
    if (!section_payload) {
      printf("Alloc memory failed, with error : %s\n", strerror(errno));
      break;
    }
    memset(section_payload, 0, pay_load_len);
    int offset = 0;
    
    add_option(section_payload, &offset, SECTION_HW_CODE, hw);
    add_option(section_payload, &offset, SECTION_OS_CODE, os);
    add_option(section_payload, &offset, SECTION_USER_APP_CODE, USER_APP_INFOMATION);

    /* Total length = header + option + total length(4 bytes) */
    section.total_length = sizeof(struct pcapng_section_header) + pay_load_len;
    MITM_PUT_LE32(section_payload + offset, section.total_length);
    
    if (fwrite(&section, sizeof(struct pcapng_section_header), 1, fp) != 1)
      break;
    if (fwrite(section_payload, pay_load_len, 1, fp) != 1)
      break;

    /* alies */
    struct interface_description_header interface;
    interface.block_type = INTERFACE_BLOCK_TYPE;
    interface.link_type = linktype;
    interface.reserved = 0;
    interface.snap_len = snaplen;
    /* interface options */
    interface.total_length = sizeof(struct interface_description_header) + 4;

    if (fwrite(&interface, sizeof(interface), 1, fp) != 1)
      break;
    if (fwrite(&interface.total_length, sizeof(interface.total_length), 1, fp) != 1)
      break;
    free(os);
    free(hw);
    return 0;
  } while (0);
  free(os);
  free(hw);
  return -1;
}

int write_packet_to_file(FILE *fp, u8 *packet, u32 len, u32 id, os_time_t tv) {
  union t_convert t;
  t.tv = tv;
  struct enhanced_packet_header header;
  header.block_type = ENHANCED_BLOCK_TYPE;
  header.interface_id = id;
  header.timetamp_high = t.set.high;
  header.timetamp_low = t.set.low;
  header.captured_packet_legth = (u32)len;
  header.original_packet_length = (u32)len;
  int fill_len = 4 - (len % 4);
  header.total_length = sizeof(struct enhanced_packet_header) + len + fill_len + 4;
  u8 *option;
  do {
    /* write header */
    if (fwrite(&header, sizeof(struct enhanced_packet_header), 1, fp) != 1)
      break;
    /* write data */
    if (fwrite(packet, len, 1, fp) != 1)
      break;
    /* write options */
    option = malloc(4 + fill_len);
    MITM_PUT_LE32(option + fill_len, header.total_length);
    if (fwrite(option, 4 + fill_len, 1, fp) != 1)
      break;
    free(option);
    return 0;
  } while(0);
  free(option);
  return -1;
}
