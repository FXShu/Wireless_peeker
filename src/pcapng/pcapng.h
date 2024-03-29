#ifndef PCAPNG_H
#define PCAPNG_H

#include "common.h"
#include "os.h"

/***
 *  Section Header Block :
 *    |- section_header
 *    |- options context : CPU inofrmation, operation system, software name.
 *    |- repeated total block length
 * */
struct pcapng_section_header {
  u32 block_type;       /* string : "\n\r\r\n" */
  u32 total_length;
  u32 magic;            /* detect byte order 0x1a2b3c4d */
  u16 version_major;
  u16 version_minor;
  long section_length;  /* length of section (non-include section header block), -1 means unknown */
}__attribute__((packed));

struct pcap_global_header {
  u32 magic_number;
  u16 version_major;
  u16 version_minor;
  u32 this_zone;
  u32 sigfigs;
  u32 snaplen;
  u32 network;
}__attribute__((packed));

struct pcap_packet_header {
  u32 ts_sec;
  u32 ts_usec;
  u32 incl_len;
  u32 orig_len;
}__attribute__((packed));
/***
 *  Interface Description Block
 *    |- interface_description_header
 *    |- options context : interface name, interface description, operation system information...
 *    |- repeated total block length
 * */
struct interface_description_header {
  u32 block_type;     /* 0x00000001 */
  u32 total_length;
  u16 link_type;
  u16 reserved;
  u32 snap_len;       /* max length saved portion of each packet */
}__attribute__((packed));

/***
 *  Enhanced Packet Block
 *    |- enhanced_packet_header
 *    |- packet data
 *    |- options
 *    |-repeated total block length
 * */
struct enhanced_packet_header {
  u32 block_type;     /* 0x00000006 */
  u32 total_length;
  u32 interface_id;
  u32 timestamp_high;
  u32 timestamp_low;
  u32 captured_packet_length;
  u32 original_packet_length;
}__attribute__((packed));

void convert_pcapng_packet_header_to_pcap(struct enhanced_packet_header *pcapng,
		struct pcap_packet_header *pcap);
int check_file_integrity_pcapng(FILE *fp, int *is_little_endian);
int pop_packet_from_file_pcapng(FILE *fp, struct enhanced_packet_header *header, u8 *buffer, int *buffer_len);

int check_file_integrity_pcap(FILE *fp, int *is_little_endian);
int pop_packet_from_file_pcap(FILE *fp, struct pcap_packet_header *header, u8 *buffer, int *buffer_len);

/***
 * write_header - write down the pcapng format header (include SHB and IDB)
 * @fp : pointer of file
 * @linktype : layer2 type
 * @thiszone : 
 * @snaplen : Maximum bytes of packet capture
 */
int write_header_pcap(FILE *fp, int linktype, int thiszone, int snaplen);

/***
 * write_packet_to_file - write down packet data to pcapng file
 * @fp : pointer of file
 * @packet : whole packet
 * @len : length of packet
 * @id : interface ID, should be same with IDB
 * @tv : capture timestamp
 */
int write_packet_to_pcap_file(FILE *fp, u8 *packet, u32 len, u32 id, struct os_reltime tv);

int write_packet_to_pcap_file_with_header(FILE *fp, u8 *packet,
		u32 len, struct pcap_packet_header *header);
#endif /* PCAPNG_H */
