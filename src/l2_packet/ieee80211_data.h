#ifndef LINUX_IEEE80211_H
#define LINUX_IEEE80211_H

#include "radiotap.h"
#include "stdint.h"
#define NONCE_LEN 32
#define IEEE_8021X_MIC_LEN 16

#ifndef u8
#define u8 uint8_t
#endif /* u8 */
#ifndef u16
#define u16 uint16_t
#endif /* u16 */
#ifndef u32
#define u32 uint32_t
#endif /* u32 */
#ifndef u64
#define u64 uint64_t
#endif /* u64 */

enum ieee80211_type {
	/* Management Type */
	IEEE80211_ASSOCIATION_RESQUEST    =  0x0000,
	IEEE80211_ASSOCIATION_RESPONSE    =  0x0001,
	IEEE80211_REASSOCIATION_REQUEST   = 0x0002,
	IEEE80211_REASSOCIATION_RESPONSE  = 0x0003,
	IEEE80211_PROBE_REQUEST           = 0x0004,
	IEEE80211_PROBE_RESPONSE          = 0x0005,
	IEEE80211_TIMING_ADVERTISEMENT    = 0x0006,
	IEEE80211_BEACON                  = 0x0008,
	IEEE80211_ATIM                    = 0x0009,
	IEEE80211_DISASSOCIATION          = 0x000A,
	IEEE80211_AUTHENTICATION          = 0x000B,
	IEEE80211_DEAUTHENTICATION        = 0x000C,
	IEEE80211_ACTION                  = 0x000D,
	IEEE80211_ACTION_NO_ACK           = 0x000E,
	/* Control Type */
	IEEE80211_Trigger                 = 0x0012,
	IEEE80211_BEAMFORMING_REPORT_POLL = 0x0014,
	IEEE80211_VHT_NDP_ANNOUNCEMENT    = 0x0015,
	IEEE80211_CONTROL_FRAME_EXTENSION = 0x0016,
	IEEE80211_CONTROL_WRAPPER         = 0x0017,
	IEEE80211_BLOCK_ACK_REQUEST       = 0x0018,
	IEEE80211_BLOCK_ACK               = 0x0019,
	IEEE80211_PS_POLL                 = 0x001A,
	IEEE80211_RTS                     = 0x001B,
	IEEE80211_CTS                     = 0x001C,
	IEEE80211_ACK                     = 0x001D,
	IEEE80211_CF_END                  = 0x001E,
	IEEE80211_CF_END_CF_ACK           = 0x001F,
	/* Data Type */
	IEEE80211_DATA                    = 0x0020,
	IEEE80211_DATA_CF_ACK             = 0x0021,
	IEEE80211_DATA_CF_POLL            = 0x0023,
	IEEE80211_NO_DATA                 = 0x0024,
	IEEE80211_CF_ACK                  = 0x0025,
	IEEE80211_CF_POLL                 = 0x0026,
	IEEE80211_CF_ACK_CF_POLL          = 0x0027,
	IEEE80211_QOS_DATA                = 0x0028,
	IEEE80211_QOS_DATA_CF_ACK         = 0x0029,
	IEEE80211_QOS_DATA_CF_POLL        = 0x002A,
	IEEE80211_QOS_DATA_CF_ACK_CF_POLL = 0x002B,
	IEEE80211_QOS_NO_DATA             = 0x002C,
	IEEE80211_QOS_CF_POLL             = 0x002E,
	IEEE80211_QOS_CF_ACK_CF_POLL      = 0x002F,
	/* Extension Type */
	IEEE80211_DMG_BEACON              = 0x0030,
};

struct ieee80211_hdr {
	u16 frame_control;
	u16 duration_id;
	u8  addr1[ETH_ALEN];
	u8  addr2[ETH_ALEN];
	u8  addr3[ETH_ALEN];
	u16 seq_ctrl;
	u8  addr4[ETH_ALEN];
} __packed __attribute__((aligend(2)));

/* Type: Data = 0x00020 */
struct ieee80211_hdr_3addr {
        u16 frame_control;
        u16 duration_id;
        u8  addr1[ETH_ALEN];
        u8  addr2[ETH_ALEN];
        u8  addr3[ETH_ALEN];
        u16 seq_ctrl;
} __attribute__((aligend(2)));
/* Type: Qos Data = 0x0028 */
struct ieee80211_qos_hdr {
        u16 frame_control;
        u16 duration_id;
        u8  addr1[ETH_ALEN];
        u8  addr2[ETH_ALEN];
        u8  addr3[ETH_ALEN];
        u16 seq_ctrl;
	u16 qos_ctrl;
} __attribute__((aligend(2)));


struct llc_header {
	u8  DSAP;
	u8  SSAP;
	u8  control_field;
	u8  code[3];
	u16 type;
} __attribute__((aligend(2)));


struct ieee_8021x_authentication {
	u8  version;
	u8  type;
	u16 len;
	u8  key_descriptor_type;
	u16 key_information;
	u16 key_len;
	u64 replay_counter;
	u8  Nonce[NONCE_LEN];
	u8  IV[16];
	u64 RSC;
	u64 key_id;
	u8  MIC[IEEE_8021X_MIC_LEN];
	u16 data_len;
	u8 *data;
} __attribute__((aligend(2)));

struct WPA2_handshake_packet {
	struct ieee80211_radiotap_header radiotap_hdr;
	enum ieee80211_type type;
	void *ieee80211_data;
	struct llc_header llc_hdr;
	struct ieee_8021x_authentication auth_data;
} __attribute((aligend(2)));
#endif /* LINUX_IEEE80211_H */
