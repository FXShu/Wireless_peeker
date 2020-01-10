#ifndef L2_PACKET_H
#define L2_PACKET_H

/**
 * struct l2_packet_date - Internal l2_packet data strcut
 *
 * This structrue is used by the l2_packet implementation to store its private
 * data. Other files use a pointer to this data calling the l2_packet function
 * but the contents of this structure should not be used directly outside l2_packet
 * implementation.
 * */
#include "ieee80211_data.h"
#include "common.h"
#define GETTYPE(type, object) ((struct (type) *)object)

struct l2_packet_data;

struct l2_ethhdr;

struct access_point_info{
	struct dl_list ap_node;
	char *SSID;
	int channel;
	char country[COUNTRY_CODE_LEN];
	u8 BSSID[ETH_ALEN];
	/***
	 * support rate
	 * Traffic indication
	 * RSN information
	 * vendor specific
	 * HT capabilities
	 * HT information
	 * extended capabilies
	 * vendor specific
	 ***/
};

enum l2_packet_filter_type {
	L2_PACKET_FILTER_DHCP,
	L2_PACKET_FILTER_NDISC,
};

int l2_packet_get_own_addr(struct l2_packet_data *l2, u8 *addr);

int l2_packet_send(struct l2_packet_data *l2, const u8 *dst_addr,
	       	u16 protocol, const u8 *buf, size_t len);

struct l2_packet_data * l2_packet_init(const char *ifname, 
		unsigned short protocol, 
		void (*rx_callback)(void *ctx, const u8 *src_addr,
		       	const char *buf, size_t len),
	       	void *rx_callback_ctx, int l2_hdr);

struct l2_packet_data * l2_packet_init_bridge(const char *br_ifname, 
		const char *ifname, const u8 *own_addr, unsigned short protocol,
	       	void (*rx_callback)(void *ctx, const u8 *src_addr, const char *buf, size_t len), 
		      void *rx_callback_ctx, int l2_hdr);

void l2_packet_deinit(struct l2_packet_data *l2);

int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buf, size_t len);

void l2_packet_notify_auth_start(struct l2_packet_data *l2);

int l2_packet_set_packet_filter(struct l2_packet_data *l2, enum l2_packet_filter_type type);

void print_handshake_packet(struct WPA2_handshake_packet *packet);

uint16_t parse_subtype(uint16_t value);

void handle_four_way_shakehand(void *ctx, const uint8_t *src_addr, const char *buf, size_t len);

void deauth_attack(void *eloop_data, void *user_ctx);

void ap_init(struct access_point_info *info);

/* Just for testing */
void handle_four_way_shakehand(void *ctx, const uint8_t *src_addr, const char *buf, size_t len);

int prepare_deauth_pkt(u8 *buffer, size_t *pkt_len, u8 *victim, u8 *ap, u16 seq_num);
/* Just for testing */

#endif /* L2_PACKET_H */
