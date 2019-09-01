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

#define GETTYPE(type, object) ((struct (type) *)object)

struct l2_packet_data;

struct l2_ethhdr;

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
		       	const u8 *buf, size_t len),
	       	void *rx_callback_ctx, int l2_hdr);

struct l2_packet_data * l2_packet_init_bridge(const char *br_ifname, 
		const char *ifname, const u8 *own_addr, unsigned short protocol,
	       	void (*rx_callback)(void *ctx, const u8 *src_addr, const u8 *buf, size_t len), 
		      void *rx_callback_ctx, int l2_hdr);

void l2_packet_deinit(struct l2_packet_data *l2);

int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buf, size_t len);

void l2_packet_notify_auth_start(struct l2_packet_data *l2);

int l2_packet_set_packet_filter(struct l2_packet_data *l2, enum l2_packet_filter_type type);

void print_handshake_packet(struct WPA2_handshake_packet packet);
#endif /* L2_PACKET_H */
