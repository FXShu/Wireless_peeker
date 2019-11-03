#ifndef SHA1_H
#define SHA1_H

#include "common.h"
#define SHA1_MAC_LEN 20

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
	       	const u8 *addr[], const size_t *len, u8 *mac);

int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, 
		size_t data_len, u8 *mac);

int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len
		, int iterations, u8 *buf, size_t buflen);

int sha1_prf(const u8 *key, size_t key_len, const char *label, const u8 *data, 
		size_t data_len, u8 *buf, size_t buf_len);

#endif /* SHA1_H */


