#include "sha1.h"

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem, 
		const u8 *addr[], const size_t *len, u8 *mac) {
	if (!key || key_len < 0 || !addr || len < 0 || !mac)
		return -1;
	SHA_CTX context;
	u8 k_ipad[65]; /* inner padding - key XORd with ipad, 64 bytes + '/0' */
	u8 k_opad[65]; /* outer padding - key XORd with opad */

	/* To compute HMAC over the 'text', we perform: 
	 * H(K XOR opad, H(K XOR ipad, text))
	 * ipad - byte 0x36 repeated 64 times
	 * opad - byte 0x5c repeated 64 times
	 * */
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	for (int i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	SHA1_Init(&context);
	SHA1_Update(&context, k_ipad, 64);

	for (int i = 0; i < num_elem; i++) {
		SHA1_Update(&context, addr[i], len[i]);
	}
	SHA1_Final(mac, &context);

	SHA1_Init(&context);
	SHA1_Update(&context, k_opad, 64);

	SHA1_Update(&context, mac, 20);
	SHA1_Final(mac, &context);
	return 0;
}

int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len, u8 *mac) {
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}
