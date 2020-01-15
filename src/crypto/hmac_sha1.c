#include "sha1.h"

SHA1_CACHE cached;

int hmac_sha1_vector(unsigned char *key, size_t key_len, size_t num_elem, 
		unsigned char *addr[], const size_t *len, unsigned char *mac, int usecached) {
	if (!key || key_len < 0 || !addr || len < 0 || !mac)
		return -1;
	SHA_CTX context;
	u8 k_ipad[65]; /* inner padding - key XORd with ipad, 64 bytes + '/0' */
	u8 k_opad[65]; /* outer padding - key XORd with opad */
	int i;
	/* To compute HMAC over the 'text', we perform: 
	 * H(K XOR opad, H(K XOR ipad, text))
	 * ipad - byte 0x36 repeated 64 times
	 * opad - byte 0x5c repeated 64 times
	 * */
	if (usecached == NOCACHED || !cached.k_ipad_set || !cached.k_opad_set) {
		memset(k_ipad, 0, sizeof(k_ipad));
		memset(k_opad, 0, sizeof(k_opad));
		memcpy(k_ipad, key, key_len);
		memcpy(k_opad, key, key_len);

		for (i = 0; i < 64; i++) {
			k_ipad[i] ^= 0x36;
			k_opad[i] ^= 0x5c;
		}

		SHA1Init(&context);
		SHA1Update(&context, k_ipad, 64);
		
		if (usecached) {
			memcpy(&cached.k_ipad, &context, sizeof(context));
			cached.k_ipad_set = 1;
		}
		for (i = 0; i < num_elem; i++) {
			SHA1Update(&context, addr[i], len[i]);
		}
		SHA1Final(mac, &context);

		SHA1Init(&context);
		SHA1Update(&context, k_opad, 64);

		if (usecached) {
			memcpy(&cached.k_opad, &context, sizeof(context));
			cached.k_opad_set = 1;
		}

		SHA1Update(&context, mac, 20);
		SHA1Final(mac, &context);
		return 0;
	}

	/* End NOCACHED SHA1 processing */
	/* This code attempts to optimize the hmac-sha1 process by caching
	 * values that remain constant for the same key.  This code is called
	 * many times by pbkdf2, so all optimizations help.
	 *
	 * If we've gotten here, we want to use caching, and have already cached
	 * the values for k_ipad and k_opad after SHA1Update. 
	 */
	memcpy(&context, &cached.k_ipad, sizeof(context));
	for(i = 0; i < num_elem; i++) {
		SHA1Update(&context, addr[i], len[i]);
	}
	SHA1Final(mac, &context);

	memcpy(&context, &cached.k_opad, sizeof(context));
	SHA1Update(&context, mac, 20);
	SHA1Final(mac, &context);
	return 0;
}

int hmac_sha1(unsigned char *key, size_t key_len, unsigned char *data, size_t data_len, unsigned char *mac, int usecached) {
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac, usecached);
}
