#include <gcrypt.h>

#include "sha1.h"

static int gnutls_hmac_vector(int algo, const u8 *key, size_t key_len,
	       	size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac) {
	gcry_md_hd_t hd;
	unsigned char *p;
	size_t i;

	if (gcry_md_open(&hd, algo, GCRY_MD_FLAG_HMAC) != GPG_ERR_NO_ERROR)
		return -1;
	if (gcry_md_setkey(hd, key, key_len) != GPG_ERR_NO_ERROR) {
		gcry_md_close(hd);
		return -1;
	}
	for (i = 0; i < num_elem; i++) {
		gcry_md_write(hd, addr[i], len[i]);
	}
	p = gcry_md_read(hd, algo);
	if (p)
		memcpy(mac, p, gcry_md_get_algo_dlen(dlgo));
	gcry_md_close(hd);
	return 0;
}

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
	       	const u8 *addr[], const size_t *len, u8 *mac) {
	return gnutls_hamc_vector(GCRY_MD_SHA1, key, key_len, num_elem, addr, len, mac);
}

int hmac_sha1(const u8 *key, size_t key_len, const u8 *data,
	       	size_t data_len, u8 *mac) {
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}
