#include "sha1.h"

extern SHA1_CACHE cached;

/*
static int pbkdf2_sha1_f(const char *passphrase, const u8 *ssid, size_t ssid_len,
	       			int iterations, unsigned int count, u8 *digest) {
	unsigned char tmp[SHA1_MAC_LEN], tmp2[SHA1_MAC_LEN];
	int i, j;
	unsigned char count_buf[4];
	const u8 *addr[2];
	size_t len[2];
	size_t passphrase_len = strlen(passphrase);

	addr[0] = ssid;
	len[0] = ssid_len;
	addr[1] = count_buf;
	len[1] = 4;
*/
	/* F(P, S, c, i) = u1 xor U2 xor ... Uc
	 * U1 = PRF(P, S || i)
	 * U2 = PRF(P, U1)
	 * Uc = PRF(P, Uc-1)
	 * */
/*	count_buf[0] = (count >> 24) & 0xff;
	count_buf[1] = (count >> 16) & 0xff;
	count_buf[2] = (count >> 8)  & 0xff;
	count_buf[3] = count & 0xff;
	if (hmac_sha1_vector((u8 *) passphrase, passphrase_len, 2,
			       	addr, len ,tmp)) //U1
		return -1;
	memcpy(tmp, tmp2, SHA1_MAC_LEN);

	for (i = 0; i < iterations; i++) {
		if (hmac_sha1((u8 *) passphrase, passphrase_len, tmp, SHA1_MAC_LEN, tmp2))
			return -1;
		memcpy(tmp, tmp2, SHA1_MAC_LEN);
		for (j = 0; j < SHA1_MAC_LEN; j++)
			digest[j] ^= tmp2[j];
	}
	return 0;
}
*/
static void pbkdf2_sha1_f(char *passphrase, char *ssid,
		        size_t ssid_len, int iterations, int count,
			unsigned char *digest, int usecached) {
	unsigned char tmp[SHA1_MAC_LEN], tmp2[SHA1_MAC_LEN];
	int i, j;
	unsigned char count_buf[4];
	unsigned char *addr[] = { (unsigned char *)ssid, count_buf };
	size_t len[] = { ssid_len, 4 };
	size_t passphrase_len = strlen(passphrase);

	/* F(P, S, c, i) = U1 xor U2 xor ... Uc
	 * U1 = PRF(P, S || i)
	 * U2 = PRF(P, U1)
	 * Uc = PRF(P, Uc-1)
	 */

	count_buf[0] = (count >> 24) & 0xff;
	count_buf[1] = (count >> 16) & 0xff;
	count_buf[2] = (count >> 8) & 0xff;
	count_buf[3] = count & 0xff;

	hmac_sha1_vector((unsigned char *)passphrase, passphrase_len, 2,
				addr, len, tmp, NOCACHED);
	memcpy(digest, tmp, SHA1_MAC_LEN);

	for (i = 1; i < iterations; i++) {
		hmac_sha1((unsigned char *)passphrase, passphrase_len, tmp,
									SHA1_MAC_LEN, tmp2, USECACHED);
		memcpy(tmp, tmp2, SHA1_MAC_LEN);
		for (j = 0; j < SHA1_MAC_LEN; j++)
			digest[j] ^= tmp2[j];
		}
	/* clear the cached data set */
	memset(&cached, 0, sizeof(cached));
}
/*
int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len,
	       	int iterations, u8 *buf, size_t buflen) {
	unsigned int count = 0;
	unsigned char *pos = buf;
	size_t left = buflen, plen;
	unsigned char digest[SHA1_MAC_LEN];

	while (left > 0) {
		count++;
		if (pbkdf2_sha1_f(passphrase, ssid, ssid_len, iterations,
				       	count, digest))
			return -1;
		plen = left > SHA1_MAC_LEN ? SHA1_MAC_LEN : left;
		memcpy(pos, digest, plen);
		pos += plen;
		left -= plen;
	}

	return 0;
}
*/

int pbkdf2_sha1(char *passphrase, char *ssid, size_t ssid_len,
	int iterations, unsigned char *buf, size_t buflen, int usecached) {
	int count = 0;
	unsigned char *pos = buf;
	size_t left = buflen, plen;
	unsigned char digest[SHA1_MAC_LEN];

	while (left > 0) {
		count++;
		pbkdf2_sha1_f(passphrase, ssid, ssid_len, iterations, count,
										digest, NOCACHED);
		plen = left > SHA1_MAC_LEN ? SHA1_MAC_LEN : left;
		memcpy(pos, digest, plen);
		pos += plen;
		left -= plen;
	}
	return 0;
}
