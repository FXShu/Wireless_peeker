#include <sha1.h>

/**
 * sha1_prf - SHA1-based Pseudo-Random Function (PRF) (IEEE 802.11i, 8.5.1.1)
 * @key: Key for PRF
 * @key_len: Length of the key in bytes
 * @label: A unique label for each purpose of the PRF
 * @data: Extra data to bind into the key
 * @data_len: Length of the data
 * @buf: Buffer for the generated pesudo-random key
 * Returns: 0 on success, -1 of failure.
 *
 * This function is used to derive new, cryptographically separate keys from a give key
 * */
int sha1_prf(unsigned char *key, unsigned int key_len, char *label,
		unsigned char *data, unsigned int data_len, unsigned char *buf, size_t buf_len) {
	char zero = 0, counter = 0;
	size_t pos, plen;
	u8 hash[SHA1_MAC_LEN];
	size_t label_len = strlen(label);
	unsigned char *addr[] = { (unsigned char *)label, (unsigned char *)&zero, data, (unsigned char *)&counter};
	size_t len[] = {label_len, 1, data_len, 1};


	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		if (plen >= SHA1_MAC_LEN) {
			hmac_sha1_vector(key, key_len, 4, addr, len, &buf[pos], NOCACHED);
			pos += SHA1_MAC_LEN;
		} else {
			hmac_sha1_vector(key, key_len, 4, addr, len, hash, NOCACHED);
			memcpy(&buf[pos], hash, plen);
			break;
		}
		counter++;
	}
	memset(hash, 0, sizeof(hash));
	return 0;
}
