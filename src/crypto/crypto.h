#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include "sha1.h"


#define WPA_KCK_MAX_LEN 32
#define WPA_KEK_MAX_LEN 64
#define WPA_TK_MAX_LEN 32

struct wpa_ptk {
        u8 kck[WPA_KCK_MAX_LEN];
        u8 kek[WPA_KEK_MAX_LEN];
        u8 tk [WPA_TK_MAX_LEN];
        size_t kck_len;
        size_t kek_len;
        size_t tk_len;
};

struct encrypto_info {
	u8 *SSID;
	u8 SA[ETH_ALEN];
	u8 AA[ETH_ALEN];
	u8 SN[NONCE_ALEN];
	u8 AN[NONCE_ALEN];
	u8 *eapol;
	struct wpa_ptk ptk;
	u8 MIC[MD5_DIGEST_LENGTH];
	int enough;
};

/**
 * sha1_vector - SHA-1 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 on failure
 **/
int sha1_vector(size_t num_elem, const uint8_t *addr[], const size_t *len,
		                uint8_t *mac);

int wpa_pmk_to_ptk(u8 *pmk, u8 *addr1, u8 *addr2, 
		u8 *nonce1, u8 *nonce2, u8 *ptk, size_t ptk_len);

/***
 * hmac_hash - calculate MIC by PTK
 * @ver - version of encryption.
 * @key - KCK
 * @hashlen - length of KCK. 
 * @buf - eapol header of authenticent frame
 * @buflen - length of entire eapol packet.
 * @mic - MIC key  
 * */
int hmac_hash(int ver, u8 *key, int hashlen, u8 *buf, int buflen, u8 *mic);
#endif /* CRYPTO_H */
