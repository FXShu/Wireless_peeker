#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include "sha1.h"


#define WPA_KCK_MAX_LEN 32
#define WPA_KEK_MAX_LEN 64
#define WPA_TK_MAX_LEN 32
#define WPA_REPLAY_COUNTER_LEN 8
#define WPA_NONCE_LEN 32
struct wpa_eapol_key {
	u8 version;
	u8 type;
	u16 eapol_len;
	u8 key_description;
	u16 key_info;
	u16 key_length;
	u8 replay_counter[WPA_REPLAY_COUNTER_LEN];
	u8 key_nonce[WPA_NONCE_LEN];
	u8 key_iv[16];
	u8 key_rsc[8];
	u8 key_id[8];   /* Reserved in IEEE 802.11i/RSN */
	u8 key_mic[16];
	u16 key_data_length;
	/* u8 key_data[0]; */
} __attribute__ ((packed));

struct wpa_ptk {
	u8 mic_key[16];
	u8 encr_key[16];
	u8 tk1[16];
	union {
		u8 tk2[16];
		struct {
			u8 tx_mic_key[8];
			u8 rx_mic_key[8];
		} auth;
	} u;
} __attribute__ ((packed));

struct encrypto_info {
	u8 *SSID;
	int Channel;
	u8 SA[ETH_ALEN];
	u8 AA[ETH_ALEN];
	u8 SN[NONCE_ALEN];
	u8 AN[NONCE_ALEN];
	int version;
	u8 counter[8];
	int eapol_frame_len;
	u8 *eapol;
	struct wpa_ptk ptk;
	u8 MIC[MD5_DIGEST_LENGTH];
	int enough;
	char *password;
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

/**
 * wpa_pmk_to_ptk - calculate PTK by PMK
 * @pmk: pointers to PMK areas
 * @addr1: MAC Address of access point
 * @addr2: MAC Address of STA
 * @nonce1: Nonce value generate by Access pointer
 * @nonce2: Nonce value generate by STA
 * @ptk: Pointers to PTK area
 * @pkt_len: Length of PTK (bytes)
 */
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

/**
 * dictionary_attack - foreach password in dictionary to match correct password.
 * @dictionary_path: The path of password dictionary (absolute path).
 * @info: The information to calculate PMK, PTK and MIC wihch capute in the 4-way handshake.
 * @cracked: set this to 1, if already crack password.
 */

int dictionary_attack(const char *dictionary_path, struct encrypto_info *info, int cracked);

/**
 * aes_encrypt_init - Initialize AES for encryption
 * @key: Encryption key.
 * @len: Key Length in bytes (usually 16, i.e., 128 bits)
 * Returns : Pointer to context data or NULL on failure.
 */
void *aes_encrypt_init(const u8 *key, size_t len);

/**
 * aes_encrypt - Encrypt one AES block
 * @ctx: Context pointer from aes_encrypt_init()
 * @plain: Plaintext data to be encrypted (16 bytes)
 * @crypt: Buffer for the encrypted data (18 bytes)
 * Returns: 0 on success, -1 on failure.
 */
int aes_encrypt(void *ctx, const u8 *plain, u8 *crypt);

/**
 * aes_encrypt_deinit - Deinitialize AES encryption
 * @ctx: Context pointer from aes_encrypt_init()
 */
void aes_encrypt_deinit(void *ctx);

/**
 * aes_ccm_ae - Main AES-CBC encrption process.
 */
int aes_ccm_ae(const u8 *key, size_t key_len, const u8 *nonce,
    size_t M, const u8 *plain, size_t plain_len, const u8 *aad,
    size_t aad_len, u8 *crypt, u8 *auth);


int aes_ccm_ad(const u8 *key, size_t key_len, const u8 *nonce, size_t M,
    const u8 *crypt, size_t crypt_len, const u8 *aad, size_t aad_len,
    const u8 *auth, u8 *plain);

u8 *ccmp_encrypt(const u8 *tk, u8 *frame, size_t len, size_t hdrlen, u8 *qos,
		 u8 *pn, int keyid, size_t *encrypted_len);

/**
 * ccmp_descrpt - descrpte cipher to plain by AES-CCM
 * @tk - temporal key from PTK
 * @hdr - ieee80211 header from packet
 * @data - payload from packet, not include radiotap header, 80211 header
 * @data_len - length of packet payload. likely, not include radiotap and 80211 header
 * @descrtpted_len - length of plain text.
 * Return - Plain text, should be free after using.
 */
u8 *ccmp_decrypt(const u8 *tk, const struct ieee80211_hdr_3addr *hdr, const u8 *data,
      size_t data_len, size_t *decrypted_len);
#endif /* CRYPTO_H */
