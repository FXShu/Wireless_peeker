#include "common.h"
#include "crypto.h"

static void ccmp_aad_nonce(const struct ieee80211_hdr_3addr *hdr,
	const u8 *data, u8 *aad, size_t *aad_len, u8 *nonce) {
	u16 fc, stype, seq;
	int qos = 0, addr4 = 0;
	u8 *pos;

	nonce[0] = 0;

	fc = ntohs(hdr->frame_control);
	stype = WLAN_PARSE_SUBTYPE(fc);

	if (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS) == (WLAN_FC_TODS | WLAN_FC_FROMDS))
		addr4 = 1;
	if (WLAN_PARSE_TYPE(fc) == IEEE80211_DATA_TYPE) {
		//IEEE802.11 12.5.3.3.3 Construct AAD
		//   +----|----|----|----|----|----|----+
		//   | FC | A1 | A2 | A3 | SC | A4 | QC |
		//   +----|----|----|----|----|----|----+
		//Oct  2    6    6    6    2    6    2
		//
		// AAD construction is performed as follows:
		// FC - MPDU frame control field, with
		// 1. Subtype subfield (bits 4 5 6) in a Data frame masked to 0
		// 2. Retry subfield (bit 11) masked to 0
		// 3. Power Management subfield (bit 12) masked to 0
		// 4. More Data subfield (bit 13) masked to 0
		// 5. Protected Frame subfield (bit 14) always set to 1
		// 6. + HTC subfield (bit 15) as follow:
		// 	- Masked to 0 in all Data frame containing a QoS control field
		// 	- Unmasked otherwise
		// A1 - MPDU address 1 field
		// A2 - MPDU address 2 field
		// A3 - MPDU address 3 field
		// SC - MPDU sequence control field, with the sequence number subfield (bit 4-15
		// 	of sequence control field) masked to 0. The fragment number subfield is not
		// 	modified.
		// A4 - MPDU address 4 field. if present.
		// QC - QoS control field contains the MSDU priority, if present. The QC TID is
		// 	used in the construction of the AAD. When in a non-DMG BSS and both the STA
		// 	and its peer have their SPP A-MSDU capable field equal to 1, bit 7
		// 	(the A-MSDU Present field) is used in the construction of the ADD. The
		// 	remaining QC fields are masked to 0 for the AAD calculation (bit 4 to 6,
		// 	bit 8 to 15, and bit 7 when either the STA or its peer has the SPP A-MSDU
		// 	capable field equal to 0). When in a DMG BSS, the A-MSDU present bit 7 and
		// 	A-MSDU type bit 8 are used in the construction of the AAD, and the remaining
		// 	QC fields are masked to 0 for the AAD calculation (bit 4 to 6, bit 9 to 15).
		//
		// IEEE802.11 12.5.3.3.4 Construct CCM nonce
		//   +-------------+----------------------------------+----+
		//   | Nonce Flags | STA Mac Address identified by A2 | PN |
		//   +-------------+----------------------------------+----+
		//Oct       1                      6                    6
		//
		//	Nonce Flags
		//	   B0        B3     B4        B5 B6      B7      
		//	   +----------+------------+-----+-------+
		//	   | Priority | Management | PV1 | Zeros |
		//	   +----------+------------+-----+-------+
		//	bit     4           1        1       2
		//	
		fc &= ~0x0070;
		if (WLAN_PARSE_SUBTYPE(fc) == IEEE80211_QOS_DATA) {
			qos = 1;
			const u8 *qc;
			fc &= ~WLAN_FC_ORDER;
			/* Get the QOS message priority item. */
			qc = (const u8*)(hdr + 1);
			if (addr4)
				qc += ETH_ALEN;
			nonce[0] = qc[0] & 0x0f; /* prioriry item = 4 bits */
		}
	} else if (WLAN_PARSE_TYPE(fc) == IEEE80211_MANAGMENT_TYPE)
	nonce[0] |= 0x10; /* Managment. */

	fc &= ~(WLAN_FC_RETRY | WLAN_FC_PWRMGT | WLAN_FC_MOREDATA);
	fc |= WLAN_FC_PROTECTED;

	//  memcpy(aad, &fc, 2);
	MITM_PUT_BE16(aad, fc);
	pos = aad + 2;
	memcpy(pos, hdr->addr1, 3 * ETH_ALEN);
	pos += 3 * ETH_ALEN;
	/* Mask Seq#: do not modify Frag#. */
	seq = ntohs(hdr->seq_ctrl & ~0xfff0);
	memcpy(pos, &seq, 2);
	pos += 2;

	memcpy(pos, hdr + 1, addr4 * ETH_ALEN + qos * 2);
	pos += addr4 * ETH_ALEN;
	if (qos) {
		if (1 /* FIXME: non-DMG BSS */) {
			pos[0] &= ~0x70; /* masked bit 4 to 6 */
			pos[1] &= 0x00; /* masked bit 8 to 15 */
			if (1 /* FIXME: either STA or its peer not support SPP A-MSDU Capab */)
				pos[0] &= ~0x0080;
		} else {
			pos[0] &= 0x70; /* masked bit 4 to 6 */
			pos[1] &= 0xfe; /* masked bit 9 to 15 */
		}
		pos += 2;
	}

	*aad_len = pos - aad;

	memcpy(nonce + 1, hdr->addr2, ETH_ALEN);
	/* The PN subfield shall contain the packet number,
	 * with PN0 in the last octet of the subfield */
	nonce[7] = data[7];   /* PN5 */
	nonce[8] = data[6];   /* PN4 */
	nonce[9] = data[5];   /* PN3 */
	nonce[10] = data[4];  /* PN2 */
	nonce[11] = data[1];  /* PN1 */
	nonce[12] = data[0];  /* PN0 */
}

/***
 * Function - ccmp_encrypt : encrypt plaintext to chipher by CCMP 
 * (counter cipher mode with block chaining message authentication code protocol)
 * @tk - temporarily key
 * @frame - 
 */
u8 *ccmp_encrypt(const u8 *tk, u8 *frame, size_t len, size_t hdrlen, u8 *qos, 
    u8 *pn, int keyid, size_t *encrypted_len) {
  u8 aad[30], nonce[13];
  size_t aad_len, plen;
  u8 *crypt, *pos;
  struct ieee80211_hdr_3addr *hdr;

  if (len < hdrlen || hdrlen < 24)
    return NULL;
  plen = len - hdrlen;

  crypt = malloc(hdrlen + 8 + plen + 8 + AES_BLOCK_SIZE);
  if (crypt == NULL)
    return NULL;

  memcpy(crypt, frame, hdrlen);
  hdr = (struct ieee80211_hdr_3addr *) crypt;

  hdr->frame_control |= htons(WLAN_FC_PROTECTED);
  pos = crypt + hdrlen;
  *pos++ = pn[5]; /* PN0 */
  *pos++ = pn[4]; /* PN1 */
  *pos++ = 0x00;  /* Resd */
  *pos++ = 0x20 | (keyid << 6);
  *pos++ = pn[3]; /* PN2 */
  *pos++ = pn[2]; /* PN3 */
  *pos++ = pn[1]; /* PN4 */
  *pos++ = pn[0]; /* PN5 */

  memset(aad, 0, sizeof(aad));
  ccmp_aad_nonce(hdr, crypt + hdrlen, aad, &aad_len, nonce);
  lamont_hdump(MSG_EXCESSIVE, "CCMP AAD", aad, aad_len);
  lamont_hdump(MSG_EXCESSIVE, "CCMP NONCE", nonce, 13);

  if (aes_ccm_ae(tk, 16, nonce, 8, frame + hdrlen, plen, aad, aad_len,
        pos, pos + plen) < 0) {
    free(crypt);
    return NULL;
  }
  lamont_hdump(MSG_EXCESSIVE, "CCMP encrypted", crypt + hdrlen + 8, plen);

  *encrypted_len = hdrlen + 8 + plen + 8;

  return crypt;
}

u8 *ccmp_decrypt(const u8 *tk, const struct ieee80211_hdr_3addr *hdr,
	const u8 *data, size_t data_len, size_t *decrypted_len) {
	u8 aad[30], nonce[13];
	size_t aad_len;
	/* length of message */
	size_t mlen;
	u8 *plain;

	if (data_len < 8 + 8)
		return NULL;

	plain = malloc(data_len + AES_BLOCK_SIZE);
	if (!plain)
		return NULL;

	mlen = data_len - 8 - 8;

	memset(aad, 0, sizeof(aad));
	ccmp_aad_nonce(hdr, data, aad, &aad_len, nonce);
	lamont_hdump(MSG_EXCESSIVE, "CCMP AAD",aad, aad_len);
	lamont_hdump(MSG_EXCESSIVE, "CCMP nonce", nonce, ARRAY_SIZE(nonce));

	if (aes_ccm_ad(tk, 16, nonce, 8, data+8, mlen, aad, aad_len, data + 8 + mlen, plain) < 0) {
		u16 seq_ctrl = hdr->seq_ctrl;
		log_printf(MSG_INFO, "Invalid CCMP MIC in frame: A1="MACSTR " A2="MACSTR 
			" A3=" MACSTR " seq=%u frag=%u", MAC2STR(hdr->addr1), MAC2STR(hdr->addr2),
			MAC2STR(hdr->addr3), WLAN_PARSE_SEQ(seq_ctrl), WLAN_PARSE_FRAG(seq_ctrl));
		free(plain);
		return NULL;
	}
	*decrypted_len = mlen;
	return plain;
}
