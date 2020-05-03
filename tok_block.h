#ifndef TOK_BLOCK_DSCAO__
#define TOK_BLOCK_DSCAO__
#include <string.h>
#include "sha256.h"
#include "ecc_secp256k1.h"

struct txrec_area {
	unsigned long txlen;
	unsigned char txhash[SHA_DGST_LEN];
	unsigned char txbuf[0];
};

static inline struct txrec_area *txrec_area_next(struct txrec_area *tx)
{
	return (struct txrec_area *)((void *)(tx + 1) + tx->txlen);
}

static inline void txrec_area_copy(struct txrec_area *dst, const struct txrec_area *src)
{
	memcpy(dst, src, src->txlen + sizeof(struct txrec_area));
}

struct bl_header {
	unsigned short ver;
	unsigned short zbits;
	unsigned short node_id;
	unsigned short numtxs;
	unsigned char prev_hash[SHA_DGST_LEN];
	unsigned char mtree_root[SHA_DGST_LEN];
	unsigned long tm;
	unsigned long nonce;
	struct ecc_sig nodsig;
};

struct etk_block {
	struct bl_header hdr;
	unsigned long area_len;
	struct txrec_area tx_area[0];
};

void bl_header_init(struct bl_header *blkhdr, const unsigned char *dgst);

int zbits_blkhdr(const struct bl_header *blhd, unsigned char *dgst);
int block_mining(struct bl_header *hdr, volatile int *fin);
int gensis_block(char *buf, int len);

#endif /* TOK_BLOCK_DSCAO__ */
