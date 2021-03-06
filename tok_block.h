#ifndef TOK_BLOCK_DSCAO__
#define TOK_BLOCK_DSCAO__
#include <string.h>
#include "sha256.h"
#include "ecc_secp256k1.h"
#include "toktx.h"

#define MAX_BLKSIZE	(128*1024)

struct txrec_area {
	ulong64 txlen;
	unsigned char txhash[SHA_DGST_LEN];
	unsigned char txbuf[0];
};

static inline struct txrec_area *txrec_area_next(struct txrec_area *tx)
{
	return (struct txrec_area *)((void *)(tx + 1) + tx->txlen);
}

static inline
const struct txrec_area *ctxrec_area_next(const struct txrec_area *tx)
{
	return (const struct txrec_area *)((void *)(tx + 1) + tx->txlen);
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
	ulong64 tm;
	ulong64 nonce;
	struct ecc_sig nodsig;
};

struct etk_block {
	struct bl_header hdr;
	ulong64 area_len;
	struct txrec_area tx_area[0];
};

void bl_header_init(struct bl_header *blkhdr, const unsigned char *dgst);

int zbits_blkhdr(const struct bl_header *blhd, unsigned char *dgst);
int block_mining(struct bl_header *hdr, volatile int *fin);
int gensis_block(char *buf, int len);

static inline struct txrec *txrec_area_deser(const struct txrec_area *txbuf)
{
	return tx_deserialize((const char *)txbuf->txbuf, txbuf->txlen);
}

int tok_block_init(void);
void tok_block_exit(void);

int block_verify(const char *blkbuf, unsigned int blklen, unsigned long blkid);

#endif /* TOK_BLOCK_DSCAO__ */
