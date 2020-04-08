#ifndef TOK_BLOCK_DSCAO__
#define TOK_BLOCK_DSCAO__
#include "sha256.h"
#include "ecc_secp256k1.h"

void tok_block_init(int zbits);

struct tree_node;
struct tree_node {
	unsigned char nhash[SHA_DGST_LEN];
	struct tree_node *father, *left, *right;
};

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
	unsigned int tx_nums;
	unsigned int txbuf_len;
	struct tree_node *mkerle;
	void *txbuf;
};

int gensis_block(char *buf, int len);

#endif /* TOK_BLOCK_DSCAO__ */
