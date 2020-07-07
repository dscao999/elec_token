#ifndef TXPACK_DSCAO__
#define TXPACK_DSCAO__
#include <stdlib.h>
#include <my_global.h>
#include <mysql.h>
#include "sha256.h"

struct txpack_op {
	MYSQL *mcon;
	MYSQL_STMT *uqtm, *uutm, *bqtm, *sqtm;
	MYSQL_BIND mbnd[3], rbnd[2];
	const char *utxo_query, *blk_query, *utxo_update, *sale_query;
	unsigned char *lock;
	unsigned long txid_len;
	unsigned long blk_len;
	unsigned long hdrhash_len;
	unsigned char txid[SHA_DGST_LEN];
	unsigned char hdr_hash[SHA_DGST_LEN];
	unsigned long value;
	unsigned long blockid;
	void *blkbuf;
	unsigned int etoken_id;
	unsigned int lock_len;
	unsigned char vout_idx;
	unsigned char in_process;
};

static inline void txpack_op_release(struct txpack_op *txop)
{
	free(txop->blkbuf);
	mysql_stmt_close(txop->uutm);
	mysql_stmt_close(txop->bqtm);
	mysql_stmt_close(txop->uqtm);
}

int txpack_op_init(struct txpack_op *txop, MYSQL *mcon);
int tx_verify(const unsigned char *txrec, int len, struct txpack_op *txop);

#endif /* TXPACK_DSCAO__ */
