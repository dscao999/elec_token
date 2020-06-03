#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <my_global.h>
#include <mysql.h>
#include <assert.h>
#include "tok_block.h"
#include "ripemd160.h"
#include "loglog.h"
#include "global_param.h"

#define ZBITS	25

static const unsigned short VER = 100;

static const unsigned char gensis[] = "Startup of Electronic Token " \
				      "Blockchain. All started from Oct 2019 with Dashi Cao.";

unsigned char * (*tx_from_blockchain)(const struct tx_etoken_in *txin,
		int *lock_len, unsigned long *val) = NULL;

static unsigned char *tx_blockchain(const struct tx_etoken_in *txin,
		int *lock_len, unsigned long *val);

static int num_zerobits(const unsigned char *hash)
{
	int zbits = 0, i, j;
	const unsigned char *p = hash;
	unsigned char cb, bbit;

	for (i = 0; i < SHA_DGST_LEN; i++, p++) {
		cb = *p;
		bbit = 0x80;
		for (j = 8; j > 0; j--) {
			if ((cb & bbit) == 0)
				zbits++;
			else
				break;
			bbit = (bbit >> 1);
		}
		if (j > 0)
			break;
	}
	return zbits;
}

static inline void blhdr_hash(unsigned char *dgst, const struct bl_header *hdr)
{
	sha256_dgst_2str(dgst, (const unsigned char *)hdr,
			sizeof(struct bl_header));
}

int zbits_blkhdr(const struct bl_header *hdr, unsigned char *dgst)
{
	unsigned char shabuf[SHA_DGST_LEN];
	unsigned char *sha_dgst;

	if (dgst == NULL)
		sha_dgst = shabuf;
	else
		sha_dgst = dgst;
	blhdr_hash(sha_dgst, hdr);
	return num_zerobits(sha_dgst);
}

struct th_arg {
	struct bl_header *hdr;
	volatile int *fin;
	char up;
	char zbits;
	volatile char th_flag;
};

static void *nonce_search(void *arg)
{
	unsigned char dgst[SHA_DGST_LEN];
	struct th_arg *tharg = arg;
	int zerobits = 0;
	unsigned long nonce = tharg->hdr->nonce;

	assert(tharg->up == -1 || tharg->up == 1);
	do {
		tharg->hdr->nonce += tharg->up;
		if (tharg->hdr->nonce == nonce)
			break;
		zerobits = zbits_blkhdr(tharg->hdr, dgst);
	} while (zerobits < g_param->mine.zbits && *tharg->fin == 0);
	tharg->zbits = zerobits;
	*tharg->fin = 1;
	tharg->th_flag = -1;
	return NULL;
}

int block_mining(struct bl_header *hdr, volatile int *fin)
{
	unsigned char dgst[SHA_DGST_LEN];
	struct th_arg thargs[2];
	struct bl_header *hdrs[2];
	pthread_t upth, downth;
	pthread_attr_t thattr;
	int zbits, sysret, who;
	struct timespec tm0, tm1, intvl;

	blhdr_hash(dgst, hdr);
	zbits = num_zerobits(dgst);
	if (zbits >= g_param->mine.zbits)
		return zbits;
	sysret = pthread_attr_init(&thattr);
	if (sysret) {
		logmsg(LOG_ERR, "pthread attr init failed: %s\n",
				strerror(sysret));
		return zbits;
	}
	sysret = pthread_attr_setdetachstate(&thattr, PTHREAD_CREATE_DETACHED);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread attr set detach failed: %s\n",
				strerror(sysret));
		return zbits;
	}

	hdrs[0] = malloc(2*sizeof(struct bl_header));
	hdrs[1] = hdrs[0] + 1;
	*hdrs[0] = *hdr;
	*hdrs[1] = *hdr;
	thargs[0].hdr = hdrs[0];
	thargs[0].up = -1;
	thargs[0].zbits = zbits;
	thargs[0].fin = fin;
	thargs[0].th_flag = 0;
	thargs[1].hdr = hdrs[1];
	thargs[1].up = -1;
	thargs[1].fin = fin;
	thargs[1].zbits = zbits;
	thargs[1].th_flag = 0;

	clock_gettime(CLOCK_MONOTONIC_RAW, &tm0);
	sysret = pthread_create(&upth, &thattr, nonce_search, thargs);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread create failed: %s\n", strerror(sysret));
		thargs[0].th_flag = -1;
	} else
		thargs[0].th_flag = 1;
	sysret = pthread_create(&downth, &thattr, nonce_search, thargs+1);
	if (unlikely(sysret)) {
		logmsg(LOG_ERR, "pthread create failed: %s\n", strerror(sysret));
		thargs[1].th_flag = -1;
	} else
		thargs[1].th_flag = 1;

	intvl.tv_sec = 1;
	intvl.tv_nsec = 0;
	while (thargs[0].th_flag == 1 || thargs[1].th_flag == 1)
		nanosleep(&intvl, NULL);
	clock_gettime(CLOCK_MONOTONIC_RAW, &tm1);
	zbits = thargs[0].zbits;
	who = 0;
	if (zbits < thargs[1].zbits) {
		zbits = thargs[1].zbits;
		who = 1;
	}

	*hdr = *thargs[who].hdr;
	free(hdrs[0]);
	assert(*fin == 1);
	return time_elapsed(&tm0, &tm1);
}

int gensis_block(char *buf, int size)
{
	int len, zbits;
	struct etk_block *etblock;
	struct bl_header *bhdr;
	volatile int fin = 0;

	len = sizeof(gensis) + sizeof(struct etk_block) +
		sizeof(struct txrec_area);
	if (size < len)
		return -1;

	etblock = (struct etk_block *)buf;
	memset(etblock, 0, sizeof(struct etk_block));
	etblock->area_len = sizeof(struct txrec_area) + sizeof(gensis);
	etblock->tx_area[0].txlen = sizeof(gensis);
	memcpy(etblock->tx_area[0].txbuf, gensis, sizeof(gensis));
	sha256_dgst_2str(etblock->tx_area[0].txhash, gensis, sizeof(gensis));
	bhdr = &etblock->hdr;
	bl_header_init(bhdr, NULL);
	sha256_dgst_2str(bhdr->mtree_root, etblock->tx_area[0].txhash,
			SHA_DGST_LEN);
	zbits = block_mining(bhdr, &fin);
	logmsg(LOG_ERR, "Time used: %d milliseconds\n", zbits);

	return sizeof(struct etk_block) + sizeof(struct txrec_area) +
		etblock->tx_area[0].txlen;
}

void bl_header_init(struct bl_header *blkhdr, const unsigned char *dgst)
{
	struct timespec tm;
	struct ripemd160 ripe;

	memset(blkhdr, 0, sizeof(struct bl_header));
	clock_gettime(CLOCK_REALTIME, &tm);

	blkhdr->tm = tm.tv_sec;
	blkhdr->ver = VER;
	blkhdr->zbits = g_param->mine.zbits;
	if (dgst)
		memcpy(blkhdr->prev_hash, dgst, SHA_DGST_LEN);
	ripemd160_reset(&ripe);
	ripemd160_dgst(&ripe, (const unsigned char *)blkhdr,
			sizeof(struct bl_header));
	blkhdr->nonce = ripe.H[1];
	blkhdr->nonce = (blkhdr->nonce << 32) | ripe.H[0];
	blkhdr->node_id = g_param->node.nodeid;
}

struct txdb_con {
	MYSQL *mcon;
	MYSQL_STMT *utm, *btm;
	const char *utxo_query, *blk_query;
	unsigned char txid[SHA_DGST_LEN], hdr_hash[SHA_DGST_LEN];
	unsigned long txid_len, hdrhash_len;
	unsigned long blockid;
	MYSQL_BIND pmbnd[2], rsbnd[2];
	void *blkbuf;
	unsigned long blklen;
	unsigned char vout_idx;
};

struct txdb_con txcon = {
	.utxo_query = "SELECT blockid FROM utxo WHERE txid = ? AND " \
		       "vout_idx = ? AND in_process = 0",
	.blk_query = "SELECT blockdata, hdr_hash FROM blockchain WHERE blockid = ?"
};

int txdb_con_init(struct txdb_con *txcon)
{
	int retv = 0;

	txcon->mcon = mysql_init(NULL);
	if (!check_pointer(txcon->mcon))
		return -ENOMEM;
	if (mysql_real_connect(txcon->mcon, g_param->db.host, g_param->db.user,
				g_param->db.passwd, g_param->db.dbname, 0,
				NULL, 0) == NULL) {
		retv = -mysql_errno(txcon->mcon);
		logmsg(LOG_ERR, "Cannot connect to DB: %s\n",
				mysql_error(txcon->mcon));
		goto exit_10;
	}
	txcon->utm = mysql_stmt_init(txcon->mcon);
	if (!check_pointer(txcon->utm)) {
		retv = -mysql_stmt_errno(txcon->utm);
		logmsg(LOG_ERR, "Cannot get statement handle: %s -> %s\n",
				txcon->utxo_query, mysql_error(txcon->mcon));
		goto exit_10;
	}
	if (mysql_stmt_prepare(txcon->utm, txcon->utxo_query,
				strlen(txcon->utxo_query))) {
		logmsg(LOG_ERR, "SQL statement preparation failed: %s->%s\n",
				txcon->utxo_query, mysql_stmt_error(txcon->utm));
		retv = -mysql_stmt_errno(txcon->utm);
		goto exit_20;
	}
	memset(txcon->pmbnd, 0, sizeof(txcon->pmbnd));
	txcon->pmbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txcon->pmbnd[0].buffer = txcon->txid;
	txcon->pmbnd[0].buffer_length = SHA_DGST_LEN;
	txcon->pmbnd[0].length = &txcon->txid_len;
	txcon->pmbnd[1].buffer_type = MYSQL_TYPE_TINY;
	txcon->pmbnd[1].buffer = &txcon->vout_idx;
	txcon->pmbnd[1].is_unsigned = 1;
	if (mysql_stmt_bind_param(txcon->utm, txcon->pmbnd)) {
		logmsg(LOG_ERR, "SQL Statment bind failed: %s->%s\n",
				txcon->utxo_query, mysql_stmt_error(txcon->utm));
		retv = -mysql_stmt_errno(txcon->utm);
		goto exit_20;
	}
	memset(txcon->rsbnd, 0, sizeof(txcon->rsbnd));
	txcon->rsbnd[0].buffer_type = MYSQL_TYPE_LONGLONG;
	txcon->rsbnd[0].buffer = &txcon->blockid;
	txcon->rsbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_result(txcon->utm, txcon->rsbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind result failed: %s->%s\n",
				txcon->utxo_query, mysql_stmt_error(txcon->utm));
		retv = -mysql_stmt_errno(txcon->utm);
		goto exit_20;
	}

	txcon->btm = mysql_stmt_init(txcon->mcon);
	if (!check_pointer(txcon->btm)) {
		retv = -mysql_stmt_errno(txcon->btm);
		logmsg(LOG_ERR, "Cannot get statement handle: %s -> %s\n",
				txcon->blk_query, mysql_error(txcon->mcon));
		goto exit_20;
	}
	if (mysql_stmt_prepare(txcon->btm, txcon->blk_query,
				strlen(txcon->blk_query))) {
		logmsg(LOG_ERR, "SQL statement preparation failed: %s->%s\n",
				txcon->blk_query, mysql_stmt_error(txcon->btm));
		retv = -mysql_stmt_errno(txcon->btm);
		goto exit_30;
	}
	memset(txcon->pmbnd, 0, sizeof(txcon->pmbnd));
	txcon->pmbnd[0].buffer_type = MYSQL_TYPE_LONGLONG;
	txcon->pmbnd[0].buffer = &txcon->blockid;
	txcon->pmbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(txcon->btm, txcon->pmbnd)) {
		logmsg(LOG_ERR, "SQL Statment bind failed: %s->%s\n",
				txcon->blk_query, mysql_stmt_error(txcon->btm));
		retv = -mysql_stmt_errno(txcon->btm);
		goto exit_30;
	}
	txcon->blkbuf = malloc(MAX_BLKSIZE);
	if (!check_pointer(txcon->blkbuf)) {
		retv = -ENOMEM;
		goto exit_30;
	}
	memset(txcon->rsbnd, 0, sizeof(txcon->rsbnd));
	txcon->rsbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txcon->rsbnd[0].buffer = txcon->blkbuf;
	txcon->rsbnd[0].buffer_length = MAX_BLKSIZE;
	txcon->rsbnd[0].length = &txcon->blklen;
	txcon->rsbnd[1].buffer_type = MYSQL_TYPE_BLOB;
	txcon->rsbnd[1].buffer = txcon->hdr_hash;
	txcon->rsbnd[1].buffer_length = SHA_DGST_LEN;
	txcon->rsbnd[1].length = &txcon->hdrhash_len;
	if (mysql_stmt_bind_result(txcon->btm, txcon->rsbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind result failed: %s->%s\n",
				txcon->blk_query, mysql_stmt_error(txcon->btm));
		retv = -mysql_stmt_errno(txcon->btm);
		goto exit_30;
	}
	return retv;

exit_30:
	mysql_stmt_close(txcon->btm);
exit_20:
	mysql_stmt_close(txcon->utm);
exit_10:
	mysql_close(txcon->mcon);
	return retv;
}

static inline void txdb_con_exit(struct txdb_con *txcon)
{
	free(txcon->blkbuf);
	if (txcon->btm)
		mysql_stmt_close(txcon->btm);
	if (txcon->utm)
		mysql_stmt_close(txcon->utm);
	if (txcon->mcon)
		mysql_close(txcon->mcon);
}

static int block_verify(struct txdb_con *blkdb)
{
	int retv = 0, i;
	unsigned char hdrhash[SHA_DGST_LEN];
	struct bl_header *hdr = (struct bl_header *)blkdb->blkbuf;
	struct etk_block *blk = (struct etk_block *)blkdb->blkbuf;
	unsigned char *txids, *cur_txid;
	const struct txrec_area *txarea;

	blhdr_hash(hdrhash, hdr);
	assert(memcmp(hdrhash, blkdb->hdr_hash, SHA_DGST_LEN) == 0);
	assert(num_zerobits(hdrhash) >= g_param->mine.zbits);
	txids = malloc(SHA_DGST_LEN*(hdr->numtxs+1));
	if (!check_pointer(txids))
		return retv;
	cur_txid = txids;
	txarea = blk->tx_area;
	for (i = 0; i < hdr->numtxs; i++) {
		memcpy(cur_txid, txarea->txhash, SHA_DGST_LEN);
		txarea = ctxrec_area_next(txarea);
		cur_txid += SHA_DGST_LEN;
	}
	sha256_dgst_2str(cur_txid, (const unsigned char *)txids,
			hdr->numtxs*SHA_DGST_LEN);
	assert(memcmp(cur_txid, hdr->mtree_root, SHA_DGST_LEN) == 0);

	logmsg(LOG_INFO, "Block %lu verified.\n", blkdb->blockid);
	memcpy(txids, hdr->prev_hash, SHA_DGST_LEN);
	blkdb->blockid -= 1;
	if (mysql_stmt_execute(blkdb->btm)) {
		logmsg(LOG_ERR, "mysql_stmt_execute failed: %s->%s\n",
				blkdb->blk_query,
				mysql_stmt_error(blkdb->btm));
		goto exit_10;
	}
	if (mysql_stmt_store_result(blkdb->btm)) {
		logmsg(LOG_ERR, "mysql_stmt_store_result failed: %s->%s\n",
				blkdb->blk_query,
				mysql_stmt_error(blkdb->btm));
		goto exit_10;
	}
	if (mysql_stmt_fetch(blkdb->btm) != 0)
		logmsg(LOG_ERR, "No results from query: %s\n",
				blkdb->blk_query);
	mysql_stmt_free_result(blkdb->btm);
	assert(memcmp(txids, blkdb->hdr_hash, SHA_DGST_LEN) == 0);
	
exit_10:
	free(txids);
	return retv;
}

static unsigned char *tx_blockchain(const struct tx_etoken_in *txin,
		int *lock_len, unsigned long *val)
{
	unsigned char *lock = NULL;
	const struct etk_block *blk;
	const struct bl_header *blkhdr;
	const struct txrec_area *txarea;
	struct txrec *tx;
	int tx_idx, numret;
	struct tx_etoken_out *vout;

	*lock_len = 0;
	memcpy(txcon.txid, txin->txid, SHA_DGST_LEN);
	txcon.txid_len = SHA_DGST_LEN;
	txcon.vout_idx = txin->vout_idx;
	txcon.blockid = 0;
	if (mysql_stmt_execute(txcon.utm)) {
		logmsg(LOG_ERR, "Statement Execution failed: %s->%s\n",
				txcon.utxo_query, mysql_stmt_error(txcon.utm));
		goto exit_10;
	}
	if (mysql_stmt_store_result(txcon.utm)) {
		logmsg(LOG_ERR, "Statement Execution failed: %s->%s\n",
				txcon.utxo_query, mysql_stmt_error(txcon.utm));
		goto exit_10;
	}
	numret = 0;
	while (mysql_stmt_fetch(txcon.utm) != MYSQL_NO_DATA)
		numret += 1;
	mysql_stmt_free_result(txcon.utm);
	if (numret == 0)
		goto exit_10;
	assert(numret == 1);
	if (mysql_stmt_execute(txcon.btm)) {
		logmsg(LOG_ERR, "Statement Execution failed: %s->%s\n",
				txcon.blk_query, mysql_stmt_error(txcon.btm));
		goto exit_10;
	}
	if (mysql_stmt_store_result(txcon.btm)) {
		logmsg(LOG_ERR, "Statement Execution Failed: %s->%s\n",
				txcon.blk_query, mysql_stmt_error(txcon.btm));
		goto exit_10;
	}
	numret = 0;
	while (mysql_stmt_fetch(txcon.btm) != MYSQL_NO_DATA) {
		numret += 1;
		assert(txcon.hdrhash_len == SHA_DGST_LEN);
	}
	mysql_stmt_free_result(txcon.btm);
	assert(numret == 1);
	if (txcon.blklen == 0) {
		logmsg(LOG_ERR, "Invalid block Retrieved!\n");
		goto exit_10;
	}
	blk = txcon.blkbuf;
	blkhdr = txcon.blkbuf;
	txarea = blk->tx_area;
	tx_idx = 0;
	while (memcmp(txarea->txhash, txin->txid, SHA_DGST_LEN) != 0 &&
			tx_idx < blkhdr->numtxs) {
		txarea = ctxrec_area_next(txarea);
		tx_idx += 1;
	}
	assert(tx_idx < blkhdr->numtxs);
	tx = tx_deserialize((const char *)txarea->txbuf, txarea->txlen);
	if (!tx)
		goto exit_10;
	assert(txin->vout_idx < tx->vout_num);
	vout = *(tx->vouts + txin->vout_idx);
	*val += vout->etk.value;
	*lock_len = vout->lock_len;
	lock = malloc(vout->lock_len);
	if (lock)
		memcpy(lock, vout->lock, vout->lock_len);
	tx_destroy(tx);

	block_verify(&txcon);

exit_10:
	return lock;
}

int tok_block_init(void)
{
	tx_from_blockchain = tx_blockchain;
	return txdb_con_init(&txcon);
}

void tok_block_exit(void)
{
	txdb_con_exit(&txcon);
}
