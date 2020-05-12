#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <my_global.h>
#include <mysql.h>
#include "loglog.h"
#include "global_param.h"
#include "tok_block.h"

static volatile int global_exit = 0;

static void msig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

struct txrec_sql {
	MYSQL_STMT *query, *update, *del;
	const char *query_sql, *update_sql, *del_sql;
	struct txrec_area *txbuf;
	unsigned long hash_len;
	unsigned int seq;
};
static struct txrec_sql txdb = {
	.query_sql = "SELECT txhash, txdata, seq FROM txrec_pool" \
		      " WHERE in_process = 0 FOR UPDATE",
	.update_sql = "UPDATE txrec_pool SET in_process = 1 where seq = ?",
	.del_sql = "DELETE FROM txrec_pool WHERE in_process = 1"
};

struct block_sql {
	MYSQL_STMT *lastid, *last, *insert;
	const char *lastid_sql, *last_sql, *insert_sql;
	struct etk_block *block;
	unsigned long blkid, blklen, hash_len;
	unsigned char blk_hash[SHA_DGST_LEN];
};
static struct block_sql blkdb = {
	.lastid_sql = "SELECT MAX(blockid) FROM blockchain",
	.last_sql = "SELECT hdr_hash FROM blockchain where blockid = ?",
	.insert_sql = "INSERT INTO blockchain(hdr_hash, blockdata) VALUES(?, ?)"
};

struct utxo_sql {
	MYSQL_STMT *insert, *update;
	const char *insert_sql, *update_sql;
	unsigned char txhash[SHA_DGST_LEN];
	unsigned long owner_len, hash_len;
	struct txrec_vout vout;
};
static struct utxo_sql utxodb = {
	.insert_sql = "INSERT INTO utxo (keyhash, etoken_id, value, " \
		       "vout_idx, blockid, txid) VALUES (?, ?, ?, " \
		       "?, ?, ?)",
	.update_sql = "UPDATE utxo SET blockid = ? WHERE blockid = 1"
};

struct dbcon {
	MYSQL *mcon;
	struct txrec_sql *txdb;
	struct block_sql *blkdb;
	struct utxo_sql *utxodb;
	MYSQL_BIND pmbind[6], resbind[3];
	unsigned int maplen;
	char connected;
};

static void dbcon_disconnect(struct dbcon *db);
static void dbcon_disconnect_txdb(struct txrec_sql *txdb);
static void dbcon_disconnect_blkdb(struct block_sql *blkdb);
static void dbcon_disconnect_utxodb(struct utxo_sql *utxodb);

static int dbcon_connect_utxodb(struct dbcon *db)
{
	struct utxo_sql *utxodb = db->utxodb;
	int retv = 0;

	utxodb->insert = mysql_stmt_init(db->mcon);
	if (!check_pointer(utxodb->insert)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(utxodb->insert, utxodb->insert_sql,
				strlen(utxodb->insert_sql))) {
		logmsg(LOG_ERR, "Prepare Statement failed, %s: %s\n",
				utxodb->insert_sql,
				mysql_stmt_error(utxodb->insert));
		retv = -1;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, sizeof(MYSQL_BIND)*6);
	db->pmbind[0].buffer_type = MYSQL_TYPE_BLOB;
	db->pmbind[0].buffer = utxodb->vout.owner;
	db->pmbind[0].buffer_length = RIPEMD_LEN;
	db->pmbind[0].length = &utxodb->owner_len;
	db->pmbind[1].buffer_type = MYSQL_TYPE_SHORT;
	db->pmbind[1].buffer = &utxodb->vout.eid;
	db->pmbind[1].is_unsigned = 1;
	db->pmbind[2].buffer_type = MYSQL_TYPE_LONGLONG;
	db->pmbind[2].buffer = &utxodb->vout.value;
	db->pmbind[2].is_unsigned = 1;
	db->pmbind[3].buffer_type = MYSQL_TYPE_TINY;
	db->pmbind[3].buffer = &utxodb->vout.vout_idx;
	db->pmbind[3].is_unsigned = 1;
	db->pmbind[4].buffer_type = MYSQL_TYPE_LONGLONG;
	db->pmbind[4].buffer = &utxodb->vout.blockid;
	db->pmbind[4].is_unsigned = 1;
	db->pmbind[5].buffer_type = MYSQL_TYPE_BLOB;
	db->pmbind[5].buffer = &utxodb->txhash;
	db->pmbind[5].buffer_length = SHA_DGST_LEN;
	db->pmbind[5].length = &utxodb->hash_len;
	if (mysql_stmt_bind_param(utxodb->insert, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				utxodb->insert_sql,
				mysql_stmt_error(utxodb->insert));
		retv = -4;
		goto err_exit_10;
	}

	utxodb->update = mysql_stmt_init(db->mcon);
	if (!check_pointer(utxodb->update)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(utxodb->update, utxodb->update_sql,
				strlen(utxodb->update_sql))) {
		logmsg(LOG_ERR, "Prepare Statement failed, %s: %s\n",
				utxodb->update_sql,
				mysql_stmt_error(utxodb->update));
		retv = -1;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, sizeof(MYSQL_BIND));
	db->pmbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	db->pmbind[0].buffer = &db->blkdb->blkid;
	db->pmbind[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(utxodb->update, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				utxodb->update_sql,
				mysql_stmt_error(utxodb->update));
		retv = -4;
		goto err_exit_10;
	}

	return retv;

err_exit_10:
	dbcon_disconnect_utxodb(utxodb);
	return retv;
}

static void dbcon_disconnect_utxodb(struct utxo_sql *utxodb)
{
	if (utxodb->insert) {
		mysql_stmt_close(utxodb->insert);
		utxodb->insert = NULL;
	}
	if (utxodb->update) {
		mysql_stmt_close(utxodb->update);
		utxodb->update = NULL;
	}
}

static int dbcon_connect_txdb(struct dbcon *db)
{
	int retv = 0;
	struct txrec_sql *txdb = db->txdb;

	txdb->query = mysql_stmt_init(db->mcon);
	if (!check_pointer(txdb->query)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(txdb->query, txdb->query_sql,
				strlen(txdb->query_sql))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				txdb->query_sql,
				mysql_stmt_error(txdb->query));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->resbind, 0, 3*sizeof(MYSQL_BIND));
	db->resbind[0].buffer_type = MYSQL_TYPE_BLOB;
	db->resbind[0].buffer = txdb->txbuf->txhash;
	db->resbind[0].buffer_length = SHA_DGST_LEN;
	db->resbind[0].length = &txdb->hash_len;
	db->resbind[1].buffer_type = MYSQL_TYPE_BLOB;
	db->resbind[1].buffer = txdb->txbuf->txbuf;
	db->resbind[1].buffer_length = g_param->tx.max_txsize;
	db->resbind[1].length = &txdb->txbuf->txlen;
	db->resbind[2].buffer_type = MYSQL_TYPE_LONG;
	db->resbind[2].buffer = &txdb->seq;
	db->resbind[2].is_unsigned = 1;
	if (mysql_stmt_bind_result(txdb->query, db->resbind)) {
		logmsg(LOG_ERR, "bind result failed: %s, %s\n",
				txdb->query_sql,
				mysql_stmt_error(txdb->query));
		retv = -4;
		goto err_exit_10;
	}

	txdb->update = mysql_stmt_init(db->mcon);
	if (!check_pointer(txdb->update)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(txdb->update, txdb->update_sql,
				strlen(txdb->update_sql))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				txdb->update_sql,
				mysql_stmt_error(txdb->update));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, sizeof(MYSQL_BIND));
	db->pmbind[0].buffer_type = MYSQL_TYPE_LONG;
	db->pmbind[0].buffer = &txdb->seq;
	db->pmbind[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(txdb->update, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				txdb->update_sql,
				mysql_stmt_error(txdb->update));
		retv = -4;
		goto err_exit_10;
	}

	txdb->del = mysql_stmt_init(db->mcon);
	if (!check_pointer(txdb->del)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(txdb->del, txdb->del_sql,
				strlen(txdb->del_sql))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				txdb->del_sql,
				mysql_stmt_error(txdb->del));
		retv = -3;
		goto err_exit_10;
	}

	return retv;

err_exit_10:
	dbcon_disconnect_txdb(txdb);
	return retv;
}

static int dbcon_connect_blkdb(struct dbcon *db)
{
	struct block_sql *blkdb = db->blkdb;
	int retv = 0;

	blkdb->lastid = mysql_stmt_init(db->mcon);
	if (!check_pointer(blkdb->lastid)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(blkdb->lastid, blkdb->lastid_sql,
				strlen(blkdb->lastid_sql))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				blkdb->lastid_sql,
				mysql_stmt_error(blkdb->lastid));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->resbind, 0, sizeof(MYSQL_BIND));
	db->resbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	db->resbind[0].buffer = &blkdb->blkid;
	db->resbind[0].is_unsigned = 1;
	if (mysql_stmt_bind_result(blkdb->lastid, db->resbind)) {
		logmsg(LOG_ERR, "Cannot bind result: %s, %s\n",
				blkdb->lastid_sql,
				mysql_stmt_error(blkdb->lastid));
		goto err_exit_10;
	}

	blkdb->last = mysql_stmt_init(db->mcon);
	if (!check_pointer(blkdb->last)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(blkdb->last, blkdb->last_sql,
				strlen(blkdb->last_sql))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				blkdb->last_sql,
				mysql_stmt_error(blkdb->last));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, sizeof(MYSQL_BIND));
	db->pmbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	db->pmbind[0].buffer = &blkdb->blkid;
	db->pmbind[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(blkdb->last, db->pmbind)) {
		logmsg(LOG_ERR, "Cannot bind Param: %s, %s\n", blkdb->last_sql,
				mysql_stmt_error(blkdb->last));
		goto err_exit_10;
	}
	memset(db->resbind, 0, sizeof(MYSQL_BIND));
	db->resbind[0].buffer_type = MYSQL_TYPE_BLOB;
	db->resbind[0].buffer = blkdb->blk_hash;
	db->resbind[0].buffer_length = SHA_DGST_LEN;
	db->resbind[0].length = &blkdb->hash_len;
	if (mysql_stmt_bind_result(blkdb->last, db->resbind)) {
		logmsg(LOG_ERR, "Cannot bind Param: %s, %s\n",
				blkdb->last_sql,
				mysql_stmt_error(blkdb->last));
		goto err_exit_10;
	}

	blkdb->insert = mysql_stmt_init(db->mcon);
	if (!check_pointer(blkdb->insert)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(blkdb->insert, blkdb->insert_sql,
				strlen(blkdb->insert_sql))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				blkdb->insert_sql,
				mysql_stmt_error(blkdb->insert));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, 2*sizeof(MYSQL_BIND));
	db->pmbind[0].buffer_type = MYSQL_TYPE_BLOB;
	db->pmbind[0].buffer = blkdb->blk_hash;
	db->pmbind[0].buffer_length = SHA_DGST_LEN;
	db->pmbind[0].length = &blkdb->hash_len;
	db->pmbind[1].buffer_type = MYSQL_TYPE_BLOB;
	db->pmbind[1].buffer = blkdb->block;
	db->pmbind[1].buffer_length = g_param->mine.max_blksize;
	db->pmbind[1].length = &blkdb->blklen;
	if (mysql_stmt_bind_param(blkdb->insert, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				blkdb->insert_sql,
				mysql_stmt_error(blkdb->insert));
		retv = -4;
		goto err_exit_10;
	}

	return retv;

err_exit_10:
	dbcon_disconnect_blkdb(blkdb);
	return retv;
}

static int dbcon_connect(struct dbcon *db)
{
	int retv = 0;

	db->mcon = mysql_init(NULL);
	if (!check_pointer(db->mcon))
		return -ENOMEM;
	if (mysql_real_connect(db->mcon, g_param->db.host, g_param->db.user,
				g_param->db.passwd, g_param->db.dbname,
				0, NULL, 0) == NULL) {
		logmsg(LOG_ERR, "mysql_real_connect failed: %s\n",
				mysql_error(db->mcon));
		retv = -2;
		goto err_exit_10;
	}
	retv = dbcon_connect_txdb(db);
	if (retv)
		goto err_exit_10;
	retv = dbcon_connect_blkdb(db);
	if (retv)
		goto err_exit_10;
	retv = dbcon_connect_utxodb(db);
	if (retv)
		goto err_exit_10;

	db->connected = 1;
	return retv;

err_exit_10:
	dbcon_disconnect(db);
	return retv;
}

static void dbcon_disconnect_txdb(struct txrec_sql *txdb)
{
	if (txdb->query) {
		mysql_stmt_close(txdb->query);
		txdb->query = NULL;
	}
	if (txdb->update) {
		mysql_stmt_close(txdb->update);
		txdb->update = NULL;
	}
	if (txdb->del) {
		mysql_stmt_close(txdb->del);
		txdb->del = NULL;
	}
}

static void dbcon_disconnect_blkdb(struct block_sql *blkdb)
{
	if (blkdb->lastid) {
		mysql_stmt_close(blkdb->lastid);
		blkdb->lastid = NULL;
	}
	if (blkdb->last) {
		mysql_stmt_close(blkdb->last);
		blkdb->last = NULL;
	}
	if (blkdb->insert) {
		mysql_stmt_close(blkdb->insert);
		blkdb->insert = NULL;
	}
}

static void dbcon_disconnect(struct dbcon *db)
{

	dbcon_disconnect_txdb(db->txdb);
	dbcon_disconnect_blkdb(db->blkdb);
	dbcon_disconnect_utxodb(db->utxodb);
	mysql_close(db->mcon);
	db->connected = 0;
}

static inline void dbcon_exit(struct dbcon *dbinfo)
{
	if (dbinfo->connected)
		dbcon_disconnect(dbinfo);
	munmap(dbinfo, dbinfo->maplen);
}

static struct dbcon *dbcon_init(void)
{
	struct dbcon *dbinfo;
	unsigned int maplen;
	void *madr;

	maplen = sizeof(struct dbcon) + g_param->tx.max_txsize +
		g_param->mine.max_blksize;
	madr = mmap(NULL, maplen, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (unlikely(madr == MAP_FAILED)) {
		logmsg(LOG_ERR, nomem);
		return NULL;
	}
	dbinfo = madr;
	memset(dbinfo, 0, sizeof(struct dbcon));
	dbinfo->maplen = maplen;
	dbinfo->txdb = &txdb;
	dbinfo->blkdb = &blkdb;
	dbinfo->utxodb = &utxodb;

	dbinfo->txdb->txbuf = madr + sizeof(struct dbcon);
	dbinfo->blkdb->block = madr + sizeof(struct dbcon) +
		g_param->tx.max_txsize;

	if (dbcon_connect(dbinfo)) {
		dbcon_exit(dbinfo);
		dbinfo = NULL;
	}

	return dbinfo;
}

static unsigned long blk_get_lastid(struct dbcon *db)
{
	int mysql_retv;

	if (unlikely(mysql_stmt_execute(db->blkdb->lastid))) {
		logmsg(LOG_ERR, "Cannot execute %s: %s\n",
				db->blkdb->lastid,
				mysql_stmt_error(db->blkdb->lastid));
		return 0;
	}
	if (mysql_stmt_store_result(db->blkdb->lastid)) {
		logmsg(LOG_ERR, "Cannot Store the result: %s, %s\n",
				db->blkdb->lastid_sql,
				mysql_stmt_error(db->blkdb->lastid));
		return 0;
	}
	mysql_retv = mysql_stmt_fetch(db->blkdb->lastid);
	if (unlikely(mysql_stmt_free_result(db->blkdb->lastid)))
		logmsg(LOG_ERR, "Cannot free the result: %s, %s\n",
				db->blkdb->lastid_sql,
				mysql_stmt_error(db->blkdb->lastid));
	if (unlikely(mysql_retv)) {
		logmsg(LOG_ERR, "Cannot get the last block ID: %s, %s\n",
				db->blkdb->lastid_sql,
				mysql_stmt_error(db->blkdb->lastid));
		return 0;
	}
	return db->blkdb->blkid;
}

static int blk_get_last(struct dbcon *db)
{
	int retv = 0, mysql_retv;

	memset(db->blkdb->blk_hash, 0, SHA_DGST_LEN);

	if (blk_get_lastid(db) == 0)
		return -1;
	if (unlikely(mysql_stmt_execute(db->blkdb->last))) {
		logmsg(LOG_ERR, "Cannot execute %s: %s\n",
				db->blkdb->last_sql,
				mysql_stmt_error(db->blkdb->last));
		return -1;
	}
	if (unlikely(mysql_stmt_store_result(db->blkdb->last)))
		logmsg(LOG_ERR, "Cannot store the result: %s\n",
				db->blkdb->last,
				mysql_stmt_error(db->blkdb->last));
	mysql_retv = mysql_stmt_fetch(db->blkdb->last);
	mysql_stmt_free_result(db->blkdb->last);
	if (mysql_retv) {
		logmsg(LOG_ERR, "Cannot get the hash of last block header: %s\n",
				mysql_stmt_error(db->blkdb->last));
		retv = -1;
	}
	assert(db->blkdb->hash_len == SHA_DGST_LEN);
	return retv;
}

static int txrec_pack(struct dbcon *db)
{
	int mysql_retv, i, len;
	struct txrec_sql *txdb = db->txdb;
	struct utxo_sql *utxodb = db->utxodb;
	struct txrec_area *txbuf;
	struct bl_header *blkhdr;
	unsigned char *dgst_buf, *dgst;
	struct txrec *tx;

	blkhdr = &db->blkdb->block->hdr;
	bl_header_init(blkhdr, db->blkdb->blk_hash);

	if (mysql_query(db->mcon, "START TRANSACTION")) {
		logmsg(LOG_ERR, "Cannot start a transaction: %s\n",
				mysql_error(db->mcon));
		return 0;
	}
	if (mysql_stmt_execute(txdb->query)) {
		logmsg(LOG_ERR, "failed to do txrec_pool query: %s\n",
				mysql_stmt_error(txdb->query));
		goto err_exit_10;
	}
	if (mysql_stmt_store_result(txdb->query)) {
		logmsg(LOG_ERR, "Store result failed: %s, %s\n",
				txdb->query_sql,
				mysql_stmt_error(txdb->query));
		mysql_stmt_free_result(txdb->query);
		goto err_exit_10;
	}

	utxodb->owner_len = RIPEMD_LEN;
	utxodb->hash_len = SHA_DGST_LEN;
	txbuf = db->blkdb->block->tx_area;
	len = ((void *)txbuf - (void *)db->blkdb->block);
	mysql_retv = mysql_stmt_fetch(txdb->query);
	while (mysql_retv != MYSQL_NO_DATA && len + sizeof(struct txrec_area) +
			txdb->txbuf->txlen <= g_param->mine.max_blksize) {
		tx = tx_deserialize((const char *)txdb->txbuf->txbuf,
				txdb->txbuf->txlen);
		if (!tx) {
			mysql_retv = mysql_stmt_fetch(txdb->query);
			continue;
		}
		memcpy(utxodb->txhash, txdb->txbuf->txhash, SHA_DGST_LEN);
		utxodb->vout.vout_idx = 0;
		while (tx_get_vout(tx, &utxodb->vout, 1) == 1) {
			if (mysql_stmt_execute(utxodb->insert))
				logmsg(LOG_ERR, "Cannot insert UTXO %s: %s\n",
						utxodb->insert_sql,
						mysql_stmt_error(utxodb->insert));
			utxodb->vout.vout_idx++;
		}
		tx_destroy(tx);

		txrec_area_copy(txbuf, txdb->txbuf);
		txbuf = txrec_area_next(txbuf);
		if (mysql_stmt_execute(txdb->update)) {
			logmsg(LOG_ERR, "Statement Execution %s failed: %s\n",
					txdb->update_sql,
					mysql_stmt_error(txdb->update));
			break;
		}
		blkhdr->numtxs++;
		len = ((void *)txbuf - (void *)db->blkdb->block);
		mysql_retv = mysql_stmt_fetch(txdb->query);
	}
	mysql_stmt_free_result(txdb->query);
	if (mysql_commit(db->mcon))
		logmsg(LOG_ERR, "Commit failed: %s\n", mysql_error(db->mcon));

	if (blkhdr->numtxs == 0)
		return blkhdr->numtxs;

	db->blkdb->blklen = len;
	db->blkdb->block->area_len = len - sizeof(struct etk_block);
	dgst_buf = malloc(blkhdr->numtxs*SHA_DGST_LEN);
	if (!check_pointer(dgst_buf)) {
		blkhdr->numtxs = 0;
		return blkhdr->numtxs;
	}
	dgst = dgst_buf;
	txbuf = db->blkdb->block->tx_area;
	for (i = 0; i < blkhdr->numtxs; i++) {
		memcpy(dgst, txbuf->txhash, SHA_DGST_LEN);
		txbuf = txrec_area_next(txbuf);
		dgst += SHA_DGST_LEN;
	}
	sha256_dgst_2str(blkhdr->mtree_root, dgst_buf, blkhdr->numtxs*SHA_DGST_LEN);
	free(dgst_buf);

	return blkhdr->numtxs;

err_exit_10:
	if (mysql_commit(db->mcon))
		logmsg(LOG_ERR, "Commit failed: %s\n", mysql_error(db->mcon));
	return 0;
}

static int block_log(struct dbcon *db)
{
	int retv = -1;
	struct block_sql *blkdb = db->blkdb;

	if (mysql_query(db->mcon, "START TRANSACTION")) {
		logmsg(LOG_ERR, "Cannot start transaction: %s\n",
				mysql_error(db->mcon));
		return mysql_errno(db->mcon);
	}
	if (mysql_stmt_execute(blkdb->insert)) {
		logmsg(LOG_ERR, "Cannot execute %s: %s\n", blkdb->insert_sql,
				mysql_stmt_error(blkdb->insert));
		goto exit_10;
	}
	blkdb->blkid++;
	if (mysql_stmt_execute(db->utxodb->update)) {
		logmsg(LOG_ERR, "Cannot execute %s: %s\n",
				db->utxodb->update_sql,
				mysql_stmt_error(db->utxodb->update));
		goto exit_10;
	}
	if (mysql_stmt_execute(db->txdb->del)) {
		logmsg(LOG_ERR, "Cannot execute %s: %s\n", db->txdb->del_sql,
				mysql_stmt_error(db->txdb->del));
		goto exit_10;
	}
	retv = 0;

exit_10:
	if (mysql_commit(db->mcon)) {
		logmsg(LOG_ERR, "Cannot Commit transaction: %s\n",
				mysql_errno(db->mcon));
		retv = mysql_errno(db->mcon);
	}
	return retv;
}

int main(int argc, char *argv[])
{
	struct dbcon *dbinfo;
	int retv = 0, numtx, sysret, zerobits;
	struct sigaction act;
	struct timespec intvl;
	volatile int fin;
	int i, elapsed;

	global_param_init(NULL, 0, 0);
	dbinfo = dbcon_init();
	if (!dbinfo) {
		global_param_exit();
		return 1;
	}

	memset(&act, 0, sizeof(act));
	act.sa_handler = msig_handler;
	sysret = sigaction(SIGINT, &act, NULL);
	if (sysret == -1)
		logmsg(LOG_ERR, "Cannot install signal handler: %s\n",
				strerror(errno));
	sysret = sigaction(SIGTERM, &act, NULL);
	if (sysret == -1)
		logmsg(LOG_ERR, "Cannot install signal handler: %s\n",
				strerror(errno));

	intvl.tv_sec = 1;
	intvl.tv_nsec = 0;
	if (blk_get_last(dbinfo) != 0)
		return 0;
	do {
		printf("Last block ID: %lu\n", dbinfo->blkdb->blkid);
		numtx = txrec_pack(dbinfo);
		if (numtx == 0) {
			nanosleep(&intvl, NULL);
			continue;
		}
		logmsg(LOG_INFO, "Total TX records packed: %d\n", numtx);
		fin = 0;
		elapsed = block_mining(&dbinfo->blkdb->block->hdr, &fin);
		zerobits = zbits_blkhdr(&dbinfo->blkdb->block->hdr,
				dbinfo->blkdb->blk_hash);
		logmsg(LOG_INFO, "Mined in %d milliseconds, leading zero bits: %d\n",
				elapsed, zerobits);
		logmsg(LOG_INFO, "SHA256: ");
		for (i = 0; i < SHA_DGST_LEN; i++)
			logmsg(LOG_INFO, "%02X ", dbinfo->blkdb->blk_hash[i]);
		logmsg(LOG_INFO, "\n");
		if (block_log(dbinfo) != 0) {
			logmsg(LOG_ERR, "Fatal Error, Cannot log block into " \
					"the chain\n");
			global_exit = 1;
		}
	} while (global_exit == 0);

	dbcon_exit(dbinfo);
	global_param_exit();
	return retv;
}
