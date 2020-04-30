#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <my_global.h>
#include <mysql.h>
#include "loglog.h"
#include "global_param.h"
#include "tok_block.h"

struct dbcon {
	MYSQL *mcon;
	MYSQL_STMT *qtm, *utm, *deltm, *itm;
	const char *txrec_query, *txrec_update, *txrec_del;
	const char *blk_insert;
	unsigned char *block;
	unsigned char sha_dgst[SHA_DGST_LEN];
	unsigned long shalen, blklen;
	unsigned int seq;
	unsigned int maplen;
	MYSQL_BIND pmbind[2], resbind[3];
	struct txrec_area *txbuf;
	char connected;
};

static const char txrec_query[] = "SELECT txhash, txdata, seq FROM txrec_pool" \
				   " WHERE in_process = 0";
static const char txrec_update[] = "UPDATE txrec_pool SET in_process = 1" \
				   " where seq = ?";
static const char txrec_del[] = "DELETE FROM txrec_pool where seq = ?";
static const char blk_insert[] = "INSERT INTO blockchain(hdr_hash, blockdata)" \
				  "VALUES(?, ?)";

static void dbcon_disconnect(struct dbcon *db);

static int dbcon_connect(struct dbcon *db)
{
	int retv;

	retv = 0;
	db->connected = 0;
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
	db->qtm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->qtm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->qtm, db->txrec_query,
				strlen(db->txrec_query))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->txrec_query, mysql_stmt_error(db->qtm));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->resbind, 0, sizeof(db->resbind));
	db->resbind[0].buffer_type = MYSQL_TYPE_BLOB;
	db->resbind[0].buffer = db->txbuf->txhash;
	db->resbind[0].buffer_length = SHA_DGST_LEN;
	db->resbind[0].length = &db->shalen;
	db->resbind[1].buffer_type = MYSQL_TYPE_BLOB;
	db->resbind[1].buffer = db->txbuf->txbuf;
	db->resbind[1].buffer_length = g_param->tx.max_txsize;
	db->resbind[1].length = &db->txbuf->txlen;
	db->resbind[2].buffer_type = MYSQL_TYPE_LONG;
	db->resbind[2].buffer = &db->seq;
	db->resbind[2].is_unsigned = 1;
	if (mysql_stmt_bind_result(db->qtm, db->resbind)) {
		logmsg(LOG_ERR, "bind result failed: %s\n",
				mysql_stmt_error(db->qtm));
		retv = -4;
		goto err_exit_10;
	}

	db->utm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->utm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->utm, db->txrec_update,
				strlen(db->txrec_update))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->txrec_update, mysql_stmt_error(db->utm));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, sizeof(MYSQL_BIND));
	db->pmbind[0].buffer_type = MYSQL_TYPE_LONG;
	db->pmbind[0].buffer = &db->seq;
	db->pmbind[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(db->utm, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				db->txrec_update, mysql_stmt_error(db->utm));
		retv = -4;
		goto err_exit_10;
	}

	db->deltm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->deltm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->deltm, db->txrec_del,
				strlen(db->txrec_del))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->txrec_del, mysql_stmt_error(db->deltm));
		retv = -3;
		goto err_exit_10;
	}
	if (mysql_stmt_bind_param(db->deltm, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				db->txrec_del, mysql_stmt_error(db->deltm));
		retv = -4;
		goto err_exit_10;
	}

	db->itm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->itm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->itm, db->blk_insert,
				strlen(db->blk_insert))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->blk_insert, mysql_stmt_error(db->itm));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, 2*sizeof(MYSQL_BIND));
	db->pmbind[0].buffer_type = MYSQL_TYPE_BLOB;
	db->pmbind[0].buffer = db->sha_dgst;
	db->pmbind[0].buffer_length = SHA_DGST_LEN;
	db->pmbind[0].length = &db->shalen;
	db->pmbind[1].buffer_type = MYSQL_TYPE_BLOB;
	db->pmbind[1].buffer = db->block;
	db->pmbind[1].buffer_length = g_param->mine.max_blksize;
	db->pmbind[1].length = &db->blklen;
	if (mysql_stmt_bind_param(db->itm, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				db->blk_insert, mysql_stmt_error(db->itm));
		retv = -4;
		goto err_exit_10;
	}

	db->connected = 1;
	return retv;

err_exit_10:
	dbcon_disconnect(db);
	return retv;
}

static void dbcon_disconnect(struct dbcon *db)
{
	if (db->qtm) {
		mysql_stmt_close(db->qtm);
		db->qtm = NULL;
	}
	if (db->utm) {
		mysql_stmt_close(db->utm);
		db->utm = NULL;
	}
	if (db->deltm) {
		mysql_stmt_close(db->deltm);
		db->deltm = NULL;
	}
	if (db->itm) {
		mysql_stmt_close(db->itm);
		db->itm = NULL;
	}
	if (db->mcon) {
		mysql_close(db->mcon);
		db->mcon = NULL;
	}
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
	dbinfo->txrec_query = txrec_query;
	dbinfo->txrec_update = txrec_update;
	dbinfo->txrec_del = txrec_del;
	dbinfo->blk_insert = blk_insert;

	dbinfo->txbuf = madr + sizeof(struct dbcon);
	dbinfo->block = madr + sizeof(struct dbcon) + g_param->tx.max_txsize;

	if (dbcon_connect(dbinfo)) {
		dbcon_exit(dbinfo);
		dbinfo = NULL;
	}

	return dbinfo;
}

static void pack_txrec(struct dbcon *db)
{
	int mysql_retv, pos;
	struct txrec_area *txbuf;
	struct bl_header *blkhdr;

	blkhdr = (struct bl_header *)db->block;
	pos = sizeof(struct bl_header);
	txbuf = (struct txrec_area *)(db->block + pos);
	if (mysql_query(db->mcon, "START TRANSACTION")) {
		logmsg(LOG_ERR, "Cannot start a transaction: %s\n",
				mysql_error(db->mcon));
		return;
	}
	if (mysql_stmt_execute(db->qtm)) {
		logmsg(LOG_ERR, "failed to do txrec_pool query: %s\n",
				mysql_stmt_error(db->qtm));
		return;
	}

	bl_header_init(blkhdr);
	if (mysql_stmt_store_result(db->qtm)) {
		logmsg(LOG_ERR, "Store result failed: %s, %s\n", txrec_query,
				mysql_stmt_error(db->qtm));
		mysql_stmt_free_result(db->qtm);
	}
	mysql_retv = mysql_stmt_fetch(db->qtm);
	while (mysql_retv != MYSQL_NO_DATA &&
			pos + sizeof(struct txrec_area) + db->txbuf->txlen <
			g_param->mine.max_blksize)  {
		txrec_area_copy(txbuf, db->txbuf);
		pos += sizeof(struct txrec_area) + txbuf->txlen;
		txbuf = (struct txrec_area *)(db->block + pos);
		if (mysql_stmt_execute(db->utm)) {
			logmsg(LOG_ERR, "Statement Execution %s failed: %s\n",
					txrec_update, mysql_stmt_error(db->utm));
			break;
		}
		blkhdr->numtxs++;
		mysql_retv = mysql_stmt_fetch(db->qtm);
	}
	mysql_stmt_free_result(db->qtm);
	if (mysql_commit(db->mcon))
		logmsg(LOG_ERR, "Commit failed: %s\n", mysql_error(db->mcon));
}

int main(int argc, char *argv[])
{
	struct dbcon *dbinfo;
	int retv = 0;

	global_param_init(NULL, 0, 0);
	dbinfo = dbcon_init();
	if (!dbinfo)
		return 1;

	pack_txrec(dbinfo);

	dbcon_exit(dbinfo);
	global_param_exit();
	return retv;
}
