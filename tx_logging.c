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

struct dbcon {
	MYSQL *mcon;
	MYSQL_STMT *txrec_qtm, *txrec_utm, *txrec_dtm;
	MYSQL_STMT *blk_itm, *blk_q0tm, *blk_q1tm;
	const char *txrec_query, *txrec_update, *txrec_del;
	const char *blk_lastid, *blk_last, *blk_insert;
	unsigned char *block;
	unsigned char sha_dgst[SHA_DGST_LEN];
	unsigned long shalen, blklen, blkid;
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
static const char blk_lastid[] = "SELECT MAX(blockid) FROM blockchain";
static const char blk_last[] = "SELECT hdr_hash FROM blockchain where" \
				       " blockid = ?";
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
	db->txrec_qtm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->txrec_qtm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->txrec_qtm, db->txrec_query,
				strlen(db->txrec_query))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->txrec_query,
				mysql_stmt_error(db->txrec_qtm));
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
	if (mysql_stmt_bind_result(db->txrec_qtm, db->resbind)) {
		logmsg(LOG_ERR, "bind result failed: %s\n",
				mysql_stmt_error(db->txrec_qtm));
		retv = -4;
		goto err_exit_10;
	}

	db->txrec_utm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->txrec_utm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->txrec_utm, db->txrec_update,
				strlen(db->txrec_update))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->txrec_update,
				mysql_stmt_error(db->txrec_utm));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, sizeof(MYSQL_BIND));
	db->pmbind[0].buffer_type = MYSQL_TYPE_LONG;
	db->pmbind[0].buffer = &db->seq;
	db->pmbind[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(db->txrec_utm, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				db->txrec_update,
				mysql_stmt_error(db->txrec_utm));
		retv = -4;
		goto err_exit_10;
	}

	db->txrec_dtm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->txrec_dtm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->txrec_dtm, db->txrec_del,
				strlen(db->txrec_del))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->txrec_del, mysql_stmt_error(db->txrec_dtm));
		retv = -3;
		goto err_exit_10;
	}
	if (mysql_stmt_bind_param(db->txrec_dtm, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				db->txrec_del, mysql_stmt_error(db->txrec_dtm));
		retv = -4;
		goto err_exit_10;
	}

	db->blk_q0tm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->blk_q0tm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->blk_q0tm, db->blk_lastid,
				strlen(db->blk_lastid))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->blk_lastid, mysql_stmt_error(db->blk_q0tm));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->resbind, 0, sizeof(MYSQL_BIND));
	db->resbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	db->resbind[0].buffer = &db->blkid;
	db->resbind[0].is_unsigned = 1;
	if (mysql_stmt_bind_result(db->blk_q0tm, db->resbind)) {
		logmsg(LOG_ERR, "Cannot bind result: %s, %s\n", db->blk_lastid,
				mysql_stmt_error(db->blk_q0tm));
		goto err_exit_10;
	}

	db->blk_q1tm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->blk_q1tm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->blk_q1tm, db->blk_last,
				strlen(db->blk_last))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->blk_last, mysql_stmt_error(db->blk_q1tm));
		retv = -3;
		goto err_exit_10;
	}
	memset(db->pmbind, 0, sizeof(MYSQL_BIND));
	db->pmbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
	db->pmbind[0].buffer = &db->blkid;
	db->pmbind[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(db->blk_q1tm, db->pmbind)) {
		logmsg(LOG_ERR, "Cannot bind Param: %s, %s\n", db->blk_last,
				mysql_stmt_error(db->blk_q1tm));
		goto err_exit_10;
	}
	memset(db->resbind, 0, sizeof(MYSQL_BIND));
	db->resbind[0].buffer_type = MYSQL_TYPE_BLOB;
	db->resbind[0].buffer = db->sha_dgst;
	db->resbind[0].buffer_length = SHA_DGST_LEN;
	db->resbind[0].length = &db->shalen;
	if (mysql_stmt_bind_result(db->blk_q1tm, db->resbind)) {
		logmsg(LOG_ERR, "Cannot bind Param: %s, %s\n", db->blk_last,
				mysql_stmt_error(db->blk_q1tm));
		goto err_exit_10;
	}

	db->blk_itm = mysql_stmt_init(db->mcon);
	if (!check_pointer(db->blk_itm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(db->blk_itm, db->blk_insert,
				strlen(db->blk_insert))) {
		logmsg(LOG_ERR, "Prepare Statement Failed: %s, %s\n",
				db->blk_insert, mysql_stmt_error(db->blk_itm));
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
	if (mysql_stmt_bind_param(db->blk_itm, db->pmbind)) {
		logmsg(LOG_ERR, "Param Bind failed: %s, %s\n",
				db->blk_insert, mysql_stmt_error(db->blk_itm));
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
	if (db->txrec_qtm) {
		mysql_stmt_close(db->txrec_qtm);
		db->txrec_qtm = NULL;
	}
	if (db->txrec_utm) {
		mysql_stmt_close(db->txrec_utm);
		db->txrec_utm = NULL;
	}
	if (db->txrec_dtm) {
		mysql_stmt_close(db->txrec_dtm);
		db->txrec_dtm = NULL;
	}
	if (db->blk_q0tm) {
		mysql_stmt_close(db->blk_q0tm);
		db->blk_q0tm = NULL;
	}
	if (db->blk_q1tm) {
		mysql_stmt_close(db->blk_q1tm);
		db->blk_q1tm = NULL;
	}
	if (db->blk_itm) {
		mysql_stmt_close(db->blk_itm);
		db->blk_itm = NULL;
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
	dbinfo->blk_lastid = blk_lastid;
	dbinfo->blk_last = blk_last;
	dbinfo->blk_insert = blk_insert;

	dbinfo->txbuf = madr + sizeof(struct dbcon);
	dbinfo->block = madr + sizeof(struct dbcon) + g_param->tx.max_txsize;

	if (dbcon_connect(dbinfo)) {
		dbcon_exit(dbinfo);
		dbinfo = NULL;
	}

	return dbinfo;
}

static inline int blk_get_last(struct dbcon *db)
{
	int retv = 0, mysql_retv;

	memset(db->sha_dgst, 0, SHA_DGST_LEN);
	if (mysql_stmt_execute(db->blk_q0tm)) {
		logmsg(LOG_ERR, "Cannot execute %s: %s\n", db->blk_lastid,
				mysql_stmt_error(db->blk_q0tm));
		return -1;
	}
	mysql_retv = mysql_stmt_fetch(db->blk_q0tm);
	mysql_stmt_free_result(db->blk_q0tm);
	if (mysql_retv) {
		logmsg(LOG_ERR, "Cannot get the last block ID: %s\n",
				mysql_stmt_error(db->blk_q0tm));
		return -1;
	}

	if (mysql_stmt_execute(db->blk_q1tm)) {
		logmsg(LOG_ERR, "Cannot execute %s: %s\n", db->blk_last,
				mysql_stmt_error(db->blk_q1tm));
		return -1;
	}
	mysql_retv = mysql_stmt_fetch(db->blk_q1tm);
	mysql_stmt_free_result(db->blk_q1tm);
	if (mysql_retv) {
		logmsg(LOG_ERR, "Cannot get the last block header: %s\n",
				mysql_stmt_error(db->blk_q1tm));
		retv = -1;
	}
	return retv;
}

static int pack_txrec(struct dbcon *db)
{
	int mysql_retv, pos;
	struct txrec_area *txbuf;
	struct bl_header *blkhdr;

	blkhdr = (struct bl_header *)db->block;
	if (blk_get_last(db) != 0)
		return 0;
	bl_header_init(blkhdr, db->sha_dgst);

	pos = sizeof(struct bl_header);
	txbuf = (struct txrec_area *)(db->block + pos);
	if (mysql_query(db->mcon, "START TRANSACTION")) {
		logmsg(LOG_ERR, "Cannot start a transaction: %s\n",
				mysql_error(db->mcon));
		return 0;
	}
	if (mysql_stmt_execute(db->txrec_qtm)) {
		logmsg(LOG_ERR, "failed to do txrec_pool query: %s\n",
				mysql_stmt_error(db->txrec_qtm));
		return 0;
	}

	if (mysql_stmt_store_result(db->txrec_qtm)) {
		logmsg(LOG_ERR, "Store result failed: %s, %s\n", txrec_query,
				mysql_stmt_error(db->txrec_qtm));
		mysql_stmt_free_result(db->txrec_qtm);
	}
	mysql_retv = mysql_stmt_fetch(db->txrec_qtm);
	while (mysql_retv != MYSQL_NO_DATA &&
			pos + sizeof(struct txrec_area) + db->txbuf->txlen <
			g_param->mine.max_blksize)  {
		txrec_area_copy(txbuf, db->txbuf);
		pos += sizeof(struct txrec_area) + txbuf->txlen;
		txbuf = (struct txrec_area *)(db->block + pos);
		if (mysql_stmt_execute(db->txrec_utm)) {
			logmsg(LOG_ERR, "Statement Execution %s failed: %s\n",
					txrec_update,
					mysql_stmt_error(db->txrec_utm));
			break;
		}
		blkhdr->numtxs++;
		mysql_retv = mysql_stmt_fetch(db->txrec_qtm);
	}
	mysql_stmt_free_result(db->txrec_qtm);
	if (mysql_commit(db->mcon))
		logmsg(LOG_ERR, "Commit failed: %s\n", mysql_error(db->mcon));
	if (mysql_query(db->mcon, "COMMIT"))
		logmsg(LOG_ERR, "Commit failed: %s\n", mysql_error(db->mcon));

	return blkhdr->numtxs;
}

static const char txcount_query[] = "SELECT COUNT(*) FROM txrec_pool WHERE " \
				    "in_process = 0";
int main(int argc, char *argv[])
{
	struct dbcon *dbinfo;
	int retv = 0, numtx, sysret, mysql_retv;
	unsigned long txcount;
	struct sigaction act;
	MYSQL_STMT *ctm;
	MYSQL_BIND resbnd[1];
	struct timespec intvl;


	memset(&act, 0, sizeof(act));
	act.sa_handler = msig_handler;
	sysret = sigaction(SIGINT, &act, NULL);
	if (sysret == -1)
		logmsg(LOG_ERR, "Cannot install signal handler: %s\n",
				strerror(errno));
	sysret = sigaction(SIGINT, &act, NULL);
	if (sysret == -1)
		logmsg(LOG_ERR, "Cannot install signal handler: %s\n",
				strerror(errno));

	global_param_init(NULL, 0, 0);
	dbinfo = dbcon_init();
	if (!dbinfo) {
		global_param_exit();
		return 1;
	}

	ctm = mysql_stmt_init(dbinfo->mcon);
	if (!check_pointer(ctm)) {
		logmsg(LOG_ERR, "Cannot get a statement handle: %s\n",
				mysql_error(dbinfo->mcon));
		retv = 2;
		goto exit_10;
	}
	if (mysql_stmt_prepare(ctm, txcount_query, strlen(txcount_query))) {
		logmsg(LOG_ERR, "Cannot prepare %s: %s\n", txcount_query,
				mysql_stmt_error(ctm));
		retv = 2;
		goto exit_20;
	}
	memset(resbnd, 0, sizeof(resbnd));
	resbnd[0].buffer_type = MYSQL_TYPE_LONGLONG;
	resbnd[0].buffer = &txcount;
	resbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_result(ctm, resbnd)) {
		logmsg(LOG_ERR, "Cannot bind result, %s: %s\n", txcount_query,
				mysql_stmt_error(ctm));
		retv = 2;
		goto exit_20;
	}

	intvl.tv_sec = 1;
	intvl.tv_nsec = 0;
	do {
		if (mysql_stmt_execute(ctm)) {
			logmsg(LOG_ERR, "Cannot execute %s: %s\n",
					txcount_query, mysql_stmt_error(ctm));
			retv = 2;
			goto exit_20;
		}
		mysql_stmt_store_result(ctm);
		mysql_retv = mysql_stmt_fetch(ctm);
		mysql_stmt_free_result(ctm);
		if (mysql_retv) {
			logmsg(LOG_ERR, "No result from %s: %s\n",
					txcount_query, mysql_stmt_error(ctm));
			retv = 3;
			goto exit_20;
		}
		if (txcount == 0) {
			nanosleep(&intvl, NULL);
			continue;
		}
		numtx = pack_txrec(dbinfo);
		printf("Total TX records packed: %d\n", numtx);
		if (numtx == 0)
			continue;
	} while (global_exit == 0);

exit_20:
	mysql_stmt_close(ctm);
exit_10:
	dbcon_exit(dbinfo);
	global_param_exit();
	return retv;
}
