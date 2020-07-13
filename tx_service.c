#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <my_global.h>
#include <mysql.h>
#include <mysqld_error.h>
#include "global_param.h"
#include "loglog.h"
#include "sha256.h"
#include "ripemd160.h"
#include "wcomm.h"
#include "base64.h"
#include "txcheck.h"
#include "db_probe.h"

static volatile int global_exit = 0;

static void mysig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT || sig == SIGPIPE)
		global_exit = 1;
}

struct tokid_info {
	MYSQL_STMT *venmt, *catmt, *tokmt;
	const char *ven_query, *cat_query, *tok_query;
	unsigned long name_len, descp_len;
	unsigned int vid, catid, tokid;
	char name[16], descp[128];
};

static const char utxo_query[] = "SELECT value, txid, vout_idx FROM utxo " \
				  "WHERE keyhash = ? AND etoken_id = ? " \
				  "AND in_process = false AND blockid > 1";
struct utxo_info {
	MYSQL_STMT *qmt;
	const char *query;
	unsigned long txid_len, pkey_len;
	unsigned long value;
	char txid[SHA_DGST_LEN];
	char pkey[RIPEMD_LEN];
	unsigned int etoken_id;
	unsigned char vout_idx;
};

struct txrec_info {
	MYSQL *mcon;
	MYSQL_STMT *imt;
	struct tokid_info tokq;
	struct utxo_info utxo;
	struct txpack_op txop;
	MYSQL_BIND mbnd[3], rbnd[3];
	unsigned long txrec_len;
	struct wpacket wpkt;
} __attribute__((aligned(8)));

static inline void utxo_info_release(struct txrec_info *txp)
{
	struct utxo_info *utxo = &txp->utxo;

	mysql_stmt_close(utxo->qmt);
}

static int utxo_info_init(struct txrec_info *txp)
{
	struct utxo_info *utxo = &txp->utxo;
	int retv = 0;

	utxo->query = utxo_query;
	utxo->qmt = mysql_stmt_init(txp->mcon);
	if (!check_pointer(utxo->qmt))
		return -ENOMEM;
	if (mysql_stmt_prepare(utxo->qmt, utxo->query, strlen(utxo->query))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				utxo->query, mysql_stmt_error(utxo->qmt));
		retv = -mysql_stmt_errno(utxo->qmt);
		goto err_exit_10;
	}
	memset(txp->mbnd, 0, 2*sizeof(MYSQL_BIND));
	txp->mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txp->mbnd[0].buffer = utxo->pkey;
	txp->mbnd[0].buffer_length = RIPEMD_LEN;
	txp->mbnd[0].length = &utxo->pkey_len;
	txp->mbnd[1].buffer_type = MYSQL_TYPE_LONG;
	txp->mbnd[1].buffer = &utxo->etoken_id;
	txp->mbnd[1].is_unsigned = 1;
	if (mysql_stmt_bind_param(utxo->qmt, txp->mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				utxo->query, mysql_stmt_error(utxo->qmt));
		retv = -mysql_stmt_errno(utxo->qmt);
		goto err_exit_10;
	}
	memset(txp->rbnd, 0, 3*sizeof(MYSQL_BIND));
	txp->rbnd[0].buffer_type = MYSQL_TYPE_LONGLONG;
	txp->rbnd[0].buffer = &utxo->value;
	txp->rbnd[0].is_unsigned = 1;
	txp->rbnd[1].buffer_type = MYSQL_TYPE_BLOB;
	txp->rbnd[1].buffer = utxo->txid;
	txp->rbnd[1].buffer_length = SHA_DGST_LEN;
	txp->rbnd[1].length = &utxo->txid_len;
	txp->rbnd[2].buffer_type = MYSQL_TYPE_TINY;
	txp->rbnd[2].buffer = &utxo->vout_idx;
	txp->rbnd[2].is_unsigned = 1;
	if (mysql_stmt_bind_result(utxo->qmt, txp->rbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_result failed: %s, %s\n",
				utxo->query, mysql_stmt_error(utxo->qmt));
		retv = -mysql_stmt_errno(utxo->qmt);
		goto err_exit_10;
	}
	return retv;

err_exit_10:
	mysql_stmt_close(utxo->qmt);
	return retv;
}

static const char *vendor_query = "SELECT id, name, descp FROM vendors";
static const char *cat_query = "SELECT id, name, descp FROM etoken_cat " \
				"WHERE vendor_id = ?";
static const char *tok_query = "SELECT id, name, descp FROM etoken_type " \
				"WHERE cat_id = ?";

static inline void tokid_info_release(struct txrec_info *txp)
{
	struct tokid_info *tokq = &txp->tokq;

	mysql_stmt_close(tokq->tokmt);
	mysql_stmt_close(tokq->catmt);
	mysql_stmt_close(tokq->venmt);
}

static int tokid_info_init(struct txrec_info *txp)
{
	struct tokid_info *tokq = &txp->tokq;
	int retv = 0;

	tokq->ven_query = vendor_query;
	tokq->venmt = mysql_stmt_init(txp->mcon);
	if (!check_pointer(tokq->venmt))
		return -ENOMEM;
	if (mysql_stmt_prepare(tokq->venmt, tokq->ven_query,
				strlen(tokq->ven_query))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				tokq->ven_query, mysql_stmt_error(tokq->venmt));
		retv = -mysql_stmt_errno(tokq->venmt);
		goto err_exit_10;
	}
	memset(txp->rbnd, 0, 3*sizeof(MYSQL_BIND));
	txp->rbnd[0].buffer_type = MYSQL_TYPE_LONG;
	txp->rbnd[0].buffer = &tokq->vid;
	txp->rbnd[0].is_unsigned = 1;
	txp->rbnd[1].buffer_type = MYSQL_TYPE_STRING;
	txp->rbnd[1].buffer = tokq->name;
	txp->rbnd[1].buffer_length = sizeof(tokq->name);
	txp->rbnd[1].length = &tokq->name_len;
	txp->rbnd[2].buffer_type = MYSQL_TYPE_STRING;
	txp->rbnd[2].buffer = tokq->descp;
	txp->rbnd[2].buffer_length = sizeof(tokq->descp);
	txp->rbnd[2].length = &tokq->descp_len;
	if (mysql_stmt_bind_result(tokq->venmt, txp->rbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_result failed: %s, %s\n",
				tokq->ven_query,
				mysql_stmt_error(tokq->venmt));
		retv = -mysql_stmt_errno(tokq->venmt);
		goto err_exit_10;
	}

	tokq->cat_query = cat_query;
	tokq->catmt = mysql_stmt_init(txp->mcon);
	if (!check_pointer(tokq->catmt)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(tokq->catmt, tokq->cat_query,
				strlen(tokq->cat_query))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				tokq->cat_query, mysql_stmt_error(tokq->catmt));
		retv = -mysql_stmt_errno(tokq->catmt);
		goto err_exit_20;
	}
	memset(txp->mbnd, 0, sizeof(MYSQL_BIND));
	txp->mbnd[0].buffer_type = MYSQL_TYPE_LONG;
	txp->mbnd[0].buffer = &tokq->vid;
	txp->mbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(tokq->catmt, txp->mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				tokq->cat_query, mysql_stmt_error(tokq->catmt));
		retv = -mysql_stmt_errno(tokq->catmt);
		goto err_exit_20;
	}
	memset(txp->rbnd, 0, 3*sizeof(MYSQL_BIND));
	txp->rbnd[0].buffer_type = MYSQL_TYPE_LONG;
	txp->rbnd[0].buffer = &tokq->catid;
	txp->rbnd[0].is_unsigned = 1;
	txp->rbnd[1].buffer_type = MYSQL_TYPE_STRING;
	txp->rbnd[1].buffer = tokq->name;
	txp->rbnd[1].buffer_length = sizeof(tokq->name);
	txp->rbnd[1].length = &tokq->name_len;
	txp->rbnd[2].buffer_type = MYSQL_TYPE_STRING;
	txp->rbnd[2].buffer = tokq->descp;
	txp->rbnd[2].buffer_length = sizeof(tokq->descp);
	txp->rbnd[2].length = &tokq->descp_len;
	if (mysql_stmt_bind_result(tokq->catmt, txp->rbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_result failed: %s, %s\n",
				tokq->cat_query, mysql_stmt_error(tokq->catmt));
		retv = -mysql_stmt_errno(tokq->catmt);
		goto err_exit_20;
	}

	tokq->tok_query = tok_query;
	tokq->tokmt = mysql_stmt_init(txp->mcon);
	if (!check_pointer(tokq->tokmt)) {
		retv = -ENOMEM;
		goto err_exit_20;
	}
	if (mysql_stmt_prepare(tokq->tokmt, tokq->tok_query,
				strlen(tokq->tok_query))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				tokq->tok_query, mysql_stmt_error(tokq->tokmt));
		retv = -mysql_stmt_errno(tokq->tokmt);
		goto err_exit_30;
	}
	memset(txp->mbnd, 0, sizeof(MYSQL_BIND));
	txp->mbnd[0].buffer_type = MYSQL_TYPE_LONG;
	txp->mbnd[0].buffer = &tokq->catid;
	txp->mbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(tokq->tokmt, txp->mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				tokq->tok_query, mysql_stmt_error(tokq->catmt));
		retv = -mysql_stmt_errno(tokq->tokmt);
		goto err_exit_30;
	}
	memset(txp->rbnd, 0, 3*sizeof(MYSQL_BIND));
	txp->rbnd[0].buffer_type = MYSQL_TYPE_LONG;
	txp->rbnd[0].buffer = &tokq->tokid;
	txp->rbnd[0].is_unsigned = 1;
	txp->rbnd[1].buffer_type = MYSQL_TYPE_STRING;
	txp->rbnd[1].buffer = tokq->name;
	txp->rbnd[1].buffer_length = sizeof(tokq->name);
	txp->rbnd[1].length = &tokq->name_len;
	txp->rbnd[2].buffer_type = MYSQL_TYPE_STRING;
	txp->rbnd[2].buffer = tokq->descp;
	txp->rbnd[2].buffer_length = sizeof(tokq->descp);
	txp->rbnd[2].length = &tokq->descp_len;
	if (mysql_stmt_bind_result(tokq->tokmt, txp->rbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_result failed: %s, %s\n",
				tokq->tok_query, mysql_stmt_error(tokq->tokmt));
		retv = -mysql_stmt_errno(tokq->tokmt);
		goto err_exit_30;
	}
	return retv;

err_exit_30:
	mysql_stmt_close(tokq->tokmt);
err_exit_20:
	mysql_stmt_close(tokq->catmt);
err_exit_10:
	mysql_stmt_close(tokq->venmt);
	return retv;
}

static void txrec_info_release(struct txrec_info *txp)
{
	txpack_op_release(&txp->txop);
	mysql_stmt_close(txp->imt);
	tokid_info_release(txp);
	utxo_info_release(txp);
	mysql_close(txp->mcon);
}

static const char txid_insert[] = "INSERT INTO txrec_pool(txhash, txdata) " \
				  "VALUES(?, ?)";

static int txrec_info_init(struct txrec_info *txp, struct winfo *wif)
{
	int retv = 0;

	memset(txp, 0, sizeof(struct txrec_info));
	txp->mcon = mysql_init(NULL);
	if (!check_pointer(txp->mcon))
		return -ENOMEM;
	if (mysql_real_connect(txp->mcon, g_param->db.host, g_param->db.user,
				g_param->db.passwd, g_param->db.dbname, 0,
				NULL, 0) == NULL ) {
		logmsg(LOG_ERR, "mysql_real_connect failed: %s\n",
				mysql_error(txp->mcon));
		retv = -mysql_errno(txp->mcon);
		goto err_exit_10;
	}

	retv = utxo_info_init(txp);
	if (retv != 0) {
		logmsg(LOG_ERR, "Cannot initialize utxo_info: %d\n", retv);
		goto err_exit_10;
	}
	retv = tokid_info_init(txp);
	if (retv != 0)
		goto err_exit_20;

	txp->imt = mysql_stmt_init(txp->mcon);
	if (!check_pointer(txp->imt)) {
		retv = -ENOMEM;
		goto err_exit_30;
	}
	if (mysql_stmt_prepare(txp->imt, txid_insert, strlen(txid_insert))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				txid_insert, mysql_stmt_error(txp->imt));
		retv = -mysql_stmt_errno(txp->imt);
		goto err_exit_40;
	}
	memset(txp->mbnd, 0, 2*sizeof(MYSQL_BIND));
	txp->mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txp->mbnd[0].buffer = txp->utxo.txid;
	txp->mbnd[0].buffer_length = SHA_DGST_LEN;
	txp->mbnd[0].length = &txp->utxo.txid_len;
	txp->mbnd[1].buffer_type = MYSQL_TYPE_BLOB;
	txp->mbnd[1].buffer = wif->wpkt.pkt;
	txp->mbnd[1].buffer_length = MAX_TXSIZE - sizeof(struct winfo);
	txp->mbnd[1].length = &txp->txrec_len;
	if (mysql_stmt_bind_param(txp->imt, txp->mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				txid_insert, mysql_stmt_error(txp->imt));
		retv = -mysql_stmt_errno(txp->imt);
		goto err_exit_40;
	}
	if (txpack_op_init(&txp->txop, txp->mcon) != 0)
		goto err_exit_40;

	return retv;

err_exit_40:
	mysql_stmt_close(txp->imt);
err_exit_30:
	tokid_info_release(txp);
err_exit_20:
	utxo_info_release(txp);
err_exit_10:
	mysql_close(txp->mcon);
	return retv;
}

static int txrec_verify(int sock, const struct winfo *wif,
		struct txrec_info *txp)
{
	int suc, sqlerr, numb;
	struct sockaddr_in *sockaddr;
	FILE *fout;

	fout = fopen("/tmp/txrec-ser.dat", "wb");
	numb = fwrite(wif->wpkt.pkt, 1, wif->wpkt.len, fout);
	if (numb < wif->wpkt.len)
		logmsg(LOG_WARNING, "/tmp/txrec-ser.dat write failed.\n");
	fclose(fout);

	suc = 0;
	if (mysql_query(txp->mcon, "START TRANSACTION")) {
		logmsg(LOG_ERR, "Cannot START TRANSACTION: %s\n",
				mysql_error(txp->mcon));
		goto exit_10;
	}
	suc = tx_verify((const unsigned char *)wif->wpkt.pkt, wif->wpkt.len,
			&txp->txop);
	if (suc == 0)
		goto exit_20;

	sha256_dgst_2str((unsigned char *)txp->utxo.txid,
			(const unsigned char *)wif->wpkt.pkt, wif->wpkt.len);
	txp->utxo.txid_len = SHA_DGST_LEN;
	txp->txrec_len = wif->wpkt.len;
       	if (mysql_stmt_execute(txp->imt)) {
		sqlerr = mysql_stmt_errno(txp->imt);
		if (sqlerr == ER_DUP_ENTRY) {
			suc = 2;
		} else {
			suc = -1;
			logmsg(LOG_ERR, "mysql_execute failed: %s, %s\n",
					txid_insert, mysql_stmt_error(txp->imt));
		}
	}

exit_20:
	if (suc > 0) {
		if (mysql_query(txp->mcon, "COMMIT"))
			logmsg(LOG_ERR, "COMMIT failed: %s\n",
					mysql_error(txp->mcon));
	} else {
		if (mysql_query(txp->mcon, "ROLLBACK"))
			logmsg(LOG_ERR, "ROLLBACK failed: %s\n",
					mysql_error(txp->mcon));
	}
exit_10:
	txp->wpkt.ptype = suc;
	printf("Verified Result: %d\n", suc);
	txp->wpkt.len = SHA_DGST_LEN;
	sha256_dgst_2str((unsigned char *)txp->wpkt.pkt,
			(const unsigned char *)wif->wpkt.pkt, wif->wpkt.len);
	sockaddr = (struct sockaddr_in *)&wif->srcaddr;
	numb = sendto(sock, &txp->wpkt, sizeof(struct wpacket)+txp->wpkt.len, 0,
			(const struct sockaddr *)sockaddr,
			sizeof(struct sockaddr_in));
	if (numb == -1)
		logmsg(LOG_ERR, "sendto failed: %s\n", strerror(errno));
	return suc;
}

struct utxo_query {
	unsigned char len;
	char keyhash[0];
};

static int utxo_do_query(int sock, const struct winfo *wif,
		struct txrec_info *txp)
{
	unsigned char *ackval;
	const struct utxo_query *uq;
	unsigned int *etoken_id;
	char *curmsg;
	int mysql_retv, len, numb;
	struct wpacket *wpkt;
	struct sockaddr_in *sockaddr;
	struct utxo_info *utxo = &txp->utxo;

	wpkt = &txp->wpkt;
	etoken_id = (unsigned int *)wif->wpkt.pkt;
	utxo->etoken_id = *etoken_id;
	utxo->pkey_len = RIPEMD_LEN;
	curmsg = wpkt->pkt;

	len = 0;
	uq = (const struct utxo_query *)(wif->wpkt.pkt + sizeof(unsigned int));
	while (uq->len != 0) {
		assert(uq->len == RIPEMD_LEN);
		memcpy(utxo->pkey, uq->keyhash, uq->len);
		*curmsg = uq->len;
		memcpy(curmsg+1, uq->keyhash, uq->len);
		curmsg += uq->len + 1;
		len += uq->len + 1;
		ackval = (unsigned char *)curmsg;
		if (mysql_stmt_execute(utxo->qmt)) {
			logmsg(LOG_ERR, "mysql_execute failed: %s, %s\n",
					utxo->query,
					mysql_stmt_error(utxo->qmt));
		} else {
			mysql_stmt_store_result(utxo->qmt);
			mysql_retv = mysql_stmt_fetch(utxo->qmt);
			while (mysql_retv != MYSQL_NO_DATA) {
				memcpy(ackval, &utxo->value, sizeof(unsigned long));
				curmsg += sizeof(unsigned long);
				len += sizeof(unsigned long);
				assert(utxo->txid_len == SHA_DGST_LEN);
				*curmsg = utxo->txid_len;
				memcpy(curmsg+1, utxo->txid, utxo->txid_len);
				curmsg += utxo->txid_len + 1;
				len += utxo->txid_len + 1;
				*curmsg = utxo->vout_idx;
				curmsg += 1;
				len += 1;
				mysql_retv = mysql_stmt_fetch(utxo->qmt);
				ackval = (unsigned char *)curmsg;
			}
			mysql_stmt_free_result(utxo->qmt);
		}
		memset(ackval, 0, sizeof(unsigned long));
		len += sizeof(unsigned long);
		curmsg += sizeof(unsigned long);
		uq = (const struct utxo_query *)(((const char *)(uq + 1)) + uq->len);
	}
	wpkt->len = len;
	wpkt->ptype = 1;
	sockaddr = (struct sockaddr_in *)&wif->srcaddr;
	numb = sendto(sock, wpkt, sizeof(struct wpacket)+wpkt->len, 0,
			(const struct sockaddr *)sockaddr,
			sizeof(struct sockaddr_in));
	if (numb == -1)
		logmsg(LOG_ERR, "sendto failed: %s\n", strerror(errno));
	return 0;
}

static int vendor_do_query(int sock, const struct winfo *wif,
		struct txrec_info *txp)
{
	unsigned char *curmsg;
	int mysql_retv, len, numb, rem;
	struct wpacket *wpkt;
	struct sockaddr_in *sockaddr;
	struct tokid_info *tokq = &txp->tokq;
	unsigned int *vid;

	wpkt = &txp->wpkt;
	curmsg = (unsigned char *)wpkt->pkt;
	numb = 0;
	len = 0;

	if (mysql_stmt_execute(tokq->venmt)) {
		logmsg(LOG_ERR, "mysql_execute_failed: %s->%s\n",
				tokq->ven_query,
				mysql_stmt_error(tokq->venmt));
		goto exit_100;
	}
	if (mysql_stmt_store_result(tokq->venmt)) {
		logmsg(LOG_ERR, "mysql_store_result failed: %s->%s\n",
				tokq->ven_query,
				mysql_stmt_error(tokq->venmt));
		goto exit_100;
	}
	mysql_retv = mysql_stmt_fetch(tokq->venmt);
	while (mysql_retv != MYSQL_NO_DATA) {
		vid = (unsigned int *)curmsg;
		*vid = tokq->vid;
		curmsg += sizeof(*vid);
		len += sizeof(*vid);
		*curmsg = tokq->name_len;
		curmsg += 1;
		len += 1;
		memcpy(curmsg, tokq->name, tokq->name_len);
		curmsg += tokq->name_len;
		len += tokq->name_len;
		*curmsg = tokq->descp_len;
		curmsg += 1;
		len += 1;
		memcpy(curmsg, tokq->descp, tokq->descp_len);
		curmsg += tokq->descp_len;
		len += tokq->descp_len;
		rem = (unsigned long)curmsg & 3;
		if (rem) {
			curmsg += 4 - rem;
			len += 4 - rem;
			assert((len & 3) == 0);
		}

		mysql_retv = mysql_stmt_fetch(tokq->venmt);
	}

exit_100:
	vid = (unsigned int *)curmsg;
	*vid = 0;
	len += sizeof(*vid);
	wpkt->len = len;
	wpkt->ptype = 1;
	sockaddr = (struct sockaddr_in *)&wif->srcaddr;
	numb = sendto(sock, wpkt, sizeof(struct wpacket)+wpkt->len, 0,
			(const struct sockaddr *)sockaddr,
			sizeof(struct sockaddr_in));
	if (numb == -1)
		logmsg(LOG_ERR, "sendto failed: %s\n", strerror(errno));
	return 0;
}

static int cat_do_query(int sock, const struct winfo *wif,
		struct txrec_info *txp)
{
	char *curmsg;
	int mysql_retv, len, numb, rem;
	struct wpacket *wpkt;
	struct sockaddr_in *sockaddr;
	struct tokid_info *tokq = &txp->tokq;
	unsigned int *catid, *vid;

	wpkt = &txp->wpkt;
	curmsg = wpkt->pkt;
	numb = 0;
	len = 0;

	vid = (unsigned int *)wif->wpkt.pkt;
	tokq->vid = *vid;
	if (mysql_stmt_execute(tokq->catmt)) {
		logmsg(LOG_ERR, "mysql_execute_failed: %s->%s\n",
				tokq->cat_query,
				mysql_stmt_error(tokq->catmt));
		goto exit_100;
	}
	if (mysql_stmt_store_result(tokq->catmt)) {
		logmsg(LOG_ERR, "mysql_store_result failed: %s->%s\n",
				tokq->cat_query,
				mysql_stmt_error(tokq->catmt));
		goto exit_100;
	}
	mysql_retv = mysql_stmt_fetch(tokq->catmt);
	while (mysql_retv != MYSQL_NO_DATA) {
		catid = (unsigned int *)curmsg;
		*catid = tokq->catid;
		curmsg += sizeof(*catid);
		len += sizeof(*catid);
		*curmsg = tokq->name_len;
		curmsg += 1;
		len += 1;
		memcpy(curmsg, tokq->name, tokq->name_len);
		curmsg += tokq->name_len;
		len += tokq->name_len;
		*curmsg = tokq->descp_len;
		curmsg += 1;
		len += 1;
		memcpy(curmsg, tokq->descp, tokq->descp_len);
		curmsg += tokq->descp_len;
		len += tokq->descp_len;
		rem = ((unsigned long)curmsg) & 3;
		if (rem) {
			curmsg += 4 - rem;
			len += 4 -rem;
			assert((len & 3) == 0);
		}

		mysql_retv = mysql_stmt_fetch(tokq->catmt);
	}
	mysql_stmt_free_result(tokq->catmt);

exit_100:
	catid = (unsigned int *)curmsg;
	*catid = 0;
	len += sizeof(*catid);
	wpkt->len = len;
	wpkt->ptype = 1;
	sockaddr = (struct sockaddr_in *)&wif->srcaddr;
	numb = sendto(sock, wpkt, sizeof(struct wpacket)+wpkt->len, 0,
			(const struct sockaddr *)sockaddr,
			sizeof(struct sockaddr_in));
	if (numb == -1)
		logmsg(LOG_ERR, "sendto failed: %s\n", strerror(errno));
	return 0;
}

static int tok_do_query(int sock, const struct winfo *wif,
		struct txrec_info *txp)
{
	char *curmsg;
	int mysql_retv, len, numb, rem;
	struct wpacket *wpkt;
	struct sockaddr_in *sockaddr;
	struct tokid_info *tokq = &txp->tokq;
	unsigned int *catid, *tokid;

	wpkt = &txp->wpkt;
	curmsg = wpkt->pkt;
	numb = 0;
	len = 0;

	catid = (unsigned int *)wif->wpkt.pkt;
	tokq->catid = *catid;
	if (mysql_stmt_execute(tokq->tokmt)) {
		logmsg(LOG_ERR, "mysql_execute_failed: %s->%s\n",
				tokq->tok_query,
				mysql_stmt_error(tokq->tokmt));
		goto exit_100;
	}
	if (mysql_stmt_store_result(tokq->tokmt)) {
		logmsg(LOG_ERR, "mysql_store_result failed: %s->%s\n",
				tokq->tok_query,
				mysql_stmt_error(tokq->tokmt));
		goto exit_100;
	}
	mysql_retv = mysql_stmt_fetch(tokq->tokmt);
	while (mysql_retv != MYSQL_NO_DATA) {
		tokid = (unsigned int *)curmsg;
		*tokid = tokq->tokid;
		curmsg += sizeof(*tokid);
		len += sizeof(*tokid);
		*curmsg = tokq->name_len;
		curmsg += 1;
		len += 1;
		memcpy(curmsg, tokq->name, tokq->name_len);
		curmsg += tokq->name_len;
		len += tokq->name_len;
		*curmsg = tokq->descp_len;
		curmsg += 1;
		len += 1;
		memcpy(curmsg, tokq->descp, tokq->descp_len);
		curmsg += tokq->descp_len;
		len += tokq->descp_len;
		rem = (unsigned long)curmsg & 3;
		if (rem) {
			curmsg += 4 - rem;
			len += 4 - rem;
			assert((len & 3) == 0);
		}

		mysql_retv = mysql_stmt_fetch(tokq->tokmt);
	}
	mysql_stmt_free_result(tokq->tokmt);

exit_100:
	tokid = (unsigned int *)curmsg;
	*tokid = 0;
	len += sizeof(*tokid);
	wpkt->len = len;
	wpkt->ptype = 1;
	sockaddr = (struct sockaddr_in *)&wif->srcaddr;
	numb = sendto(sock, wpkt, sizeof(struct wpacket)+wpkt->len, 0,
			(const struct sockaddr *)sockaddr,
			sizeof(struct sockaddr_in));
	if (numb == -1)
		logmsg(LOG_ERR, "sendto failed: %s\n", strerror(errno));
	return 0;
}

static inline int notify_tx_logging(int pipd)
{
	int numb, pingpong = 1;


	numb = write(pipd, &pingpong, sizeof(pingpong));
	if (numb == -1)
		logmsg(LOG_ERR, "Cannot write to pipe: %d -> %s\n", errno,
				strerror(errno));
	return numb;
}

void *tx_process(void *arg)
{
	struct wcomm *wm = arg;
	int rc, verified, secs;
	struct timespec tm, pbtm;
	const struct winfo *cwif;
	struct winfo *wif;
	struct txrec_info *txp;
	int pret;

	wif = malloc(2*g_param->tx.max_txsize+sizeof(struct txrec_info));
	if (!check_pointer(wif))
		return NULL;
	txp= (struct txrec_info *)(((unsigned char *)wif) + g_param->tx.max_txsize);
	if (txrec_info_init(txp, wif) != 0)
		goto exit_5;

	pbtm.tv_sec = 0;
	do {
		pthread_mutex_lock(&wm->wmtx);
		clock_gettime(CLOCK_REALTIME, &tm);
		tm.tv_sec += 1;
		rc = 0;
		secs = 0;
		while (global_exit == 0 && wcomm_empty(wm) &&
				(rc == 0 || rc == ETIMEDOUT)) {
			rc = pthread_cond_timedwait(&wm->wcd, &wm->wmtx, &tm);
			tm.tv_sec += 1;
			if (rc == ETIMEDOUT) {
				secs += 1;
				if (secs >= g_param->db.probe) {
					secs = 0;
					pret = check_db_probe(txp->mcon, &pbtm);
					if (pret < 0)
						global_exit = 1;
				}
			}
		}
		if (unlikely(rc != 0 && rc != ETIMEDOUT)) {
			logmsg(LOG_ERR, "pthread_cond_timedwait failed: %s\n",
					strerror(rc));
			global_exit = 1;
			pthread_mutex_unlock(&wm->wmtx);
			continue;
		}
		cwif = NULL;
		if (!wcomm_empty(wm)) {
			cwif = wcomm_getload(wm);
			memcpy(wif, cwif, sizeof(struct winfo) + cwif->wpkt.len);
			wcomm_tail_inc(wm);
		}
		pthread_mutex_unlock(&wm->wmtx);
		if (!cwif)
			continue;
		switch(wif->wpkt.ptype) {
		case TX_REC:
			printf("Before Verify\n");
			verified = txrec_verify(wm->sock, wif, txp);
			if (verified == 1 && wm->pipd != -1) {
				if (notify_tx_logging(wm->pipd) == -1)
					global_exit = 1;
			} else if (verified < 0)
				global_exit = 1;
			break;
		case UTXO_REQ:
			utxo_do_query(wm->sock, wif, txp);
			break;
		case VEN_REQ:
			vendor_do_query(wm->sock, wif, txp);
			break;
		case TOKEN_CAT_REQ:
			cat_do_query(wm->sock, wif, txp);
			break;
		case TOKEN_ID_REQ:
			tok_do_query(wm->sock, wif, txp);
		default:
			;
		}
	} while (global_exit == 0);

	txrec_info_release(txp);
exit_5:
	free(wif);
	global_exit = 1;
	return NULL;
}

int tx_recv(int port, struct wcomm *wm)
{
	int sd, sysret, buflen, numb;
	socklen_t saddr_len;
	struct addrinfo ahint, *resaddr;
	struct sockaddr_in *sin_addr;
	char portnum[8];
	struct winfo *wif;
	struct pollfd pfd[1];

	memset(pfd, 0, sizeof(pfd));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (unlikely(sd == -1)) {
		logmsg(LOG_ERR, "Cannot create a UDP socket: %s\n",
				strerror(errno));
		return -errno;
	}
	pfd[0].fd = sd;
	pfd[0].events = POLLIN;

	sprintf(portnum, "%d", port);
	memset(&ahint, 0, sizeof(ahint));
	ahint.ai_flags = AI_PASSIVE;
	ahint.ai_family = AF_INET;
	ahint.ai_socktype = SOCK_DGRAM;
	sysret = getaddrinfo(NULL, portnum, &ahint, &resaddr);
	if (unlikely(sysret != 0)) {
		logmsg(LOG_ERR, "getaddrinfo failed: %s\n", strerror(errno));
		close(sd);
		return -errno;
	}
	sin_addr = (struct sockaddr_in *)resaddr->ai_addr;
	printf("Port number: %d\n", (int)ntohs(sin_addr->sin_port));
	sysret = bind(sd, resaddr->ai_addr, resaddr->ai_addrlen);
	if (sysret != 0) {
		logmsg(LOG_ERR, "bind failed: %s\n", strerror(errno));
		freeaddrinfo(resaddr);
		close(sd);
		return -errno;
	}
	freeaddrinfo(resaddr);
	wm->sock = sd;
	buflen = MAX_TXSIZE - sizeof(struct sockaddr_storage);
	do {
		wif = wcomm_getarea(wm);
		saddr_len = sizeof(wif->srcaddr);
		do {
			pfd[0].revents = 0;
			sysret = poll(pfd, 1, 800);
			if (sysret == 0)
				continue;
			else if (sysret == -1 && errno != EINTR) {
				logmsg(LOG_ERR, "poll error: %s\n",
						strerror(errno));
				global_exit = 1;
			}
		} while ((pfd[0].revents & POLLIN) == 0 && global_exit == 0);
		if (global_exit)
			break;
		numb = recvfrom(sd, &wif->wpkt, buflen, 0,
				(struct sockaddr *)&wif->srcaddr, &saddr_len);
		if (numb == -1) {
		       	if (errno != EINTR) {
				logmsg(LOG_ERR, "recvfrom error: %s\n",
						strerror(errno));
				global_exit = 1;
			}
			continue;
		} else if (numb == wif->wpkt.len + sizeof(struct wpacket))
			wcomm_signal(wm);
		else
			logmsg(LOG_ERR, "NULL or truncated packet received!\n");
	} while (global_exit == 0);
	close(sd);
	return 0;
}

int main(int argc, char *argv[])
{
	struct wcomm *wm;
	int retv, sysret;
	struct sigaction sigact;
	pthread_t rcvthd;
	const char *conf;

	if (argc > 1)
		conf = argv[1];
	else
		conf = "/etc/etoken.conf";
	global_param_init(conf);
	wm = wcomm_init();
	if (!wm) {
		global_param_exit();
		return 1;
	}
	if (argc > 2)
		wm->pipd = atoi(argv[2]);
	else
		wm->pipd = -1;

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = mysig_handler;
	sysret = sigaction(SIGTERM, &sigact, NULL);
	if (unlikely(sysret == -1))
		logmsg(LOG_WARNING, "Cannot install signal handler for " \
				"SIGTERM: %s\n", strerror(errno));
	sysret = sigaction(SIGINT, &sigact, NULL);
	if (unlikely(sysret == -1))
		logmsg(LOG_WARNING, "Cannot install signal handler for " \
				"SIGINT: %s\n", strerror(errno));

	sysret = pthread_create(&rcvthd, NULL, tx_process, wm);
	if (sysret) {
		logmsg(LOG_ERR, "pthread create failed: %s\n",
				strerror(errno));
		retv = 3;
		goto exit_10;
	}

	retv = tx_recv(g_param->netp.port, wm);
	if (retv < 0) {
		retv = -retv;
		global_exit = 1;
	}

	pthread_join(rcvthd, NULL);

exit_10:
	wcomm_exit(wm);
	global_param_exit();
	return retv;
}
