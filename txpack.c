#include <my_global.h>
#include <mysql.h>
#include <string.h>
#include "loglog.h"
#include "toktx_svr.h"
#include "virtmach.h"
#include "global_param.h"

#define SCRATCH_LEN     4096

static unsigned char *tx_sales_query(const char *khash, int eid, int *lock_len)
{
	char *query, *res, *pkhash, *lock;
	int qsize, mysql_retv, res_count;
	MYSQL *mcon;
	MYSQL_STMT *mstmt;
	MYSQL_BIND pbind[2], rbind[1];
	unsigned int etok_id = eid;
	ulong64 blob_len, khash_len;
	int lsize;

	qsize = 1024;
	query = malloc(qsize*2+64);
	res = query + qsize;
	pkhash = res + qsize;
	strcpy(query, "select lockscript from sales " \
	       	"where keyhash = ? and etoken_id = ?");

	mcon = mysql_init(NULL);
	if (!check_pointer(mcon))
		return NULL;
	if (mysql_real_connect(mcon, g_param->db.host, g_param->db.user,
			g_param->db.passwd, g_param->db.dbname, 0, NULL, 0) == NULL) {
		logmsg(LOG_ERR, "mysql connect failed: %s\n", mysql_error(mcon));
		goto err_exit_10;
	}
	mstmt = mysql_stmt_init(mcon);
	if (!check_pointer(mstmt))
		goto err_exit_10;
	mysql_retv = mysql_stmt_prepare(mstmt, query, strlen(query));
	if (mysql_retv) {
		logmsg(LOG_ERR, "Statement preparation failed: %s\n",
				mysql_stmt_error(mstmt));
		goto err_exit_20;
	}
	strcpy(pkhash, khash);
	khash_len = strlen(pkhash);
	memset(pbind, 0, sizeof(pbind));
	pbind[0].buffer_type = MYSQL_TYPE_STRING;
	pbind[0].buffer = pkhash;
	pbind[0].buffer_length = khash_len;
	pbind[0].length = &khash_len;
	pbind[1].buffer_type = MYSQL_TYPE_LONG;
	pbind[1].buffer = &etok_id;
	pbind[1].is_unsigned = 1;
	mysql_retv = mysql_stmt_bind_param(mstmt, pbind);
	if (mysql_retv) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s\n",
				mysql_stmt_error(mstmt));
		goto err_exit_20;
	}
	memset(rbind, 0, sizeof(rbind));
	rbind[0].buffer_type = MYSQL_TYPE_BLOB;
	rbind[0].buffer = res;
	rbind[0].buffer_length = qsize;
	rbind[0].length = &blob_len;
	mysql_retv = mysql_stmt_bind_result(mstmt, rbind);
	if (mysql_retv) {
		logmsg(LOG_ERR, "mysql_stmt_bind_result failed: %s\n",
				mysql_stmt_error(mstmt));
		goto err_exit_20;
	}
	if (mysql_stmt_execute(mstmt)) {
		logmsg(LOG_ERR, "mysql_execute failed: %s\n", mysql_stmt_error(mstmt));
		goto err_exit_20;
	}
	res_count = 0;
	*lock_len = 0;
	lsize = 128;
	lock = malloc(lsize);
	while ((mysql_retv = mysql_stmt_fetch(mstmt)) == 0) {
		if (blob_len > lsize) {
			lsize = blob_len;
			lock = realloc(lock, lsize);
		}
		memcpy(lock, res, blob_len);
		*lock_len = blob_len;
		res_count++;
	}
	if (mysql_retv != MYSQL_NO_DATA)
		logmsg(LOG_ERR, "mysql_stmt_fech failed: data truncated\n");
	if (res_count > 1)
		logmsg(LOG_ERR, "More than two lock scripts for %s, " \
				"use the last one.\n", pkhash);
	else if (res_count < 1) {
		free(lock);
		lock = NULL;
	}

	mysql_stmt_close(mstmt);
	mysql_close(mcon);
	free(query);
	return (unsigned char *)lock;

err_exit_20:
	mysql_stmt_close(mstmt);
err_exit_10:
	mysql_close(mcon);
	free(query);
	return NULL;
}

static unsigned char *tx_vin_getlock(const struct tx_etoken_in *txin, int eid,
		int *lock_len, ulong64 *val)
{
	struct ecc_key ekey;
	char khash[32];
	int len;
	unsigned char *lock;

	*lock_len = 0;
	if (txin->gensis != 0x0ff) {
		if (tx_from_blockchain)
			return tx_from_blockchain(txin, lock_len, val);
		else
			return NULL;
	}

	*val = 0xfffffffffffffffful;
	memcpy(ekey.px, txin->txid, SHA_DGST_LEN);
	ecc_get_public_y(&ekey, txin->odd);
	len = ecc_key_hash(khash, 32, &ekey);
	khash[len] = 0;
	lock = tx_sales_query(khash, eid, lock_len);
	return lock;
}

int tx_verify(const unsigned char *txrec, int len)
{
	int i, lock_len, suc, retv;
	const struct tx_etoken_in *txin, **txins;
	const struct tx_etoken_out *txout, **txouts;
	const struct etoken *petk;
	unsigned char *lock = NULL;
	ulong64 out_val = 0, in_val = 0;
	struct vmach *vm;
	struct txrec *tx;

	suc = 0;
	tx = tx_deserialize((const char *)txrec, len);
	if (tx == NULL)
		return suc;

	txouts = (const struct tx_etoken_out **)tx->vouts;
	petk = &(*txouts)->etk;
	for (i = 0; *txouts && i < tx->vout_num; i++, txouts++) {
		txout = *txouts;
		if (!etoken_equiv(&txout->etk, petk))
			return suc;
		out_val += txout->etk.value;
	}

	suc = 1;
	vm = vmach_init();
	txins = (const struct tx_etoken_in **)tx->vins;
	for(i = 0; i < tx->vin_num; i++, txins++) {
		txin = *txins;
		retv = vmach_execute(vm, txin->unlock, txin->unlock_len, NULL, 0);
		if (retv <= 0) {
			suc = 0;
			break;
		}
		lock = tx_vin_getlock(txin, petk->token_id, &lock_len, &in_val);
		if (!lock) {
		       	if (vmach_success(vm))
				continue;
			suc = 0;
			break;
		}
		retv = vmach_execute(vm, lock, lock_len, txrec, len);
		free(lock);
		if (retv <= 0 || (!vmach_stack_empty(vm) &&
					!vmach_success(vm))) {
			suc = 0;
			break;
		}
	}

	vmach_exit(vm);
	if (in_val < out_val)
		suc = 0;
	return suc;
}

static void tx_get_vout_owner(unsigned char *owner, const unsigned char *lock,
		int lock_len)
{
	const unsigned char *opcode;
       	unsigned char opc;

	opcode = lock;
	while (opcode - lock < lock_len) {
		opc = *opcode++;
		if (opc != OP_DUP)
			continue;
		opc = *opcode++;
		if (opc != OP_RIPEMD160)
			continue;
		break;
	}
	if ((int)(opcode - lock) + RIPEMD_LEN + 1 <= lock_len) {
		assert(*opcode == RIPEMD_LEN);
		memcpy(owner, opcode+1, RIPEMD_LEN);
	} else
		memset(owner, 0, RIPEMD_LEN);
}

int tx_get_vout(const struct txrec *tx, struct txrec_vout *vo)
{
	const struct tx_etoken_out *vout;

	if (vo->vout_idx >= tx->vout_num)
		return 0;
	vout = *(tx->vouts + vo->vout_idx);
	vo->eid = vout->etk.token_id;
	vo->value = vout->etk.value;
	if (vout->lock_len == 0)
		memset(vo->owner, 0, RIPEMD_LEN);
	else
		tx_get_vout_owner(vo->owner, vout->lock, vout->lock_len);

	return 1;
}
