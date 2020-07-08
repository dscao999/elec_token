#include <my_global.h>
#include <mysql.h>
#include <string.h>
#include "loglog.h"
#include "virtmach.h"
#include "global_param.h"
#include "tok_block.h"
#include "txcheck.h"


int txpack_op_init(struct txpack_op *txop, MYSQL *mcon)
{
	static const char utxo_query[] = "SELECT blockid, in_process FROM utxo " \
					  "WHERE txid = ? AND vout_idx = ? " \
					  "FOR UPDATE";
	static const char blk_query[] = "SELECT blockdata, hdr_hash FROM " \
					"blockchain  WHERE blockid = ?";
	static const char utxo_update[] = "UPDATE utxo SET in_process = 1 " \
					   "WHERE txid = ? AND vout_idx = ?";
	static const char sale_query[] = "SELECT lockscript FROM sales " \
					  "WHERE keyhash = ? AND etoken_id = ?";
	int retv = 0;

	txop->blkbuf = malloc(g_param->mine.max_blksize);
	if (!check_pointer(txop->blkbuf))
		return -ENOMEM;

	txop->mcon = mcon;
	txop->utxo_query = utxo_query;
	txop->uqtm = mysql_stmt_init(mcon);
	if (!check_pointer(txop->uqtm)) {
		retv = -ENOMEM;
		goto err_exit_5;
	}
	if (mysql_stmt_prepare(txop->uqtm, txop->utxo_query,
				strlen(txop->utxo_query))) {
		logmsg(LOG_ERR, "SQL statement preparation failed: %s->%s\n",
				txop->utxo_query, mysql_stmt_error(txop->uqtm));
		retv = -mysql_stmt_errno(txop->uqtm);
		goto err_exit_10;
	}
	memset(txop->mbnd, 0, 2*sizeof(MYSQL_BIND));
	txop->mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txop->mbnd[0].buffer = txop->txid;
	txop->mbnd[0].buffer_length = SHA_DGST_LEN;
	txop->mbnd[0].length = &txop->txid_len;
	txop->mbnd[1].buffer_type = MYSQL_TYPE_TINY;
	txop->mbnd[1].buffer = &txop->vout_idx;
	txop->mbnd[1].is_unsigned = 1;
	if (mysql_stmt_bind_param(txop->uqtm, txop->mbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind param failed: %s->%s\n",
				txop->utxo_query, mysql_stmt_error(txop->uqtm));
		retv = -mysql_stmt_errno(txop->uqtm);
		goto err_exit_10;
	}
	memset(txop->rbnd, 0, 2*sizeof(MYSQL_BIND));
	txop->rbnd[0].buffer_type = MYSQL_TYPE_LONGLONG;
	txop->rbnd[0].buffer = &txop->blockid;
	txop->rbnd[0].is_unsigned = 1;
	txop->rbnd[1].buffer_type = MYSQL_TYPE_TINY;
	txop->rbnd[1].buffer = &txop->in_process;
	txop->rbnd[1].is_unsigned = 1;
	if (mysql_stmt_bind_result(txop->uqtm, txop->rbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind result failed: %s->%s\n",
				txop->utxo_query, mysql_stmt_error(txop->uqtm));
		retv = -mysql_stmt_errno(txop->uqtm);
		goto err_exit_10;
	}

	txop->blk_query = blk_query;
	txop->bqtm = mysql_stmt_init(mcon);
	if (!check_pointer(txop->bqtm)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(txop->bqtm, txop->blk_query,
				strlen(txop->blk_query))) {
		logmsg(LOG_ERR, "SQL Statement preparation failed: %s->%s\n",
				txop->blk_query, mysql_stmt_error(txop->bqtm));
		retv = -mysql_stmt_errno(txop->bqtm);
		goto err_exit_20;
	}
	memset(txop->mbnd, 0, sizeof(MYSQL_BIND));
	txop->mbnd[0].buffer_type = MYSQL_TYPE_LONGLONG;
	txop->mbnd[0].buffer = &txop->blockid;
	txop->mbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_param(txop->bqtm, txop->mbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind param failed: %s->%s\n",
				txop->blk_query, mysql_stmt_error(txop->bqtm));
		retv = -mysql_stmt_errno(txop->bqtm);
		goto err_exit_20;
	}
	memset(txop->rbnd, 0, 2*sizeof(MYSQL_BIND));
	txop->rbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txop->rbnd[0].buffer = txop->blkbuf;
	txop->rbnd[0].buffer_length = g_param->mine.max_blksize;
	txop->rbnd[0].length = &txop->blk_len;
	txop->rbnd[1].buffer_type = MYSQL_TYPE_BLOB;
	txop->rbnd[1].buffer = txop->hdr_hash;
	txop->rbnd[1].buffer_length = SHA_DGST_LEN;
	txop->rbnd[1].length = &txop->hdrhash_len;
	if (mysql_stmt_bind_result(txop->bqtm, txop->rbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind result failed: %s->%s\n",
				txop->blk_query, mysql_stmt_error(txop->bqtm));
		retv = -mysql_stmt_errno(txop->bqtm);
		goto err_exit_20;
	}

	txop->utxo_update = utxo_update;
	txop->uutm = mysql_stmt_init(mcon);
	if (!check_pointer(txop->uutm)) {
		retv = -ENOMEM;
		goto err_exit_20;
	}
	if (mysql_stmt_prepare(txop->uutm, txop->utxo_update,
				strlen(txop->utxo_update))) {
		logmsg(LOG_ERR, "SQL Statement preparation failed: %s->%s\n",
				txop->utxo_update, mysql_stmt_error(txop->uutm));
		retv = -mysql_stmt_errno(txop->uutm);
		goto err_exit_30;
	}
	memset(txop->mbnd, 0, 2*sizeof(MYSQL_BIND));
	txop->mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txop->mbnd[0].buffer = txop->txid;
	txop->mbnd[0].buffer_length = SHA_DGST_LEN;
	txop->mbnd[0].length = &txop->txid_len;
	txop->mbnd[1].buffer_type = MYSQL_TYPE_TINY;
	txop->mbnd[1].buffer = &txop->vout_idx;
	txop->mbnd[1].is_unsigned = 1;
	if (mysql_stmt_bind_param(txop->uutm, txop->mbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind param failed: %s->%s\n",
				txop->utxo_update, mysql_stmt_error(txop->uutm));
		retv = -mysql_stmt_errno(txop->uutm);
		goto err_exit_30;
	}

	txop->sale_query = sale_query;
	txop->sqtm = mysql_stmt_init(mcon);
	if (!check_pointer(txop->sqtm)) {
		retv = -ENOMEM;
		goto err_exit_30;
	}
	if (mysql_stmt_prepare(txop->sqtm, txop->sale_query,
				strlen(txop->sale_query))) {
		logmsg(LOG_ERR, "SQL Statement preparation failed: %s->%s\n",
				txop->sale_query, mysql_stmt_error(txop->sqtm));
		retv = -mysql_stmt_errno(txop->sqtm);
		goto err_exit_40;
	}
	memset(txop->mbnd, 0, 2*sizeof(MYSQL_BIND));
	txop->mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txop->mbnd[0].buffer = txop->txid;
	txop->mbnd[0].buffer_length = SHA_DGST_LEN;
	txop->mbnd[0].length = &txop->txid_len;
	txop->mbnd[1].buffer_type = MYSQL_TYPE_LONG;
	txop->mbnd[1].buffer = &txop->etoken_id;
	txop->mbnd[1].is_unsigned = 1;
	if (mysql_stmt_bind_param(txop->sqtm, txop->mbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind param failed: %s->%s\n",
				txop->sale_query, mysql_stmt_error(txop->sqtm));
		retv = -mysql_stmt_errno(txop->sqtm);
		goto err_exit_40;
	}
	memset(txop->rbnd, 0, sizeof(MYSQL_BIND));
	txop->rbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txop->rbnd[0].buffer = txop->blkbuf;
	txop->rbnd[0].buffer_length = g_param->mine.max_blksize;
	txop->rbnd[0].length = &txop->blk_len;
	if (mysql_stmt_bind_result(txop->sqtm, txop->rbnd)) {
		logmsg(LOG_ERR, "SQL Statement bind result failed: %s->%s\n",
				txop->sale_query, mysql_stmt_error(txop->sqtm));
		retv = -mysql_stmt_errno(txop->sqtm);
		goto err_exit_40;
	}

	return retv;

err_exit_40:
	mysql_stmt_close(txop->sqtm);
err_exit_30:
	mysql_stmt_close(txop->uutm);
err_exit_20:
	mysql_stmt_close(txop->bqtm);
err_exit_10:
	mysql_stmt_close(txop->uqtm);
err_exit_5:
	free(txop->blkbuf);
	return retv;
}

static int tx_getlock(const struct tx_etoken_in *txin, struct txpack_op *txop)
{
	const struct etk_block *blk;
	const struct bl_header *blkhdr;
	const struct txrec_area *txarea;
	struct txrec *tx;
	int tx_idx, numret, retv = 0, i;
	struct tx_etoken_out *vout;

	txop->value = 0;
	txop->lock = NULL;
	txop->lock_len = 0;
	txop->blockid = 0;
	memcpy(txop->txid, txin->txid, SHA_DGST_LEN);
	txop->txid_len = SHA_DGST_LEN;
	txop->vout_idx = txin->vout_idx;
	if (mysql_stmt_execute(txop->uqtm)) {
		logmsg(LOG_ERR, "Statement Execution failed: %s->%s\n",
				txop->utxo_query, mysql_stmt_error(txop->uqtm));
		retv = -mysql_stmt_errno(txop->uqtm);
		goto exit_10;
	}
	if (mysql_stmt_store_result(txop->uqtm)) {
		logmsg(LOG_ERR, "Statement Store Result failed: %s->%s\n",
				txop->utxo_query, mysql_stmt_error(txop->uqtm));
		retv = -mysql_stmt_errno(txop->uqtm);
		goto exit_10;
	}
	numret = 0;
	while (mysql_stmt_fetch(txop->uqtm) != MYSQL_NO_DATA) {
		if (txop->blockid > 1 && txop->in_process == 0)
			numret += 1;
	}
	mysql_stmt_free_result(txop->uqtm);
	if (numret == 0) {
		logmsg(LOG_ERR, "Not such utxo as vout: %d and txid: ",
				txop->vout_idx);
		for (i = 0; i < SHA_DGST_LEN; i++)
			logmsg(LOG_ERR, "%02hhX ", txop->txid[i]);
		logmsg(LOG_ERR, "\n");
		retv = -1;
		goto exit_10;
	}
	assert(numret == 1);
	if (mysql_stmt_execute(txop->uutm)) {
		logmsg(LOG_ERR, "Statement Execution failed: %s->%s\n",
				txop->utxo_update, mysql_stmt_error(txop->uutm));
		retv = -mysql_stmt_errno(txop->uutm);
		goto exit_10;
	}
	if (mysql_stmt_execute(txop->bqtm)) {
		logmsg(LOG_ERR, "Statement Execution failed: %s->%s\n",
				txop->blk_query, mysql_stmt_error(txop->bqtm));
		retv = -mysql_stmt_errno(txop->bqtm);
		goto exit_10;
	}
	if (mysql_stmt_store_result(txop->bqtm)) {
		logmsg(LOG_ERR, "Statement Execution Failed: %s->%s\n",
				txop->blk_query, mysql_stmt_error(txop->bqtm));
		retv = -mysql_stmt_errno(txop->bqtm);
		goto exit_10;
	}
	numret = 0;
	while (mysql_stmt_fetch(txop->bqtm) != MYSQL_NO_DATA) {
		numret += 1;
		assert(txop->hdrhash_len == SHA_DGST_LEN);
	}
	mysql_stmt_free_result(txop->bqtm);
	assert(numret == 1);
	if (txop->blk_len == 0) {
		logmsg(LOG_ERR, "Invalid block Retrieved!\n");
		retv = -2;
		goto exit_10;
	}
	blk = txop->blkbuf;
	blkhdr = txop->blkbuf;
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
	txop->value = vout->etk.value;
	txop->lock_len = vout->lock_len;
	txop->lock = malloc(vout->lock_len);
	if (check_pointer(txop->lock))
		memcpy(txop->lock, vout->lock, vout->lock_len);
	tx_destroy(tx);

exit_10:
	return retv;
}

static int tx_sales_query(const char *khash, int eid, struct txpack_op *txop)
{
	int retv = 0;

	txop->value = 0;
	txop->lock = NULL;
	txop->lock_len = 0;

	strcpy((char *)txop->txid, khash);
	txop->txid_len = strlen(khash);
	txop->etoken_id = eid;
	txop->blk_len = 0;
	if (mysql_stmt_execute(txop->sqtm)) {
		logmsg(LOG_ERR, "Statement execution failed: %s->%s\n",
				txop->sale_query, mysql_stmt_error(txop->sqtm));
		retv = -mysql_stmt_errno(txop->sqtm);
		goto exit_10;
	}
	if (mysql_stmt_store_result(txop->sqtm)) {
		logmsg(LOG_ERR, "Statement store result failed: %s->%s\n",
				txop->sale_query, mysql_stmt_error(txop->sqtm));
		retv = -mysql_stmt_errno(txop->sqtm);
		goto exit_10;
	}

	if (mysql_stmt_fetch(txop->sqtm) != MYSQL_NO_DATA) {
		assert(txop->blk_len != 0);
		txop->value = 0xfffffffffffffffful;
		txop->lock = malloc(txop->blk_len);
		if (check_pointer(txop->lock)) {
			txop->lock_len = txop->blk_len;
			memcpy(txop->lock, txop->blkbuf, txop->lock_len);
		}
	}
	mysql_stmt_free_result(txop->sqtm);

exit_10:
	return retv;
}

static int tx_vin_getlock(const struct tx_etoken_in *txin,
		unsigned int eid, struct txpack_op *txop)
{
	struct ecc_key ekey;
	char khash[32];
	int len;

	if (txin->gensis != 0x0ff)
		return tx_getlock(txin, txop);

	memcpy(ekey.px, txin->txid, SHA_DGST_LEN);
	ecc_get_public_y(&ekey, txin->odd);
	len = ecc_key_hash(khash, 32, &ekey);
	khash[len] = 0;
	return tx_sales_query(khash, eid, txop);
}

int tx_verify(const unsigned char *txrec, int len, struct txpack_op *txop)
{
	int i, suc, retv, txbuf_len;
	const struct tx_etoken_in *txin, **txins;
	const struct tx_etoken_out *txout, **txouts;
	const struct etoken *petk;
	unsigned long out_val = 0, in_val = 0;
	struct vmach *vm;
	struct txrec *tx;
	char *txbuf;

	suc = 0;
	tx = tx_deserialize((const char *)txrec, len);
	if (tx == NULL)
		return suc;

	txbuf = malloc(g_param->tx.max_txsize);
	if (!check_pointer(txbuf))
		goto exit_10;

	txouts = (const struct tx_etoken_out **)tx->vouts;
	petk = &(*txouts)->etk;
	for (i = 0; *txouts && i < tx->vout_num; i++, txouts++) {
		txout = *txouts;
		if (!etoken_equiv(&txout->etk, petk))
			return suc;
		out_val += txout->etk.value;
	}
	vm = vmach_init();
	if (!check_pointer(vm))
		goto exit_20;

	txbuf_len = tx_serialize(txbuf, g_param->tx.max_txsize, tx, 0);
	txins = (const struct tx_etoken_in **)tx->vins;
	suc = 1;
	for(i = 0; i < tx->vin_num; i++, txins++) {
		txin = *txins;
		retv = vmach_execute(vm, txin->unlock, txin->unlock_len,
				NULL, 0);
		if (retv <= 0) {
			suc = 0;
			break;
		}
		retv = tx_vin_getlock(txin, petk->token_id, txop);
		in_val += txop->value;
		if (!txop->lock) {
		       	if (vmach_success(vm))
				continue;
			suc = 0;
			break;
		}
		retv = vmach_execute(vm, txop->lock, txop->lock_len,
				(const unsigned char *)txbuf, txbuf_len);
		free(txop->lock);
		if (retv <= 0 || (!vmach_stack_empty(vm) &&
					!vmach_success(vm))) {
			suc = 0;
			break;
		}
	}
	if (in_val < out_val)
		suc = 0;

	vmach_exit(vm);
exit_20:
	free(txbuf);
exit_10:
	tx_destroy(tx);
	return suc;
}
