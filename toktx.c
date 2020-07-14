#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include "loglog.h"
#include "tokens.h"
#include "toktx.h"
#include "virtmach_code.h"
#include "base64.h"

#define TOKEN_TX_VER	0x01

void tx_trans_abort(ulong64 txptr)
{
	struct txrec *tx;

	tx = (struct txrec *)txptr;
	tx_destroy(tx);
}

void tx_destroy(struct txrec *tx)
{
	struct tx_etoken_in **txins, *txin;
	struct tx_etoken_out **txouts, *txout;
	int i, nitem;

	if (!tx)
		return;

	if (tx->vins) {
		txins = tx->vins;
		nitem = tx->vin_num;
		for (i = 0; i < nitem && *txins; i++, txins++) {
			txin = *txins;
			if (txin->unlock)
				free(txin->unlock);
			free(txin);
		}
		free(tx->vins);
	}
	if (tx->vouts) {
		nitem = tx->vout_num;
		txouts = tx->vouts;
		for (i = 0; i < nitem && *txouts; i++, txouts++) {
			txout = *txouts;
			etoken_option_del(&txout->etk);
			if (txout->lock)
				free(txout->lock);
			free(txout);
		}
		free(tx->vouts);
	}

	free(tx);
}

static int tx_sign(char *buf, int buflen, const struct txrec *tx, int vin_idx,
		const struct ecc_key *ecckey)
{
	int txlen, pos;
	struct tx_etoken_in *vin;
	struct ecc_sig eccsig;

	txlen = tx_serialize(buf, buflen, tx, 0);
	assert(txlen <= buflen);
	ecc_sign(&eccsig, ecckey, (const unsigned char *)buf, txlen);
	vin = *(tx->vins + vin_idx);
	vin->unlock_len = sizeof(struct ecc_sig) + ECCKEY_INT_LEN * 4 + 4;
	vin->unlock = malloc(vin->unlock_len);
	if (!check_pointer(vin->unlock))
		return -ENOMEM;
	vin->unlock[0] = sizeof(struct ecc_sig);
	memcpy(vin->unlock+1, &eccsig, sizeof(struct ecc_sig));
	pos = sizeof(struct ecc_sig) + 1;
	vin->unlock[pos] = ECCKEY_INT_LEN * 4 + 1;
	vin->unlock[pos+1] = 2 - (ecckey->py[ECCKEY_INT_LEN-1] & 1);
	memcpy(vin->unlock+pos+2, ecckey->px, ECCKEY_INT_LEN * 4);
	pos += ECCKEY_INT_LEN * 4 + 2;
	vin->unlock[pos] = OP_CALCULATE_Y;
	assert(pos + 1 == vin->unlock_len);
	return 0;
}

struct txrec *tx_create(int tkid, ulong64 value, int days,
		const char *payto, const struct ecc_key *ecckey)
{
	int buflen, retv;
	struct timespec tm;
	struct tx_etoken_in *vin;
	struct tx_etoken_out *vout;
	void *pool;
	char *buf;
	struct txrec *tx;

	tx = malloc(sizeof(struct txrec));
	if(!check_pointer(tx))
		return NULL;
	tx->ver = TOKEN_TX_VER;
	tx->vin_num = 1;
	tx->vout_num = 1;
	clock_gettime(CLOCK_REALTIME_COARSE, &tm);
	tx->tm = tm.tv_sec;
	tx->vins = NULL;
	tx->vouts = NULL;

	tx->vins = malloc(sizeof(struct tx_etoken_in *));
	if (!check_pointer(tx->vins))
		goto err_exit_10;

	tx->vouts = malloc(sizeof(struct tx_etoken_out *));
	if (!check_pointer(tx->vouts))
		goto err_exit_10;

	pool = malloc(2048);
	if (!check_pointer(pool))
		goto err_exit_10;
	buf = pool;
	buflen = 2048;

	*tx->vins = malloc(sizeof(struct tx_etoken_in));
	if (!check_pointer(*tx->vins))
		goto err_exit_20;

	vin = *tx->vins;
	memset(vin, 0, sizeof(struct tx_etoken_in));

	vin->odd = 2 - (ecckey->py[ECCKEY_INT_LEN-1] & 1);
	vin->gensis = 0xff;
	memcpy(vin->txid, ecckey->px, SHA_DGST_LEN);
	vin->unlock_len = 0;
	vin->unlock = NULL;

	*tx->vouts = malloc(sizeof(struct tx_etoken_out));
	if (!check_pointer(*tx->vouts))
		goto err_exit_20;
	vout = *tx->vouts;
	memset(vout, 0, sizeof(struct tx_etoken_out));
	etoken_init(&vout->etk, tkid, value, days);
	vout->lock_len = 25;
	vout->lock = malloc(25);
	if (!check_pointer(vout->lock))
		goto err_exit_20;
	vout->lock[0] = OP_DUP;
	vout->lock[1] = OP_RIPEMD160;
	vout->lock[2] = RIPEMD_LEN;
	vout->lock[23] = OP_EQUALVERIFY;
	vout->lock[24] = OP_CHECKSIG;
	retv = str2bin_b64(vout->lock+3, RIPEMD_LEN, payto);
	if (retv != RIPEMD_LEN) {
		logmsg(LOG_ERR, "Invalid public key hash.\n");
		goto err_exit_30;
	}
	retv = tx_sign(buf, buflen, tx, 0, ecckey);
	if (retv != 0)
		goto err_exit_30;

	free(pool);
	return tx;

err_exit_30:
	free(vout->lock);
err_exit_20:
	free(pool);
err_exit_10:
	tx_destroy(tx);
	return NULL;
}

static inline int tx_etoken_in_length(const struct tx_etoken_in *txin, int with_unlock)
{
	int len;
	
	len = sizeof(struct tx_etoken_in);
	if (with_unlock)
		len += txin->unlock_len;
	return align8(len);
}

static inline int tx_etoken_out_length(const struct tx_etoken_out *txout)
{
	int len;

	len = sizeof(struct tx_etoken_out) +
		etoken_option_length(&txout->etk) + txout->lock_len;
	return align8(len);
}

int tx_serialize(char *buf, int buflen, const struct txrec *tx, int with_unlock)
{
	int txlen, numitem, i, rlen, pos;
	struct tx_etoken_in **txins, *txin;
	struct tx_etoken_out **txouts, *txout;
	struct txrec *tx_ser;
	char *txin_ser, *txout_ser;

	txlen = align8(sizeof(struct txrec));
	numitem = tx->vin_num;
	txins = tx->vins;
	for (i = 0; i < numitem; i++, txins++) {
		txin = *txins;
		txlen += tx_etoken_in_length(txin, with_unlock);
	}
	txouts = tx->vouts;
	numitem = tx->vout_num;
	for (i = 0; i < numitem; i++, txouts++) {
		txout = *txouts;
		txlen += tx_etoken_out_length(txout);
	}
	if (buflen < txlen)
		return txlen;
	memset(buf, 0, txlen);

	tx_ser = (struct txrec *)buf;
	*tx_ser = *tx;
	tx_ser->vins = NULL;
	tx_ser->vouts = NULL;

	txins = tx->vins;
	txin_ser = buf + sizeof(struct txrec);
	numitem = tx->vin_num;
	for (i = 0; i < numitem; i++, txins++) {
		txin = *txins;
		memcpy(txin_ser, txin, sizeof(struct tx_etoken_in));
		if (with_unlock && txin->unlock)
			memcpy(txin_ser+sizeof(struct tx_etoken_in),
					txin->unlock, txin->unlock_len);
		((struct tx_etoken_in *)txin_ser)->unlock = NULL;
		if (with_unlock == 0)
			((struct tx_etoken_in *)txin_ser)->unlock_len = 0;
		txin_ser += tx_etoken_in_length(txin, with_unlock);
	}
	txouts = tx->vouts;
	txout_ser = txin_ser;
	numitem = tx->vout_num;
	for (i = 0; i < numitem; i++, txouts++) {
		txout = *txouts;
		memcpy(txout_ser, txout, sizeof(struct tx_etoken_out));
		((struct tx_etoken_out *)txout_ser)->lock = NULL;
		((struct tx_etoken_out *)txout_ser)->etk.options = NULL;
		pos = sizeof(struct tx_etoken_out);
		rlen = etoken_option_serialize(txout_ser+pos,
				buflen - (int)(txout_ser - buf), &txout->etk);
		pos += rlen;
		if (txout->lock)
			memcpy(txout_ser+pos, txout->lock, txout->lock_len);
		txout_ser += tx_etoken_out_length(txout);
	}
	return txlen;
}

struct txrec *tx_deserialize(const char *buf, int buflen)
{
	struct txrec *tx;
	struct tx_etoken_in **txins, *txin;
	struct tx_etoken_out **txouts, *txout;
	const struct txrec *buftx;
	const char *buf_txin, *buf_txout;
	int i, nitem, pos, sumpos, len;

	sumpos = 0;
	tx = malloc(sizeof(struct txrec));
	if (!check_pointer(tx))
		return NULL;
	buftx = (const struct txrec *)buf;
	if (buflen < sizeof(struct txrec)) {
		logmsg(LOG_ERR, "Illformed tx record.\n");
		goto err_exit_10;
	}
	memcpy(tx, buftx, sizeof(struct txrec));
	assert(tx->vins == NULL && tx->vouts == NULL);
	sumpos += sizeof(struct txrec);
	tx->vins = NULL;
	tx->vouts = NULL;

	tx->vins = malloc(sizeof(struct tx_etoken_in *)*tx->vin_num);
	if (!check_pointer(tx->vins)) {
		logmsg(LOG_ERR, "Out of Memory. \n");
		goto err_exit_10;
	}
	tx->vouts = malloc(sizeof(struct tx_etoken_out *)*tx->vout_num);
	if (!check_pointer(tx->vouts)) {
		logmsg(LOG_ERR, "Out of Memory.\n");
		goto err_exit_10;
	}
	memset(tx->vins, 0, sizeof(struct tx_etoken_in *)*tx->vin_num);
	memset(tx->vouts, 0, sizeof(struct tx_etoken_out *)*tx->vout_num);

	nitem = tx->vin_num;
	txins = tx->vins;
	buf_txin = buf + sumpos;
	for (i = 0; i < nitem; i++, txins++) {
		if (sumpos + sizeof(struct tx_etoken_in) > buflen)
			goto err_exit_10;
		txin = malloc(sizeof(struct tx_etoken_in));
		*txins = txin;
		if (!check_pointer(txin))
			goto err_exit_10;
		memcpy(txin, buf_txin, sizeof(struct tx_etoken_in));
		assert(txin->unlock == NULL);
		pos = sizeof(struct tx_etoken_in);
		if (txin->unlock_len != 0) {
			if (sumpos + pos + txin->unlock_len > buflen) {
				logmsg(LOG_ERR, "Illformed tx record.\n");
				goto err_exit_10;
			}
			txin->unlock = malloc(txin->unlock_len);
			if (!check_pointer(txin->unlock))
				goto err_exit_10;
			memcpy(txin->unlock, buf_txin+pos, txin->unlock_len);
		}
		buf_txin += tx_etoken_in_length(txin, 1);
		sumpos += tx_etoken_in_length(txin, 1);
	}
	nitem = tx->vout_num;
	txouts = tx->vouts;
	buf_txout = buf_txin;
	for (i = 0; i < nitem; i++, txouts++) {
		if (sumpos + sizeof(struct tx_etoken_out) > buflen)
			goto err_exit_10;
		txout = malloc(sizeof(struct tx_etoken_out));
		*txouts = txout;
		if (!check_pointer(txout))
			goto err_exit_10;
		pos = sizeof(struct tx_etoken_out);
		memcpy(txout, buf_txout, pos);
		assert(txout->lock == NULL);
		len = etoken_option_deserialize(buf_txout+pos,
				buflen - sumpos - pos, &txout->etk);
		if (len < 0)
			goto err_exit_10;
		pos += len;
		if (txout->lock_len > 0) {
			if (sumpos + pos + txout->lock_len > buflen)
				goto err_exit_10;
			txout->lock = malloc(txout->lock_len);
			if (!check_pointer(txout->lock))
				goto err_exit_10;
			memcpy(txout->lock, buf_txout+pos, txout->lock_len);
		}
		buf_txout += tx_etoken_out_length(txout);
		sumpos += tx_etoken_out_length(txout);
	}

	return tx;

err_exit_10:
	tx_destroy(tx);
	return NULL;
}

int tx_create_token(char *buf, int buflen, int tkid, ulong64 value,
		int days, const char *payto, const struct ecc_key *ecckey)
{
	int txlen;
	struct txrec *tx;

	tx = tx_create(tkid, value, days, payto, ecckey);
	if (!check_pointer(tx))
		return -ENOMEM;
	txlen = tx_serialize(buf, buflen, tx, 1);
	tx_destroy(tx);
	if (txlen > buflen)
		logmsg(LOG_WARNING, "Not enough buffer space for new token.\n");
	return txlen;
}

static int tx_vout_set_lock(struct tx_etoken_out *vout, const unsigned char *payto)
{
	vout->lock_len = 25;
	vout->lock = malloc(25);
	if (!check_pointer(vout->lock))
		return -ENOMEM;
	vout->lock[0] = OP_DUP;
	vout->lock[1] = OP_RIPEMD160;
	vout->lock[2] = RIPEMD_LEN;
	memcpy(vout->lock+3, payto, RIPEMD_LEN);
	vout->lock[23] = OP_EQUALVERIFY;
	vout->lock[24] = OP_CHECKSIG;
	return 0;
}

static int tx_vout_set(struct tx_etoken_out *vout, int tokid,
		ulong64 value, const unsigned char *payto)
{
	int retv;

	retv = tx_vout_set_lock(vout, payto);
	if (retv != 0)
		return retv;
	etoken_init(&vout->etk, tokid, value, 0);
	return retv;
}

static int tx_vout_copy(struct tx_etoken_out *vout, const struct etoken *cet,
		ulong64 value, const unsigned char *payto)
{
	int retv;

	retv = tx_vout_set_lock(vout, payto);
	if (retv != 0)
		return retv;
	etoken_clone(&vout->etk, cet, value);
	return retv;
}

static void txrec_init(struct txrec *tx)
{
	struct timespec tm;

	memset(tx, 0, sizeof(struct txrec));
	tx->ver = TOKEN_TX_VER;
	clock_gettime(CLOCK_REALTIME, &tm);
	tx->tm = tm.tv_sec;
}

static void tx_tryerror(const struct txrec *tx)
{
	char *buf;
	struct txrec *mtx;
	int len;

	buf = malloc(2048);
	len = tx_serialize(buf, 2048, tx, 0);
	mtx = tx_deserialize(buf, len);
	if (!mtx)
		goto exit_10;
	tx_destroy(mtx);

	len = tx_serialize(buf, 2048, tx, 1);
	mtx = tx_deserialize(buf, len);
	if (!mtx)
		goto exit_10;
	len = tx_serialize(buf, 2048, mtx, 1);
	tx_destroy(mtx);
	
exit_10:
	free(buf);
}

int tx_trans_begin(struct txrec **ptr, unsigned int tokid,
		ulong64 value, const unsigned char *payto)
{
	int retv = 0;
	struct txrec *txptr;
	struct tx_etoken_out *vout;

	txptr = malloc(sizeof(struct txrec));
	if (!check_pointer(txptr)) {
		*ptr = NULL;
		return -ENOMEM;
	}
	txrec_init(txptr);
	vout = malloc(sizeof(struct tx_etoken_out));
	if (!check_pointer(vout)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}

	retv = tx_vout_set(vout, tokid, value, payto);
	if (retv != 0)
		goto err_exit_20;

	txptr->vout_num = 1;
	txptr->vouts = malloc(sizeof(struct tx_etoken_out **));
	if (!check_pointer(txptr->vouts)) {
		retv = -ENOMEM;
		goto err_exit_30;
	}
	*txptr->vouts = vout;
	*ptr = txptr;

	tx_tryerror(txptr);

	return retv;

err_exit_30:
	free(vout->lock);
err_exit_20:
	free(vout);
err_exit_10:
	free(txptr);
	*ptr = NULL;
	return retv;
}

int tx_trans_add(ulong64 txptr, unsigned char *txid, int vout_idx)
{
	int retv = 0, i;
	struct tx_etoken_in *vin, **vins, **p_vins, **c_vins;
	struct txrec *tx = (struct txrec *)txptr;

	vin = malloc(sizeof(struct tx_etoken_in));
	if (!check_pointer(vin))
		return -ENOMEM;
	memset(vin, 0, sizeof(struct tx_etoken_in));
	vin->vout_idx = vout_idx;
	memcpy(vin->txid, txid, SHA_DGST_LEN);

	vins = malloc((tx->vin_num+1)*sizeof(struct tx_etoken_in **));
	if (!check_pointer(vins)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	p_vins = tx->vins;
	c_vins = vins;
	for( i = 0; i < tx->vin_num; i++)
		*c_vins++ = *p_vins++;
	*c_vins = vin;
	if (tx->vins)
		free(tx->vins);
	tx->vins = vins;
	tx->vin_num += 1;

	tx_tryerror(tx);
	return retv;

err_exit_10:
	free(vin);
	return retv;
}

int tx_trans_sup(ulong64 txptr, ulong64 value,
		const unsigned char *payto)
{
	int retv = 0, i;
	struct txrec *tx = (struct txrec *)txptr;
	struct tx_etoken_out **vouts, **p_vout, **c_vout, *vout;
	const struct etoken *etkptr;

	if (tx->vout_num == 0 || tx->vouts == NULL || *tx->vouts == NULL) {
		logmsg(LOG_ERR, "Cannot supplement a record withou vout.\n");
		return -1;
	}
	vout = *tx->vouts;
	etkptr = &vout->etk;

	vout = malloc(sizeof(struct tx_etoken_out));
	if (!check_pointer(vout))
		return -ENOMEM;
	retv = tx_vout_copy(vout, etkptr, value, payto);
	if (retv != 0)
		goto err_exit_10;
	vouts = malloc((tx->vout_num+1)*sizeof(struct tx_etoken_out));
	if (!check_pointer(vouts)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	p_vout = tx->vouts;
	c_vout = vouts;
	for (i = 0; i < tx->vout_num; i++)
		*c_vout++ = *p_vout++;
	*c_vout = vout;
	if (tx->vouts)
		free(tx->vouts);
	tx->vouts = vouts;
	tx->vout_num += 1;

	tx_tryerror(tx);
	return retv;

err_exit_10:
	free(vout);
	return retv;
}

int tx_trans_sign(ulong64 txptr, unsigned char *buf, int buflen, 
		const struct ecc_key *skey, int idx)
{
	struct txrec *tx = (struct txrec *)txptr;
	int retv = 0;

	assert(idx < tx->vin_num);
	retv = tx_sign((char *)buf, buflen, tx, idx, skey);

	tx_tryerror(tx);
	return retv;
}

int tx_trans_end(char *buf, int buflen, ulong64 txptr)
{
	struct txrec *tx = (struct txrec *)txptr;
	int len;

	len = tx_serialize(buf, buflen, tx, 1);
	if (len > buflen)
		len = -1;
	else
		tx_destroy(tx);
	return len;
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
