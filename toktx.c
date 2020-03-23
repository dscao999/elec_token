#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include "loglog.h"
#include "tokens.h"
#include "toktx.h"
#include "ecc_secp256k1.h"
#include "base64.h"
#include "virtmach.h"

#define TOKEN_TX_VER	0x01

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
		for (i = 0; i < nitem && *txouts; i++, txout++) {
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

struct txrec *tx_create(int tkid, unsigned long value, int days,
		const char *payto, const char *prkey)
{
	struct ecc_key *ecckey;
	struct ecc_sig *eccsig;
	int buflen, txlen, pos, retv;
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

	ecckey = pool;
	eccsig = pool + sizeof(struct ecc_key);
	buf = ((void *)eccsig) + sizeof(struct ecc_sig);
	buflen = 2048 - (buf - (char *)pool);
	retv = ecc_key_import(ecckey, prkey);
	if (unlikely(retv != 32)) {
		logmsg(LOG_ERR, "Cannot import ecc private key!\n");
		goto err_exit_20;
	}

	*tx->vins = malloc(sizeof(struct tx_etoken_in));
	if (!check_pointer(*tx->vins))
		goto err_exit_20;

	vin = *tx->vins;

	vin->odd = 2 - (ecckey->py[ECCKEY_INT_LEN-1] & 1);
	vin->gensis = 0xff;
	memcpy(vin->txid, ecckey->px, SHA_DGST_LEN);
	vin->unlock_len = 0;
	vin->unlock = NULL;

	*tx->vouts = malloc(sizeof(struct tx_etoken_out));
	if (!check_pointer(*tx->vouts))
		goto err_exit_20;
	vout = *tx->vouts;
	etoken_init(&vout->etk, tkid, value, days);
	vout->lock_len = 25;
	vout->lock = malloc(25);
	if (!check_pointer(vout->lock))
		goto err_exit_20;
	vout->lock[0] = OP_DUP;
	vout->lock[1] = OP_RIPEMD160;
	vout->lock[2] = 20;
	vout->lock[23] = OP_EQUALVERIFY;
	vout->lock[24] = OP_CHECKSIG;
	retv = str2bin_b64(vout->lock+3, 20, payto);
	if (retv != 20) {
		logmsg(LOG_ERR, "Invalid public key hash.\n");
		goto err_exit_30;
	}

	txlen = tx_serialize(buf, buflen, tx);
	assert(txlen <= buflen);
	ecc_sign(eccsig, ecckey, (const unsigned char *)buf, txlen);
	vin->unlock_len = sizeof(struct ecc_sig) + ECCKEY_INT_LEN * 4 + 3;
	vin->unlock = malloc(vin->unlock_len);
	if (!check_pointer(vin->unlock))
		goto err_exit_30;
	vin->unlock[0] = sizeof(struct ecc_sig);
	memcpy(vin->unlock+1, eccsig, sizeof(struct ecc_sig));
	pos = sizeof(struct ecc_sig) + 1;
	vin->unlock[pos] = ECCKEY_INT_LEN * 4 + 1;
	vin->unlock[pos+1] = 2 - (ecckey->py[0] & 1);
	memcpy(vin->unlock+pos+2, ecckey->px, ECCKEY_INT_LEN * 4);

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

static inline int tx_etoken_in_length(const struct tx_etoken_in *txin)
{
	int len;
	
	len = sizeof(struct tx_etoken_in) + txin->unlock_len;
	return align8(len);
}

static inline int tx_etoken_out_length(const struct tx_etoken_out *txout)
{
	int len;

	len = sizeof(struct tx_etoken_out) +
		etoken_option_length(&txout->etk) + txout->lock_len;
	return align8(len);
}

int tx_serialize(char *buf, int buflen, const struct txrec *tx)
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
		txlen += tx_etoken_in_length(txin);
	}
	txouts = tx->vouts;
	numitem = tx->vout_num;
	for (i = 0; i < numitem; i++, txouts++) {
		txout = *txouts;
		txlen += tx_etoken_out_length(txout);
	}
	if (buflen < txlen)
		return -txlen;

	tx_ser = (struct txrec *)buf;
	*tx_ser = *tx;

	txins = tx->vins;
	txin_ser = buf + sizeof(struct txrec);
	numitem = tx->vin_num;
	for (i = 0; i < numitem; i++, txins++) {
		txin = *txins;
		memcpy(txin_ser, txin, sizeof(struct tx_etoken_in));
		if (txin->unlock)
			memcpy(txin_ser+sizeof(struct tx_etoken_in),
					txin->unlock, txin->unlock_len);
		txin_ser += tx_etoken_in_length(txin);
	}
	txouts = tx->vouts;
	txout_ser = txin_ser;
	numitem = tx->vout_num;
	for (i = 0; i < numitem; i++, txouts++) {
		txout = *txouts;
		memcpy(txout_ser, txout, sizeof(struct tx_etoken_out));
		pos = sizeof(struct tx_etoken_out);
		rlen = buflen - (txout_ser - buf);
		rlen = etoken_option_serialize(txout_ser+pos, rlen,
				&txout->etk);
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
	sumpos += sizeof(struct txrec);
	tx->vins = NULL;
	tx->vouts = NULL;

	tx->vins = malloc(sizeof(struct tx_etoken_in *)*tx->vin_num);
	if (!check_pointer(tx->vins)) {
		logmsg(LOG_ERR, "Illformed tx record. \n");
		goto err_exit_10;
	}
	tx->vouts = malloc(sizeof(struct tx_etoken_out *)*tx->vout_num);
	if (!check_pointer(tx->vouts)) {
		logmsg(LOG_ERR, "Illformed tx record.\n");
		goto err_exit_10;
	}
	memset(tx->vins, 0, sizeof(struct tx_etoken_in *)*tx->vin_num);
	memset(tx->vouts, 0, sizeof(struct tx_etoken_out *)*tx->vin_num);

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
		buf_txin += tx_etoken_in_length(txin);
		sumpos += tx_etoken_in_length(txin);
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

int tx_create_token(char *buf, int buflen, int tkid, unsigned long value,
		int days, const char *payto, const char *prkey)
{
	int txlen;
	struct txrec *tx;

	tx = tx_create(tkid, value, days, payto, prkey);
	if (!check_pointer(tx))
		return -ENOMEM;
	txlen = tx_serialize(buf, buflen, tx);
	if (txlen < 0)
		return 0;
	return txlen;
}
