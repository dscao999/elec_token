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
	struct tx_etoken_in **txin;
	struct tx_etoken_out **txout;
	int i, nitem;

	if (!tx)
		return;

	if (tx->vins) {
		txin = tx->vins;
		nitem = tx->vin_num;
		for (i = 0; i < nitem && *txin; i++, txin++)
			free(*txin);
		free(tx->vins);
	}
	if (tx->vouts) {
		nitem = tx->vout_num;
		txout = tx->vouts;
		for (i = 0; i < nitem && *txout; i++, txout++)
			free(*txout);
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
	vin->unlock_len = sizeof(struct ecc_sig) + ECCKEY_INT_LEN * 8 + 2;
	vin->unlock = malloc(vin->unlock_len);
	if (!check_pointer(vin->unlock))
		goto err_exit_30;
	vin->unlock[0] = sizeof(struct ecc_sig);
	memcpy(vin->unlock+1, eccsig, sizeof(struct ecc_sig));
	pos = sizeof(struct ecc_sig) + 1;
	vin->unlock[pos] = ECCKEY_INT_LEN * 8;
	memcpy(vin->unlock+pos+1, ecckey->px, ECCKEY_INT_LEN * 8);

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

int tx_serialize(char *buf, int len, const struct txrec *tx)
{
	int txlen, numitem, i;
	struct tx_etoken_in **txin;
	struct tx_etoken_in *txin_ser;
	struct tx_etoken_out **txout;
       	struct tx_etoken_out *txout_ser;
	struct txrec *tx_ser;

	txlen = sizeof(struct txrec) - 2 * sizeof(void *);
	numitem = tx->vin_num;
	txin = tx->vins;
	for (i = 0; i < numitem; i++, txin++)
		txlen += sizeof(struct tx_etoken_in) + (*txin)->unlock_len -
			sizeof(void *);
	txout = tx->vouts;
	numitem = tx->vout_num;
	for (i = 0; i < numitem; i++, txout++)
		txlen += sizeof(struct tx_etoken_out) + (*txout)->lock_len -
			sizeof(void *);
	if (len < txlen)
		return txlen;

	tx_ser = (struct txrec *)buf;
	memcpy(tx_ser, tx, sizeof(struct txrec));

	txin = tx->vins;
	txin_ser = (struct tx_etoken_in *)(buf + sizeof(struct txrec) -
			2*sizeof(void *));
	numitem = tx->vin_num;
	for (i = 0; i < numitem; i++, txin++) {
		memcpy(txin_ser, *txin, sizeof(struct tx_etoken_in) -
				sizeof(BYTE *));
		if ((*txin)->unlock)
			memcpy(&txin_ser->unlock, (*txin)->unlock,
					(*txin)->unlock_len);
		txin_ser = ((void *)txin_ser) + sizeof(struct tx_etoken_in) -
			sizeof(void *) + (*txin)->unlock_len;
	}
	txout = tx->vouts;
	txout_ser = (struct tx_etoken_out *)txin_ser;
	numitem = tx->vout_num;
	for (i = 0; i < numitem; i++, txout++) {
		memcpy(txout_ser, *txout, sizeof(struct tx_etoken_out) -
				sizeof(BYTE *));
		if ((*txout)->lock)
			memcpy(&txout_ser->lock, (*txout)->lock,
					(*txout)->lock_len);
		txout_ser = ((void *)txout_ser) + sizeof(struct tx_etoken_out) -
			sizeof(BYTE *) + (*txout)->lock_len;
	}
	return txlen;
}

struct txrec *tx_deserialize(const char *buf, int len)
{
	struct txrec *tx;
	struct tx_etoken_in **txin;
	struct tx_etoken_out **txout;
	const struct txrec *buftx;
	const struct tx_etoken_in *buf_txin;
	const struct tx_etoken_out *buf_txout;
	int i, nitem;

	tx = malloc(sizeof(struct txrec));
	if (!check_pointer(tx))
		return NULL;
	buftx = (const struct txrec *)buf;
	if (len < sizeof(struct txrec)) {
		logmsg(LOG_ERR, "Illformed tx record.\n");
		goto err_exit_10;
	}
	memcpy(tx, buftx, sizeof(struct txrec));
	tx->vins = NULL;
	tx->vouts = NULL;

	tx->vins = malloc(sizeof(struct tx_etoken_in*)*tx->vin_num);
	if (!check_pointer(tx->vins)) {
		logmsg(LOG_ERR, "Illformed tx record. \n");
		goto err_exit_10;
	}
	tx->vouts = malloc(sizeof(struct tx_etoken_out)*tx->vout_num);
	if (!check_pointer(tx->vouts)) {
		logmsg(LOG_ERR, "Illformed tx record.\n");
		goto err_exit_10;
	}
	memset(tx->vins, 0, sizeof(struct tx_etoken_in)*tx->vin_num);
	memset(tx->vouts, 0, sizeof(struct tx_etoken_out)*tx->vin_num);

	nitem = tx->vin_num;
	txin = tx->vins;
	buf_txin = (struct tx_etoken_in *)(buf + sizeof(struct txrec) -
			2*sizeof(void *));
	for (i = 0; i < nitem; i++, txin++) {
		*txin = malloc(sizeof(struct tx_etoken_in));
		if (!check_pointer(*txin))
			goto err_exit_10;
		memcpy(*txin, buf_txin, sizeof(struct tx_etoken_in));
		(*txin)->unlock = malloc((*txin)->unlock_len);
		if (!check_pointer((*txin)->unlock))
			goto err_exit_10;
		memcpy((*txin)->unlock, &buf_txin->unlock, (*txin)->unlock_len);
		buf_txin = ((void *)buf_txin) + sizeof(struct tx_etoken_in) -
			sizeof(void *) + (*txin)->unlock_len;
	}
	nitem = tx->vout_num;
	txout = tx->vouts;
	buf_txout = ((void *)buf_txin);
	for (i = 0; i < nitem; i++, txout++) {
		*txout = malloc(sizeof(struct tx_etoken_out));
		if (!check_pointer(*txout))
			goto err_exit_10;
		memcpy(*txout, buf_txout, sizeof(struct tx_etoken_in));
		(*txout)->lock = malloc((*txout)->lock_len);
		if (!check_pointer((*txout)->lock))
			goto err_exit_10;
		memcpy((*txout)->lock, &buf_txout->lock, (*txout)->lock_len);
		buf_txout = ((void *)buf_txout) + sizeof(struct tx_etoken_out) -
			sizeof(void *) + (*txout)->lock_len;
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
	if (txlen > buflen)
		return 0;
	return txlen;
}
