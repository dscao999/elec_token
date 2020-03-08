#include "loglog.h"
#include "toktx.h"

#define TOKEN_TX_VER	0x01

static inline struct etoken *etoken_next(struct etoken *et)
{
	struct etoken *etn;

	etn = ((void *)et) + etoken_length(et) + et->locklen;
	return etn;
}

static inline const struct etoken *etoken_cnext(const struct etoken *et)
{
	const struct etoken *etn;

	etn = ((const void *)et) + etoken_length(et) + et->locklen;
	return etn;
}

struct token_in *tokenin_new(int *num, unsigned long value,
		int vendor, int type, int subtype)
{
}

struct token_tx *tokentx_new(int tx_class, const struct etoken *vout, int num)
{
	struct token_tx *tx;
	int i, len;
	const struct etoken *et, *cet;
	struct etoken *etn;
	unsigned long value;

	cet = vout;
	value = cet->value;
	len = cet->locklen + etoken_length(cet);
	et = etoken_cnext(cet);
	for (i = 1; i < num; i++) {
		if (!etoken_equiv_type(et, cet))
			break;
		value += et->value;
		len += et->locklen + etoken_length(et);
		et = etoken_cnext(et);
	}
	if (i < num) {
		logmsg(LOG_ERR, "Invalid Token vout.\n");
		return NULL;
	}
	tx = malloc(sizeof(struct token_tx) + len;
	if (!check_pointer(tx, LOG_CRIT, nomem))
		return tx;
	tx->ver = TOKEN_TX_VER;
	tx->tx_class = tx_class;
	tx->no_vout = num;
	tx->tokin_off = 0;
	tx->tokin_len = 0;
	tx->vout_len = len;
	memcpy(tx->vout, et, len);


}
