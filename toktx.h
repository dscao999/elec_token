#ifndef TOKTX_DSCAO__
#define TOKTX_DSCAO__
#include "sha256.h"
#include "ripemd160.h"
#include "tokens.h"

struct etoken_in {
	BYTE txid[SHA_DGST_LEN];
	union {
		HALFW vout_idx;
		BYTE odd, gensis;
	};
	HALFW unlock_len;
	BYTE *unlock;
};

static inline int etoken_in_length(const struct etoken_in *etin)
{
	return sizeof(struct etoken_in) + etin->unlock_len;
}

struct tx_head {
	WORD ver;
	WORD vin_num;
	struct etoken_in vins[0];
};

struct tx_vout {
	WORD nvout;
	struct etoken vouts[0];
};

#endif /* TOKTX_DSCAO__ */
