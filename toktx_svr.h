#ifndef TOKTX_SVR_DSCAO__
#define TOKTX_SVR_DSCAO__
#include "toktx.h"

int tx_verify(const struct txrec *tx);

int tx_get_vout(const struct txrec *tx, struct txrec_vout *vout);

extern unsigned char * (*tx_from_blockchain)(const struct tx_etoken_in *txin,
		int *lock_len, ulong64 *val);

#endif /* TOKTX_SVR_DSCAO__ */
