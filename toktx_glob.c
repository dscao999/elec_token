#include "toktx.h"

unsigned char * (*tx_from_blockchain)(const struct tx_etoken_in *txin,
		                int *lock_len, unsigned long *val) = NULL;
