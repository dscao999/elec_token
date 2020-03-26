#ifndef TOKTX_DSCAO__
#define TOKTX_DSCAO__
#include "sha256.h"
#include "ripemd160.h"
#include "tokens.h"

struct tx_etoken_in {
	BYTE txid[SHA_DGST_LEN];
	union {
		HALFW vout_idx;
		struct {
			BYTE odd, gensis;
		};
	};
	HALFW reserv[2];
	HALFW unlock_len;
	BYTE *unlock;
};

struct tx_etoken_out {
	HALFW reserv[3];
	HALFW lock_len;
	BYTE *lock;
	struct etoken etk;
};

struct txrec {
	WORD ver;
	HALFW vin_num;
	HALFW vout_num;
	LONGW tm;
	struct tx_etoken_in **vins;
	struct tx_etoken_out **vouts;
};

struct txrec *tx_create(int tkid, unsigned long value, int days,
		const char *payto, const char *prkey);
int tx_serialize(char *buf, int len, const struct txrec *tx);
struct txrec *tx_deserialize(const char *buf, int len);

void tx_destroy(struct txrec *tx);

int tx_create_token(char *buf, int buflen, int tkid, unsigned long value,
		int days, const char *payto, const char *prkey);

int tx_verify_signature(const struct txrec *tx);

#endif /* TOKTX_DSCAO__ */
