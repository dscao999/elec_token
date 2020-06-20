#ifndef TOKTX_DSCAO__
#define TOKTX_DSCAO__
#include "sha256.h"
#include "ripemd160.h"
#include "tokens.h"
#include "ecc_secp256k1.h"

#define MAX_TXSIZE 2048

struct txrec_vout {
	ulong64 value;
	ulong64 blockid;
	unsigned char owner[RIPEMD_LEN];
	unsigned short eid;
	unsigned char vout_idx;
};

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

struct txrec *tx_create(int tkid, ulong64 value, int days,
		const char *payto, const struct ecc_key *ecckey);
int tx_serialize(char *buf, int len, const struct txrec *tx, int with_unlock);
struct txrec *tx_deserialize(const char *buf, int len);

void tx_destroy(struct txrec *tx);

int tx_create_token(char *buf, int buflen, int tkid, ulong64 value,
		int days, const char *payto, const struct ecc_key *ecckey);

int tx_verify(const struct txrec *tx);

int tx_get_vout(const struct txrec *tx, struct txrec_vout *vout);

extern unsigned char * (*tx_from_blockchain)(const struct tx_etoken_in *txin,
		int *lock_len, ulong64 *val);

#endif /* TOKTX_DSCAO__ */
