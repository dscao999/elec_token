#ifndef TOKENS_DSCAO__
#define TOKENS_DSCAO__
#include <stdlib.h>

#define BYTE unsigned char
#define HALFW unsigned short
#define WORD unsigned int
#define LONGW unsigned long

#define ETK_VERSION 1
#define RIPEMD_ID_LEN	20
#define SHA256_ID_LEN	32

struct etk_option {
	BYTE id;
	BYTE len;
	BYTE desc[0];
};

struct etoken {
	BYTE id[RIPEMD_ID_LEN];
	HALFW vendor;
	HALFW type;
	HALFW hlen;

	HALFW subtype;
	BYTE desc[12];

	LONGW value;
	LONGW tm;
	LONGW expire;

	BYTE *lockscript;
	HALFW locklen;

	BYTE ver;
	BYTE noxfer;
	HALFW optlen;
	struct etk_option options[0];
};

static inline void etoken_set_vendor(struct etoken *et, int vendor, int type)
{
	et->vendor = vendor;
	et->type = type;
}
void etoken_set_subtype(struct etoken *et, int sub, const char *desc);
void etoken_set_options(struct etoken *et, const struct etk_option *opts);
static inline void etoken_set_expire(struct etoken *et, int days)
{
	et->expire = et->tm + days*24*3600;
}
int etoken_expired(const struct etoken *et);
int etoken_equiv(const struct etoken *etl, const struct etoken *etr);

struct etoken *etoken_new(unsigned long value, int subtype, const char *desc,
		const struct etk_option *opts);
struct etoken *etoken_clone(const struct etoken *et, unsigned long value);
void etoken_free(struct etoken *et)
{
	if (et) {
		if (et->lockscript)
			free(et->lockscript);
		free(et);
	}
}

int etoken_lock(struct etoken *et, int locklen, const BYTE *lockscript);
int etoken_unlock(const struct etoken *et, int unlen, const BYTE *unlock);

#endif  /* TOKENS_DSCAO__ */
