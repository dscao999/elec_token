#ifndef TOKENS_DSCAO__
#define TOKENS_DSCAO__
#include <stdlib.h>

#define BYTE unsigned char
#define HALFW unsigned short

struct etk_option {
	BYTE id;
	BYTE desc[23];
};

struct etoken {
	BYTE id[20];
	HALFW vendor;
	HALFW type;
	HALFW hlen;

	HALFW subtype;
	BYTE desc[12];

	unsigned long tm;
	unsigned long value;

	BYTE *lockscript;
	HALFW locklen;

	BYTE ver;
	BYTE numopt;
	struct etk_option options[0];
};

static inline void etoken_set_vendor(struct etoken *et, int vendor, int type)
{
	et->vendor = vendor;
	et->type = type;
}
void etoken_set_subtype(struct etoken *et, int sub, const char *desc);
void etoken_set_options(struct etoken *et, int numopt,
		const struct etk_option *opts);
int etoken_equiv(const struct etoken *etl, const struct etoken *etr);

struct etoken *etoken_new(unsigned long value, int subtype, const char *desc,
		int numopt, const struct etk_option *opts);
struct etoken *etoken_clone(const struct etoken *et, unsigned long value);
void etoken_free(struct etoken *et)
{
	if (et) {
		if (et->lockscript)
			free(et->lockscript);
		free(et);
	}
}

void etoken_lock(struct etoken *et, int locklen, const BYTE *lockscript);

#endif  /* TOKENS_DSCAO__ */
